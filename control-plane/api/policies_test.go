package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jlupsp/hopframe/control-plane/store"
	"github.com/jlupsp/hopframe/pkg/detect"
	"github.com/jlupsp/hopframe/pkg/policy"
)

func setupWithPolicies(t *testing.T) (*httptest.Server, *store.Store, *store.PolicyStore) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "log.ndjson"))
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	srv := NewServer(st, UIHandler())
	listener := srv.PolicyAuditListener()
	ps, err := store.OpenPolicyStore(store.PolicyStoreOptions{
		Path:     filepath.Join(dir, "policies.json"),
		Listener: listener,
	})
	if err != nil {
		t.Fatalf("policy store: %v", err)
	}
	srv.SetPolicyStore(ps)
	srv.SetSensorFleetEnabled(true)
	if err := srv.SetContentRoot("../../content"); err != nil {
		t.Fatalf("content root: %v", err)
	}
	ts := httptest.NewServer(srv.Routes())
	t.Cleanup(func() {
		ts.Close()
		st.Close()
	})
	return ts, st, ps
}

func TestPolicyCRUDFlow(t *testing.T) {
	ts, _, _ := setupWithPolicies(t)

	body, _ := json.Marshal(policy.Policy{
		Name:        "block-tp-prod",
		Enabled:     true,
		Scope:       policy.Scope{TenantID: "acme"},
		Selector:    policy.Selector{Categories: []string{"tool-poisoning"}},
		Disposition: policy.Disposition{Mode: detect.ModeBlock},
	})
	resp, err := http.Post(ts.URL+"/v1/policies", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("status %d body=%s", resp.StatusCode, b)
	}
	var created policy.Policy
	_ = json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	if created.ID == "" {
		t.Fatal("server didnt assign id")
	}
	if created.Version != 1 {
		t.Errorf("version = %d, want 1", created.Version)
	}

	resp, err = http.Get(ts.URL + "/v1/policies/" + created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get status %d", resp.StatusCode)
	}

	listResp, err := http.Get(ts.URL + "/v1/policies")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	defer listResp.Body.Close()
	var list struct {
		Policies []policy.Policy `json:"policies"`
		Version  int64           `json:"version"`
	}
	_ = json.NewDecoder(listResp.Body).Decode(&list)
	if len(list.Policies) != 1 || list.Version == 0 {
		t.Fatalf("list = %+v", list)
	}

	// Update (PATCH).
	created.Disposition.Mode = detect.ModeWarn
	body, _ = json.Marshal(created)
	req, _ := http.NewRequest(http.MethodPatch, ts.URL+"/v1/policies/"+created.ID, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	uResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("patch: %v", err)
	}
	uResp.Body.Close()
	if uResp.StatusCode != http.StatusOK {
		t.Fatalf("patch status %d", uResp.StatusCode)
	}

	// Active endpoint returns the enabled set.
	aResp, err := http.Get(ts.URL + "/v1/policies/active")
	if err != nil {
		t.Fatalf("active: %v", err)
	}
	defer aResp.Body.Close()
	var act struct {
		Policies []policy.Policy `json:"policies"`
		Version  int64           `json:"version"`
	}
	_ = json.NewDecoder(aResp.Body).Decode(&act)
	if len(act.Policies) != 1 || act.Policies[0].Disposition.Mode != detect.ModeWarn {
		t.Fatalf("active = %+v", act)
	}

	// Delete.
	req, _ = http.NewRequest(http.MethodDelete, ts.URL+"/v1/policies/"+created.ID, nil)
	dResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	dResp.Body.Close()
	if dResp.StatusCode != http.StatusOK {
		t.Fatalf("delete status %d", dResp.StatusCode)
	}
}

func TestPolicyChangeAppearsInAuditLog(t *testing.T) {
	ts, st, _ := setupWithPolicies(t)

	body, _ := json.Marshal(policy.Policy{
		Name:        "audit-test",
		Enabled:     true,
		Disposition: policy.Disposition{Mode: detect.ModeWarn},
	})
	resp, err := http.Post(ts.URL+"/v1/policies", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	resp.Body.Close()

	recs, _ := st.Read(store.Query{Limit: 100})
	found := false
	for _, r := range recs {
		if r.Event != nil {
			for _, f := range r.Event.Findings {
				if f.Category == "policy_audit" && strings.Contains(f.RuleID, "create") {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatal("policy create did not produce a policy_audit event in the chain")
	}
}

func TestSensorHeartbeatRoundTrip(t *testing.T) {
	ts, _, _ := setupWithPolicies(t)

	hb := map[string]any{
		"sensor_id":      "edge-1",
		"binary_version": "0.1.0",
		"hostname":       "host-a",
		"policy_version": 0,
	}
	body, _ := json.Marshal(hb)
	resp, err := http.Post(ts.URL+"/v1/sensors/heartbeat", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("hb: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}

	listResp, err := http.Get(ts.URL + "/v1/sensors")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	defer listResp.Body.Close()
	var list struct {
		Sensors []SensorView `json:"sensors"`
	}
	_ = json.NewDecoder(listResp.Body).Decode(&list)
	if len(list.Sensors) != 1 || list.Sensors[0].SensorID != "edge-1" {
		t.Fatalf("sensors = %+v", list)
	}
}

func TestContentManifestServesYAML(t *testing.T) {
	ts, _, _ := setupWithPolicies(t)

	resp, err := http.Get(ts.URL + "/v1/content/manifest")
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var mf contentManifest
	if err := json.NewDecoder(resp.Body).Decode(&mf); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if mf.Version == "" || len(mf.Files) == 0 {
		t.Fatalf("manifest = %+v", mf)
	}

	first := mf.Files[0].Name
	fResp, err := http.Get(ts.URL + "/v1/content/" + first)
	if err != nil {
		t.Fatalf("file: %v", err)
	}
	defer fResp.Body.Close()
	if fResp.StatusCode != http.StatusOK {
		t.Fatalf("file status %d", fResp.StatusCode)
	}
	if got := fResp.Header.Get("X-Hopframe-Content-Hash"); got != mf.Files[0].Hash {
		t.Errorf("content hash header = %q, want %q", got, mf.Files[0].Hash)
	}
}

func TestRBACBlocksWriteForViewer(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "log.ndjson"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	srv := NewServer(st, UIHandler())
	srv.SetAuthToken("admin")
	srv.SetRoleTokens(map[string]Role{
		"viewer-tok": RoleViewer,
		"author-tok": RoleEditor,
	})
	listener := srv.PolicyAuditListener()
	ps, err := store.OpenPolicyStore(store.PolicyStoreOptions{
		Path:     filepath.Join(dir, "policies.json"),
		Listener: listener,
	})
	if err != nil {
		t.Fatalf("ps: %v", err)
	}
	srv.SetPolicyStore(ps)
	ts := httptest.NewServer(srv.Routes())
	t.Cleanup(ts.Close)

	body, _ := json.Marshal(policy.Policy{
		Name:        "rbac-test",
		Enabled:     true,
		Disposition: policy.Disposition{Mode: detect.ModeWarn},
	})
	post := func(token string) int {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/policies", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	if code := post("viewer-tok"); code != http.StatusForbidden {
		t.Fatalf("viewer creating policy got %d, want 403", code)
	}
	if code := post("author-tok"); code != http.StatusCreated {
		t.Fatalf("author creating policy got %d, want 201", code)
	}
	if code := post("admin"); code != http.StatusCreated {
		t.Fatalf("admin creating policy got %d, want 201", code)
	}
}
