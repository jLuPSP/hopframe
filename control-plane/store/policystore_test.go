package store

import (
	"path/filepath"
	"sync"
	"testing"

	"github.com/jlupsp/hopframe/pkg/detect"
	"github.com/jlupsp/hopframe/pkg/policy"
)

type recordingListener struct {
	mu     sync.Mutex
	events []string
}

func (l *recordingListener) OnPolicyChange(op string, p policy.Policy, actor string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, op+":"+p.ID+":"+actor)
}

func newPolicy(id string) policy.Policy {
	return policy.Policy{
		ID:          id,
		Name:        "test " + id,
		Enabled:     true,
		Disposition: policy.Disposition{Mode: detect.ModeWarn},
	}
}

func TestPolicyStoreCreateGetUpdateDelete(t *testing.T) {
	dir := t.TempDir()
	rec := &recordingListener{}
	ps, err := OpenPolicyStore(PolicyStoreOptions{
		Path:     filepath.Join(dir, "policies.json"),
		Listener: rec,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	p := newPolicy("pol_1")
	stored, err := ps.Put(p, "alice")
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if stored.Version != 1 {
		t.Errorf("create version = %d, want 1", stored.Version)
	}
	if stored.CreatedBy != "alice" || stored.UpdatedBy != "alice" {
		t.Errorf("create authors = %q/%q, want alice/alice", stored.CreatedBy, stored.UpdatedBy)
	}
	if stored.CreatedAt.IsZero() || stored.UpdatedAt.IsZero() {
		t.Errorf("create timestamps zero")
	}

	got, ok := ps.Get(stored.ID)
	if !ok {
		t.Fatal("get after put returned !ok")
	}
	if got.Name != stored.Name {
		t.Errorf("name mismatch")
	}

	got.Description = "updated"
	updated, err := ps.Put(got, "bob")
	if err != nil {
		t.Fatalf("put update: %v", err)
	}
	if updated.Version != 2 {
		t.Errorf("update version = %d, want 2", updated.Version)
	}
	if updated.CreatedBy != "alice" {
		t.Errorf("CreatedBy preserved? got %q", updated.CreatedBy)
	}
	if updated.UpdatedBy != "bob" {
		t.Errorf("UpdatedBy = %q, want bob", updated.UpdatedBy)
	}

	deleted, ok, err := ps.Delete(stored.ID, "carol")
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if !ok || deleted.ID != stored.ID {
		t.Errorf("delete didnt return prior policy")
	}
	if _, ok := ps.Get(stored.ID); ok {
		t.Errorf("policy present after delete")
	}

	rec.mu.Lock()
	got2 := append([]string(nil), rec.events...)
	rec.mu.Unlock()
	want := []string{"create:" + stored.ID + ":alice", "update:" + stored.ID + ":bob", "delete:" + stored.ID + ":carol"}
	if len(got2) != len(want) {
		t.Fatalf("listener events = %v, want %v", got2, want)
	}
	for i := range want {
		if got2[i] != want[i] {
			t.Errorf("event %d = %q, want %q", i, got2[i], want[i])
		}
	}
}

func TestPolicyStorePersistsAcrossOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.json")
	ps, err := OpenPolicyStore(PolicyStoreOptions{Path: path})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for _, id := range []string{"a", "b", "c"} {
		if _, err := ps.Put(newPolicy(id), "tester"); err != nil {
			t.Fatalf("put %s: %v", id, err)
		}
	}

	ps2, err := OpenPolicyStore(PolicyStoreOptions{Path: path})
	if err != nil {
		t.Fatalf("re-open: %v", err)
	}
	snap := ps2.Snapshot()
	if len(snap) != 3 {
		t.Fatalf("snapshot len = %d, want 3", len(snap))
	}
}

func TestPolicyStoreVersionMonotonic(t *testing.T) {
	dir := t.TempDir()
	ps, err := OpenPolicyStore(PolicyStoreOptions{Path: filepath.Join(dir, "policies.json")})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if ps.Version() != 0 {
		t.Fatalf("empty version = %d, want 0", ps.Version())
	}
	p1, _ := ps.Put(newPolicy("a"), "")
	if v := ps.Version(); v != int64(p1.Version) {
		t.Fatalf("version after one put = %d, want %d", v, p1.Version)
	}
	p2, _ := ps.Put(newPolicy("b"), "")
	if ps.Version() != int64(p1.Version+p2.Version) {
		t.Fatalf("version after two puts = %d, want %d", ps.Version(), p1.Version+p2.Version)
	}
	p1.Description = "edited"
	updated, _ := ps.Put(p1, "")
	if v := ps.Version(); v != int64(updated.Version+p2.Version) {
		t.Fatalf("version after update = %d, want %d", v, updated.Version+p2.Version)
	}
}
