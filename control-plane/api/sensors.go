package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"sync"
	"time"
)

// sensorFleet tracks the latest heartbeat from every sensor that has
// reported in. State is in-memory; restart loses history but heartbeats
// resume on the next tick from each sensor. Suitable for the alpha
// shape; the HA migration in roadmap Phase 2C moves this to Postgres.
type sensorFleet struct {
	mu       sync.RWMutex
	sensors  map[string]SensorHeartbeat
	maxStale time.Duration
}

// SensorHeartbeat is the state a sensor publishes. The control plane
// merges these into the fleet view; operators query GET /v1/sensors to
// see who is connected, what version they run, and what policy version
// they have applied. Drift between the active policy version and the
// applied version surfaces as a configuration alarm.
type SensorHeartbeat struct {
	SensorID         string    `json:"sensor_id"`
	TenantID         string    `json:"tenant_id,omitempty"`
	Hostname         string    `json:"hostname,omitempty"`
	BinaryVersion    string    `json:"binary_version,omitempty"`
	PolicyVersion    int64     `json:"policy_version"`
	ContentVersion   string    `json:"content_version,omitempty"`
	StartedAt        time.Time `json:"started_at,omitempty"`
	LastSeenAt       time.Time `json:"last_seen_at"`
	EventsForwarded  int64     `json:"events_forwarded,omitempty"`
	FindingsObserved int64     `json:"findings_observed,omitempty"`
}

// SensorView is the public projection of a heartbeat. Adds drift and
// freshness markers the in-flight heartbeat does not carry directly.
type SensorView struct {
	SensorHeartbeat
	StaleSeconds int  `json:"stale_seconds"`
	IsStale      bool `json:"is_stale"`
	PolicyDrift  bool `json:"policy_drift,omitempty"`
	ContentDrift bool `json:"content_drift,omitempty"`
}

func newSensorFleet() *sensorFleet {
	return &sensorFleet{
		sensors:  make(map[string]SensorHeartbeat),
		maxStale: 60 * time.Second,
	}
}

func (f *sensorFleet) record(hb SensorHeartbeat) {
	if hb.SensorID == "" {
		return
	}
	hb.LastSeenAt = time.Now().UTC()
	f.mu.Lock()
	if existing, ok := f.sensors[hb.SensorID]; ok {
		// Preserve started_at across heartbeats; the sensor reports its
		// own start time once and we remember it.
		if hb.StartedAt.IsZero() {
			hb.StartedAt = existing.StartedAt
		}
	}
	f.sensors[hb.SensorID] = hb
	f.mu.Unlock()
}

func (f *sensorFleet) snapshot(activePolicyVersion int64, activeContentVersion string) []SensorView {
	now := time.Now().UTC()
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make([]SensorView, 0, len(f.sensors))
	for _, s := range f.sensors {
		stale := int(now.Sub(s.LastSeenAt).Seconds())
		out = append(out, SensorView{
			SensorHeartbeat: s,
			StaleSeconds:    stale,
			IsStale:         time.Duration(stale)*time.Second > f.maxStale,
			PolicyDrift:     activePolicyVersion != 0 && s.PolicyVersion != activePolicyVersion,
			ContentDrift:    activeContentVersion != "" && s.ContentVersion != activeContentVersion,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].SensorID < out[j].SensorID
	})
	return out
}

// SetSensorFleetEnabled turns on the in-memory fleet tracker. Operators
// who do not run multiple sensors can leave this off.
func (s *Server) SetSensorFleetEnabled(enabled bool) {
	if enabled && s.sensors == nil {
		s.sensors = newSensorFleet()
	}
	if !enabled {
		s.sensors = nil
	}
}

func (s *Server) handleSensorHeartbeat(w http.ResponseWriter, r *http.Request) {
	if s.sensors == nil {
		http.Error(w, "sensor fleet not enabled", http.StatusNotFound)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	var hb SensorHeartbeat
	if err := json.NewDecoder(r.Body).Decode(&hb); err != nil {
		http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
		return
	}
	if t := tenantFor(r); t != "" {
		hb.TenantID = t
	}
	s.sensors.record(hb)
	resp := map[string]any{
		"ack":             true,
		"policy_version":  s.activePolicyVersion(),
		"content_version": s.activeContentVersion(),
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleSensors(w http.ResponseWriter, r *http.Request) {
	if s.sensors == nil {
		writeJSON(w, http.StatusOK, map[string]any{"sensors": []SensorView{}})
		return
	}
	view := s.sensors.snapshot(s.activePolicyVersion(), s.activeContentVersion())
	tenant := tenantFor(r)
	if tenant == "" {
		writeJSON(w, http.StatusOK, map[string]any{"sensors": view})
		return
	}
	filtered := make([]SensorView, 0, len(view))
	for _, sv := range view {
		if sv.TenantID == tenant {
			filtered = append(filtered, sv)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"sensors": filtered})
}

func (s *Server) activePolicyVersion() int64 {
	if s.policies == nil {
		return 0
	}
	return s.policies.Version()
}

func (s *Server) activeContentVersion() string {
	if s.content == nil {
		return ""
	}
	return s.content.version()
}
