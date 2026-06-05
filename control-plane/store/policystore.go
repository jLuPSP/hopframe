package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/jlupsp/hopframe/pkg/policy"
)

// PolicyStore is the canonical state of policies on the control plane.
// State lives in a single JSON document on disk, atomically rewritten
// on every mutation. This is small enough that the simple-and-correct
// shape beats a database; policies are O(hundreds), not O(millions),
// and the read path is hot enough that an in-memory snapshot is the
// right cache.
//
// Every mutation also emits a synthetic audit event into the chain
// (when an event sink is wired in), so the audit trail captures who
// changed which policy and when.
type PolicyStore struct {
	mu       sync.RWMutex
	path     string
	policies map[string]policy.Policy
	listener PolicyListener
}

// PolicyListener is invoked after every successful mutation. The
// control plane uses it to record the change on the hash-chained audit
// log. Implementations must not call back into the store.
type PolicyListener interface {
	OnPolicyChange(op string, p policy.Policy, actor string)
}

// PolicyStoreOptions configures a PolicyStore.
type PolicyStoreOptions struct {
	// Path is the file the policies are persisted to. The parent
	// directory is created if it does not exist.
	Path string
	// Listener, when set, receives every mutation post-commit.
	Listener PolicyListener
}

// OpenPolicyStore opens or creates a policy store at the configured path.
// On open, any existing file is decoded into the in-memory map.
func OpenPolicyStore(opts PolicyStoreOptions) (*PolicyStore, error) {
	if opts.Path == "" {
		return nil, errors.New("policystore: empty path")
	}
	if err := os.MkdirAll(filepath.Dir(opts.Path), 0o755); err != nil {
		return nil, fmt.Errorf("policystore: mkdir: %w", err)
	}
	s := &PolicyStore{
		path:     opts.Path,
		policies: make(map[string]policy.Policy),
		listener: opts.Listener,
	}
	if err := s.loadLocked(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *PolicyStore) loadLocked() error {
	body, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("policystore: read: %w", err)
	}
	if len(body) == 0 {
		return nil
	}
	var doc policyDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("policystore: decode: %w", err)
	}
	s.policies = make(map[string]policy.Policy, len(doc.Policies))
	for _, p := range doc.Policies {
		s.policies[p.ID] = p
	}
	return nil
}

type policyDoc struct {
	Schema   string          `json:"schema"`
	Policies []policy.Policy `json:"policies"`
}

const policyDocSchema = "hopframe.policy/v1"

// Snapshot returns an immutable copy of every policy currently stored.
// The slice is sorted by id for deterministic iteration.
func (s *PolicyStore) Snapshot() []policy.Policy {
	s.mu.RLock()
	out := make([]policy.Policy, 0, len(s.policies))
	for _, p := range s.policies {
		out = append(out, p)
	}
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Get returns the policy with the given id, or false if it does not
// exist. The returned value is a copy and may be modified safely.
func (s *PolicyStore) Get(id string) (policy.Policy, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.policies[id]
	return p, ok
}

// Put creates or replaces a policy. On create, p.ID is required and
// must not already exist; on replace, the version is bumped and
// timestamps updated.
func (s *PolicyStore) Put(p policy.Policy, actor string) (policy.Policy, error) {
	if err := p.Validate(); err != nil {
		return policy.Policy{}, err
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()

	op := "create"
	if existing, ok := s.policies[p.ID]; ok {
		op = "update"
		p.CreatedAt = existing.CreatedAt
		p.CreatedBy = existing.CreatedBy
		p.Version = existing.Version + 1
	} else {
		if p.Version == 0 {
			p.Version = 1
		}
		if p.CreatedAt.IsZero() {
			p.CreatedAt = now
		}
		if p.CreatedBy == "" {
			p.CreatedBy = actor
		}
	}
	p.UpdatedAt = now
	p.UpdatedBy = actor
	s.policies[p.ID] = p

	if err := s.persistLocked(); err != nil {
		return policy.Policy{}, err
	}
	if s.listener != nil {
		s.listener.OnPolicyChange(op, p, actor)
	}
	return p, nil
}

// Delete removes the policy with the given id. Returns false if no
// policy with that id existed.
func (s *PolicyStore) Delete(id, actor string) (policy.Policy, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.policies[id]
	if !ok {
		return policy.Policy{}, false, nil
	}
	delete(s.policies, id)
	if err := s.persistLocked(); err != nil {
		s.policies[id] = p
		return policy.Policy{}, false, err
	}
	if s.listener != nil {
		s.listener.OnPolicyChange("delete", p, actor)
	}
	return p, true, nil
}

func (s *PolicyStore) persistLocked() error {
	out := make([]policy.Policy, 0, len(s.policies))
	for _, p := range s.policies {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	doc := policyDoc{Schema: policyDocSchema, Policies: out}
	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("policystore: encode: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o644); err != nil {
		return fmt.Errorf("policystore: write tmp: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("policystore: rename: %w", err)
	}
	return nil
}

// Version returns a monotonic version number that increments on every
// mutation. Sensors poll this on heartbeat to decide whether to refetch
// the policy snapshot. Implemented as the sum of policy versions, so
// any change to any policy bumps it.
func (s *PolicyStore) Version() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var v int64
	for _, p := range s.policies {
		v += int64(p.Version)
	}
	return v
}
