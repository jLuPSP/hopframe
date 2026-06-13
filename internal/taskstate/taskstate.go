// Package taskstate tracks long-running A2A tasks across calls so the
// sensor can detect drift, suspicious state transitions, and tasks
// that have been alive longer than expected.
//
// The PRD calls this out explicitly as a Phase 2 deliverable:
// "Long-running task monitoring: track A2A tasks across hours or
// days; detect drift in task scope; alert on suspicious state
// transitions."
//
// State is in-process. Phase 3 will sync state to the control plane
// so it survives sensor restarts and is consistent across replicas.
package taskstate

import (
	"sort"
	"sync"
	"time"
)

// State is an A2A task lifecycle state. We use the strings the A2A
// spec uses on the wire so they round-trip cleanly.
type State string

const (
	StateUnknown       State = ""
	StateSubmitted     State = "submitted"
	StateWorking       State = "working"
	StateInputRequired State = "input-required"
	StateCompleted     State = "completed"
	StateCanceled      State = "canceled"
	StateFailed        State = "failed"
)

// Transition is one entry in a task's state history.
type Transition struct {
	State State     `json:"state"`
	At    time.Time `json:"at"`
}

// Task is everything the tracker knows about a single A2A task.
type Task struct {
	ID           string       `json:"id"`
	Counterparty string       `json:"counterparty,omitempty"`
	Created      time.Time    `json:"created"`
	Updated      time.Time    `json:"updated"`
	Current      State        `json:"current"`
	History      []Transition `json:"history"`
	// FirstFingerprint captures the first task input so subsequent
	// updates can be compared for scope drift.
	FirstFingerprint string `json:"first_fingerprint,omitempty"`
	// SuspiciousReasons records every reason the task has been flagged.
	SuspiciousReasons []string `json:"suspicious_reasons,omitempty"`
}

// Tracker is concurrent task state for one sensor.
type Tracker struct {
	mu          sync.RWMutex
	tasks       map[string]*Task
	maxLifetime time.Duration
	maxTasks    int
}

// New returns a Tracker. maxLifetime is the threshold past which a
// `working` task is flagged as long-running. maxTasks bounds the
// table; the oldest entries are evicted when full.
func New(maxLifetime time.Duration, maxTasks int) *Tracker {
	if maxTasks <= 0 {
		maxTasks = 4096
	}
	return &Tracker{
		tasks:       make(map[string]*Task),
		maxLifetime: maxLifetime,
		maxTasks:    maxTasks,
	}
}

// Update records a new observation of a task. Returns the updated
// Task and the list of new suspicious findings produced by this update.
type Finding struct {
	Code    string
	Message string
}

// Update merges an observation into the tracker. If task is new, it
// is created with state=submitted unless newState is set.
func (t *Tracker) Update(id, counterparty string, newState State, fingerprint string) (*Task, []Finding) {
	if id == "" {
		return nil, nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now().UTC()
	task, ok := t.tasks[id]
	if !ok {
		t.evictIfFullLocked()
		task = &Task{
			ID:               id,
			Counterparty:     counterparty,
			Created:          now,
			Updated:          now,
			Current:          firstState(newState),
			FirstFingerprint: fingerprint,
		}
		task.History = append(task.History, Transition{State: task.Current, At: now})
		t.tasks[id] = task
		return task, nil
	}

	var findings []Finding

	if counterparty != "" && task.Counterparty == "" {
		task.Counterparty = counterparty
	} else if counterparty != "" && task.Counterparty != counterparty {
		findings = append(findings, Finding{
			Code:    "task.counterparty_changed",
			Message: "task counterparty changed mid-flight (was " + task.Counterparty + ", now " + counterparty + ")",
		})
		task.Counterparty = counterparty
	}

	if newState != StateUnknown && newState != task.Current {
		if !validTransition(task.Current, newState) {
			findings = append(findings, Finding{
				Code:    "task.invalid_transition",
				Message: "invalid state transition " + string(task.Current) + " -> " + string(newState),
			})
		}
		task.Current = newState
		task.History = append(task.History, Transition{State: newState, At: now})
	}

	// Drift check: compare fingerprint of this update against the
	// first one. Different non-empty fingerprints once the task is
	// past `submitted` is a scope-change signal.
	if fingerprint != "" && task.FirstFingerprint != "" &&
		task.FirstFingerprint != fingerprint &&
		task.Current != StateSubmitted {
		findings = append(findings, Finding{
			Code:    "task.scope_drift",
			Message: "task message fingerprint differs from initial submission",
		})
	}

	task.Updated = now
	for _, f := range findings {
		task.SuspiciousReasons = append(task.SuspiciousReasons, f.Code)
	}
	return task, findings
}

// CheckLongRunning sweeps the tracker and returns tasks whose last
// state is `working` (or `submitted`) and whose age exceeds maxLifetime.
func (t *Tracker) CheckLongRunning() []Task {
	if t.maxLifetime <= 0 {
		return nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	now := time.Now().UTC()
	out := make([]Task, 0)
	for _, task := range t.tasks {
		if task.Current != StateWorking && task.Current != StateSubmitted && task.Current != StateInputRequired {
			continue
		}
		if now.Sub(task.Created) >= t.maxLifetime {
			out = append(out, *task)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out
}

// List returns a snapshot of every tracked task.
func (t *Tracker) List() []Task {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]Task, 0, len(t.tasks))
	for _, task := range t.tasks {
		out = append(out, *task)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Updated.After(out[j].Updated) })
	return out
}

// Len returns the number of tracked tasks.
func (t *Tracker) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.tasks)
}

// Get returns the task by id, if present.
func (t *Tracker) Get(id string) (Task, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	task, ok := t.tasks[id]
	if !ok {
		return Task{}, false
	}
	return *task, true
}

// Forget drops a task from the tracker.
func (t *Tracker) Forget(id string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.tasks[id]
	if ok {
		delete(t.tasks, id)
	}
	return ok
}

func (t *Tracker) evictIfFullLocked() {
	if len(t.tasks) < t.maxTasks {
		return
	}
	// Drop the single oldest entry. Cheap and correct under our caps.
	var oldest *Task
	for _, task := range t.tasks {
		if oldest == nil || task.Updated.Before(oldest.Updated) {
			oldest = task
		}
	}
	if oldest != nil {
		delete(t.tasks, oldest.ID)
	}
}

func firstState(s State) State {
	if s == StateUnknown {
		return StateSubmitted
	}
	return s
}

// ValidateDeclaredHistory inspects the self-declared state history a peer
// puts in a single task response (A2A x_state_history). Unlike Update,
// which tracks live observations across calls, this catches drift a peer
// asserts all at once: a task that reports `completed` without ever
// passing through `working` (work claimed done that never ran), and any
// step in the declared sequence that is not a legal lifecycle transition.
func ValidateDeclaredHistory(history []State) []Finding {
	if len(history) == 0 {
		return nil
	}
	var findings []Finding
	sawWorking := false
	reachedCompleted := false
	for _, s := range history {
		if s == StateWorking || s == StateInputRequired {
			sawWorking = true
		}
		if s == StateCompleted {
			reachedCompleted = true
		}
	}
	if reachedCompleted && !sawWorking {
		findings = append(findings, Finding{
			Code:    "task.state_skip",
			Message: "task reported completed without ever entering working (no work in between)",
		})
	}
	for i := 1; i < len(history); i++ {
		if history[i] == history[i-1] {
			continue
		}
		if !validTransition(history[i-1], history[i]) {
			findings = append(findings, Finding{
				Code:    "task.invalid_transition",
				Message: "declared invalid state transition " + string(history[i-1]) + " -> " + string(history[i]),
			})
		}
	}
	return findings
}

// validTransition encodes the lifecycle the A2A protocol expects.
// Backward transitions (e.g. completed → working) are flagged as
// suspicious, replay attempts or sneaky scope changes.
func validTransition(from, to State) bool {
	allowed := map[State][]State{
		StateUnknown:       {StateSubmitted, StateWorking, StateInputRequired, StateCompleted, StateCanceled, StateFailed},
		StateSubmitted:     {StateWorking, StateInputRequired, StateCanceled, StateFailed, StateCompleted},
		StateWorking:       {StateInputRequired, StateCompleted, StateCanceled, StateFailed},
		StateInputRequired: {StateWorking, StateCanceled, StateFailed, StateCompleted},
		StateCompleted:     {}, // terminal
		StateCanceled:      {}, // terminal
		StateFailed:        {}, // terminal
	}
	for _, s := range allowed[from] {
		if s == to {
			return true
		}
	}
	return false
}
