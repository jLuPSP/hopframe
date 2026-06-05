package taskstate

import (
	"testing"
	"time"
)

func TestUpdateCreatesAndAdvances(t *testing.T) {
	tr := New(time.Hour, 100)
	task, findings := tr.Update("t1", "peer-a", StateSubmitted, "fp1")
	if task == nil || task.Current != StateSubmitted {
		t.Fatalf("create: %+v", task)
	}
	if len(findings) != 0 {
		t.Fatalf("unexpected findings on create: %+v", findings)
	}

	_, _ = tr.Update("t1", "peer-a", StateWorking, "fp1")
	got, _ := tr.Get("t1")
	if got.Current != StateWorking {
		t.Fatalf("state = %q", got.Current)
	}
	if len(got.History) != 2 {
		t.Fatalf("history len = %d", len(got.History))
	}
}

func TestInvalidTransitionFlagged(t *testing.T) {
	tr := New(time.Hour, 100)
	tr.Update("t1", "p", StateSubmitted, "fp")
	tr.Update("t1", "p", StateCompleted, "fp")
	_, findings := tr.Update("t1", "p", StateWorking, "fp")
	hit := false
	for _, f := range findings {
		if f.Code == "task.invalid_transition" {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("expected invalid_transition finding, got %+v", findings)
	}
}

func TestScopeDriftFlagged(t *testing.T) {
	tr := New(time.Hour, 100)
	tr.Update("t1", "p", StateSubmitted, "abc123")
	_, findings := tr.Update("t1", "p", StateWorking, "xyz456")
	hit := false
	for _, f := range findings {
		if f.Code == "task.scope_drift" {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("expected scope_drift finding, got %+v", findings)
	}
}

func TestCounterpartyChangeFlagged(t *testing.T) {
	tr := New(time.Hour, 100)
	tr.Update("t1", "peer-a", StateSubmitted, "fp")
	_, findings := tr.Update("t1", "peer-b", StateWorking, "fp")
	hit := false
	for _, f := range findings {
		if f.Code == "task.counterparty_changed" {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("expected counterparty_changed, got %+v", findings)
	}
}

func TestCheckLongRunning(t *testing.T) {
	tr := New(50*time.Millisecond, 100)
	tr.Update("t1", "p", StateWorking, "fp")
	tr.Update("t2", "p", StateCompleted, "fp")
	time.Sleep(80 * time.Millisecond)
	long := tr.CheckLongRunning()
	if len(long) != 1 || long[0].ID != "t1" {
		t.Fatalf("expected t1 only, got %+v", long)
	}
}

func TestMaxTasksEviction(t *testing.T) {
	tr := New(time.Hour, 2)
	tr.Update("t1", "p", StateSubmitted, "fp")
	tr.Update("t2", "p", StateSubmitted, "fp")
	tr.Update("t3", "p", StateSubmitted, "fp")
	if tr.Len() != 2 {
		t.Fatalf("expected 2 after eviction, got %d", tr.Len())
	}
}
