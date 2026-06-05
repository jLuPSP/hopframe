package quarantine

import (
	"testing"
	"time"
)

func TestQuarantineLookup(t *testing.T) {
	s := New(time.Hour)
	s.Quarantine("badtool", "fishy description", "tp.test", "high")
	if e, ok := s.Lookup("badtool"); !ok || e.RuleID != "tp.test" {
		t.Fatalf("lookup: ok=%v entry=%+v", ok, e)
	}
	if _, ok := s.Lookup("goodtool"); ok {
		t.Fatalf("unexpected hit on goodtool")
	}
}

func TestQuarantineExpires(t *testing.T) {
	s := New(50 * time.Millisecond)
	s.Quarantine("t", "r", "x", "high")
	if _, ok := s.Lookup("t"); !ok {
		t.Fatalf("expected hit immediately")
	}
	time.Sleep(80 * time.Millisecond)
	if _, ok := s.Lookup("t"); ok {
		t.Fatalf("expected expiry")
	}
}

func TestQuarantineClearAndList(t *testing.T) {
	s := New(time.Hour)
	s.Quarantine("a", "r", "x", "high")
	s.Quarantine("b", "r", "x", "high")
	if s.Len() != 2 {
		t.Fatalf("len = %d", s.Len())
	}
	if !s.Clear("a") {
		t.Fatalf("clear a should report true")
	}
	if s.Clear("a") {
		t.Fatalf("second clear should report false")
	}
	if s.Len() != 1 {
		t.Fatalf("len after clear = %d", s.Len())
	}
	list := s.List()
	if len(list) != 1 || list[0].Tool != "b" {
		t.Fatalf("list = %+v", list)
	}
}
