package main

import (
	"strings"
	"testing"

	"github.com/jlupsp/hopframe/control-plane/api"
)

func TestParseRoleTokensCanonical(t *testing.T) {
	got, err := parseRoleTokens("a:viewer,b:editor,c:admin,d:owner")
	if err != nil {
		t.Fatalf("parseRoleTokens: %v", err)
	}
	want := map[string]api.Role{
		"a": api.RoleViewer,
		"b": api.RoleEditor,
		"c": api.RoleAdmin,
		"d": api.RoleOwner,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d", len(got), len(want))
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("got[%q] = %q, want %q", k, got[k], v)
		}
	}
}

func TestParseRoleTokensLegacyAliasesNormalizeToCanonical(t *testing.T) {
	// Old config from before the LaunchDarkly-style rename. These must
	// keep working but should land in the in-memory map under the new
	// names so downstream code only ever sees canonical roles.
	got, err := parseRoleTokens("a:policy_author,b:tenant_admin,c:super_admin")
	if err != nil {
		t.Fatalf("parseRoleTokens legacy: %v", err)
	}
	if got["a"] != api.RoleEditor {
		t.Errorf("policy_author should normalize to editor, got %q", got["a"])
	}
	if got["b"] != api.RoleAdmin {
		t.Errorf("tenant_admin should normalize to admin, got %q", got["b"])
	}
	if got["c"] != api.RoleOwner {
		t.Errorf("super_admin should normalize to owner, got %q", got["c"])
	}
}

func TestParseRoleTokensUnknownRoleRejected(t *testing.T) {
	_, err := parseRoleTokens("a:janitor")
	if err == nil {
		t.Fatal("expected error on unknown role")
	}
	// The error message should now point at canonical names so an
	// operator following the message ends up with config that works.
	if !strings.Contains(err.Error(), "viewer") || !strings.Contains(err.Error(), "owner") {
		t.Errorf("error %q should reference canonical role names", err)
	}
	if strings.Contains(err.Error(), "policy_author") || strings.Contains(err.Error(), "super_admin") {
		t.Errorf("error %q should not reference deprecated alias names", err)
	}
}

func TestParseRoleTokensMalformed(t *testing.T) {
	cases := []string{
		"missing-colon",
		"too:many:colons:viewer", // first colon is splitter, the rest is part of the role string and won't match
	}
	for _, in := range cases {
		if _, err := parseRoleTokens(in); err == nil {
			t.Errorf("expected error for %q", in)
		}
	}
}

func TestParseRoleTokensEmpty(t *testing.T) {
	if _, err := parseRoleTokens(""); err == nil {
		t.Fatal("expected error on empty input")
	}
	if _, err := parseRoleTokens("  ,  ,  "); err == nil {
		t.Fatal("expected error when all entries are blank")
	}
}

func TestParseRoleTokensMixedCanonicalAndAlias(t *testing.T) {
	got, err := parseRoleTokens("new:editor,old:policy_author")
	if err != nil {
		t.Fatalf("parseRoleTokens mixed: %v", err)
	}
	if got["new"] != api.RoleEditor || got["old"] != api.RoleEditor {
		t.Errorf("both should land at editor: %+v", got)
	}
}
