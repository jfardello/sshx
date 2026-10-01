package gopass

import (
	"reflect"
	"testing"
)

func TestFilterEntriesPrefersExactMatch(t *testing.T) {
	entries := []string{
		"infrastructure/production/backup-user@example.com",
		"infrastructure/production/user@example.com",
		"infrastructure/production/nested/user@example.com",
	}

	got := filterEntries(entries, "infrastructure/production", "user@example.com")
	want := []string{
		"infrastructure/production/user@example.com",
		"infrastructure/production/nested/user@example.com",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("filterEntries() = %#v, want %#v", got, want)
	}
}

func TestFilterEntriesFallsBackToCaseInsensitivePartialMatch(t *testing.T) {
	entries := []string{
		"production/servers/Admin@Example.com",
		"production/databases/admin",
		"personal/user@example.com",
	}

	got := filterEntries(entries, "production", "example")
	want := []string{"production/servers/Admin@Example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("filterEntries() = %#v, want %#v", got, want)
	}
}
