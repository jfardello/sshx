package credential

import (
	"context"
	"errors"
	"testing"
)

func TestPublicCredentialAPI(t *testing.T) {
	backend, err := ParseBackend("gopass")
	if err != nil || backend != BackendGopass {
		t.Fatal("parse backend", backend, err)
	}
	if _, err := ParseBackend("invalid"); err == nil {
		t.Fatal("invalid backend accepted")
	}

	store := &recordingStore{}
	selection, err := Select(BackendGopass, "linux", store, nil, context.Background())
	if err != nil || selection.Backend() != BackendGopass || selection.Store() != store {
		t.Fatal("select gopass", err)
	}
	cause := errors.New("unavailable")
	unavailable := NewBackendUnavailableError(BackendSecretService, cause)
	if !IsBackendUnavailable(unavailable) || !errors.Is(unavailable, cause) {
		t.Fatal("backend availability classification")
	}

	ref := Ref{Backend: BackendGopass, ID: "servers/user@host", Label: "user@host", Target: "user@host"}
	matches, err := Match("user@host", []Ref{ref})
	if err != nil || len(matches) != 1 || Identity(matches[0]) != ref.ID {
		t.Fatal("credential matching", err)
	}
	if listed := ForListing("", []Ref{ref}); len(listed) != 1 {
		t.Fatal("credential listing")
	}
	if target, err := Target(ref, ""); err != nil || target != "user@host" {
		t.Fatal("credential target", target, err)
	}

	for _, valid := range []string{"key", "team/key_1"} {
		if !ValidGopassReference(valid) {
			t.Fatal("valid gopass reference rejected", valid)
		}
	}
	for _, invalid := range []string{"", "/key", "../key", "team//key", "-key", "key\nnext"} {
		if ValidGopassReference(invalid) {
			t.Fatal("invalid gopass reference accepted", invalid)
		}
	}
	if !ValidRegistryID("key_1") || ValidRegistryID("") || ValidRegistryID("../key") || ValidRegistryID(".") {
		t.Fatal("registry ID validation")
	}
	if !errors.Is(SanitizeKeyReadError(context.Background(), ErrLocked), ErrLocked) {
		t.Fatal("known key error changed")
	}
	if !errors.Is(SanitizeKeyReadError(context.Background(), errors.New("private provider detail")), ErrRead) {
		t.Fatal("unknown key error was not sanitized")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(SanitizeKeyReadError(cancelled, cause), context.Canceled) {
		t.Fatal("cancellation was not preserved")
	}
}
