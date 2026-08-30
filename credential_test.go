package main

import (
	"errors"
	"strings"
	"testing"
)

func TestSelectCredentialStoreUsesExplicitGopass(t *testing.T) {
	gopass := &recordingStore{}
	secretServiceCalls := 0

	store, err := selectCredentialStore(
		credentialBackendGopass,
		gopass,
		func() (credentialStore, error) {
			secretServiceCalls++
			return &recordingStore{}, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if store != gopass {
		t.Fatal("explicit gopass did not select the gopass store")
	}
	if secretServiceCalls != 0 {
		t.Fatalf("Secret Service provider calls = %d, want 0", secretServiceCalls)
	}
}

func TestSelectCredentialStoreUsesAvailableSecretService(t *testing.T) {
	gopass := &recordingStore{}
	secretService := &recordingStore{}

	store, err := selectCredentialStore(
		credentialBackendAuto,
		gopass,
		func() (credentialStore, error) {
			return secretService, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if store != secretService {
		t.Fatal("auto did not select the available Secret Service store")
	}
}

func TestSelectCredentialStoreAutoFallsBackOnlyWhenUnavailable(t *testing.T) {
	gopass := &recordingStore{}

	store, err := selectCredentialStore(
		credentialBackendAuto,
		gopass,
		func() (credentialStore, error) {
			return nil, newCredentialBackendUnavailableError(
				credentialBackendSecretService,
				errors.New("session bus is unavailable"),
			)
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if store != gopass {
		t.Fatal("auto did not fall back to gopass")
	}

	providerErr := errors.New("provider denied access")
	store, err = selectCredentialStore(
		credentialBackendAuto,
		gopass,
		func() (credentialStore, error) {
			return nil, providerErr
		},
	)
	if !errors.Is(err, providerErr) {
		t.Fatalf("error = %v, want provider error", err)
	}
	if store != nil {
		t.Fatal("auto selected a store after a non-unavailable provider error")
	}
}

func TestSelectCredentialStoreReportsUnavailableSecretService(t *testing.T) {
	store, err := selectCredentialStore(
		credentialBackendSecretService,
		&recordingStore{},
		nil,
	)
	if store != nil {
		t.Fatal("unexpected Secret Service store")
	}
	if !isCredentialBackendUnavailable(err) {
		t.Fatalf("error = %v, want backend-unavailable error", err)
	}
	if !strings.Contains(err.Error(), "support is not implemented yet") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCredentialBackendUnavailableErrorUnwrapsCause(t *testing.T) {
	cause := errors.New("missing session bus")
	err := newCredentialBackendUnavailableError(credentialBackendSecretService, cause)

	if !errors.Is(err, cause) {
		t.Fatalf("error %v does not unwrap its cause", err)
	}
	if !isCredentialBackendUnavailable(err) {
		t.Fatalf("error %v was not classified as unavailable", err)
	}
}
