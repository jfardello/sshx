package main

import (
	"errors"
	"fmt"
)

type credentialBackend string

const (
	credentialBackendAuto          credentialBackend = "auto"
	credentialBackendSecretService credentialBackend = "secret-service"
	credentialBackendGopass        credentialBackend = "gopass"
)

type credentialRef struct {
	Backend    credentialBackend
	ID         string
	Collection string
	Label      string
	Target     string
	Attributes map[string]string
}

type credentialQuery struct {
	Collection string
	Text       string
}

type credentialStore interface {
	Search(query credentialQuery) ([]credentialRef, error)
	Secret(credential credentialRef) ([]byte, error)
}

type credentialStoreProvider func() (credentialStore, error)

type credentialBackendUnavailableError struct {
	backend credentialBackend
	err     error
}

func (e *credentialBackendUnavailableError) Error() string {
	if e.err == nil {
		return fmt.Sprintf("credential backend %q is unavailable", e.backend)
	}
	return fmt.Sprintf("credential backend %q is unavailable: %v", e.backend, e.err)
}

func (e *credentialBackendUnavailableError) Unwrap() error {
	return e.err
}

func newCredentialBackendUnavailableError(backend credentialBackend, err error) error {
	return &credentialBackendUnavailableError{backend: backend, err: err}
}

func isCredentialBackendUnavailable(err error) bool {
	var unavailable *credentialBackendUnavailableError
	return errors.As(err, &unavailable)
}

func parseCredentialBackend(value string) (credentialBackend, error) {
	backend := credentialBackend(value)
	switch backend {
	case credentialBackendAuto, credentialBackendSecretService, credentialBackendGopass:
		return backend, nil
	default:
		return "", fmt.Errorf(
			"invalid credential backend %q (expected auto, secret-service, or gopass)",
			value,
		)
	}
}

func selectCredentialStore(
	backend credentialBackend,
	gopass credentialStore,
	secretService credentialStoreProvider,
) (credentialStore, error) {
	if backend == "" {
		backend = credentialBackendAuto
	}

	switch backend {
	case credentialBackendGopass:
		return configuredCredentialStore(credentialBackendGopass, gopass)
	case credentialBackendSecretService:
		return openSecretServiceStore(secretService)
	case credentialBackendAuto:
		store, err := openSecretServiceStore(secretService)
		if err == nil {
			return store, nil
		}
		if !isCredentialBackendUnavailable(err) {
			return nil, err
		}
		return configuredCredentialStore(credentialBackendGopass, gopass)
	default:
		return nil, fmt.Errorf("unsupported credential backend %q", backend)
	}
}

func configuredCredentialStore(backend credentialBackend, store credentialStore) (credentialStore, error) {
	if store == nil {
		return nil, newCredentialBackendUnavailableError(backend, nil)
	}
	return store, nil
}

func openSecretServiceStore(provider credentialStoreProvider) (credentialStore, error) {
	if provider == nil {
		return nil, newCredentialBackendUnavailableError(
			credentialBackendSecretService,
			errors.New("support is not implemented yet"),
		)
	}

	store, err := provider()
	if err != nil {
		return nil, err
	}
	return configuredCredentialStore(credentialBackendSecretService, store)
}
