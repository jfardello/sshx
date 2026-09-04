package main

import (
	"bytes"
	"reflect"
	"testing"
)

func TestGopassSearchReturnsNeutralCredentialMetadata(t *testing.T) {
	var gotArgs []string
	store := &gopassStore{
		executeCommand: func(args ...string) ([]byte, []byte, error) {
			gotArgs = append([]string(nil), args...)
			return []byte(
				"other/user@example.com\n" +
					"infrastructure/production/user@example.com\n" +
					"infrastructure/production/backup-user@example.com\n",
			), nil, nil
		},
	}

	credentials, err := store.Search(credentialQuery{
		Collection: "infrastructure/production",
		Text:       "user@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"list", "--flat", "--", "infrastructure/production"}; !reflect.DeepEqual(gotArgs, want) {
		t.Fatalf("gopass args = %#v, want %#v", gotArgs, want)
	}

	want := []credentialRef{
		{
			Backend:    credentialBackendGopass,
			ID:         "infrastructure/production/user@example.com",
			Collection: "infrastructure/production",
			Label:      "user@example.com",
			Target:     "user@example.com",
		},
	}
	if !reflect.DeepEqual(credentials, want) {
		t.Fatalf("credentials = %#v, want %#v", credentials, want)
	}
}

func TestGopassSearchUsesParentPathAsDiscoveryCollection(t *testing.T) {
	store := &gopassStore{
		executeCommand: func(args ...string) ([]byte, []byte, error) {
			return []byte("servers/production/admin@example.com\nroot@example.com\n"), nil, nil
		},
	}

	credentials, err := store.Search(credentialQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(credentials) != 2 {
		t.Fatalf("credentials = %#v, want 2 entries", credentials)
	}
	if got, want := credentials[0].Collection, "servers/production"; got != want {
		t.Fatalf("nested collection = %q, want %q", got, want)
	}
	if got := credentials[1].Collection; got != "" {
		t.Fatalf("root collection = %q, want empty", got)
	}
}

func TestGopassSecretUsesPasswordOnlyAndClearsCommandOutput(t *testing.T) {
	rawOutput := []byte("secret\r\n")
	var gotArgs []string
	store := &gopassStore{
		executeCommand: func(args ...string) ([]byte, []byte, error) {
			gotArgs = append([]string(nil), args...)
			return rawOutput, nil, nil
		},
	}

	secret, err := store.Secret(credentialRef{
		Backend: credentialBackendGopass,
		ID:      "servers/user@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clearBytes(secret)

	if want := []string{"show", "--password", "--", "servers/user@example.com"}; !reflect.DeepEqual(gotArgs, want) {
		t.Fatalf("gopass args = %#v, want %#v", gotArgs, want)
	}
	if !bytes.Equal(secret, []byte("secret")) {
		t.Fatalf("secret = %q", secret)
	}
	if !bytes.Equal(rawOutput, make([]byte, len(rawOutput))) {
		t.Fatalf("gopass command output was not cleared: %v", rawOutput)
	}
}

func TestGopassSecretRejectsForeignCredential(t *testing.T) {
	called := false
	store := &gopassStore{
		executeCommand: func(args ...string) ([]byte, []byte, error) {
			called = true
			return nil, nil, nil
		},
	}

	_, err := store.Secret(credentialRef{
		Backend: credentialBackendSecretService,
		ID:      "item",
	})
	if err == nil {
		t.Fatal("expected an error")
	}
	if called {
		t.Fatal("gopass was executed for a foreign credential")
	}
}
