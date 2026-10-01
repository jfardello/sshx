package keystore

import (
	"context"
	"testing"

	"github.com/jfardello/sshx/internal/credential"
)

func TestOpenRejectsFallbackAndSupportsGopass(t *testing.T) {
	if _, err := Open(context.Background(), credential.BackendAuto); err == nil {
		t.Fatal("automatic backend fallback accepted")
	}
	store, err := Open(context.Background(), credential.BackendGopass)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}
