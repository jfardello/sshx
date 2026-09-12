package keystore

import (
	"context"
	"errors"
	"io"

	"github.com/jfardello/sshx/internal/credential"
	"github.com/jfardello/sshx/internal/credential/gopass"
	"github.com/jfardello/sshx/internal/credential/secretservice"
)

var errUnsupportedBackend = errors.New("unsupported key credential backend")

// Open creates one exact, non-fallback key-material store for a signing job.
func Open(ctx context.Context, backend credential.Backend) (credential.KeyStore, error) {
	switch backend {
	case credential.BackendGopass:
		return gopass.New(io.Discard), nil
	case credential.BackendSecretService:
		return secretservice.New(ctx)
	default:
		return nil, errUnsupportedBackend
	}
}
