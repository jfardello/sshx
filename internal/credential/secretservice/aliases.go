package secretservice

import (
	"context"

	"github.com/jfardello/sshx/internal/credential"
	"github.com/jfardello/sshx/internal/sensitive"
)

type credentialBackend = credential.Backend
type credentialRef = credential.Ref
type credentialQuery = credential.Query
type credentialReadOptions = credential.ReadOptions
type credentialStore = credential.Store
type keyMaterialStore = credential.KeyMaterialStore

const (
	credentialBackendSecretService = credential.BackendSecretService
	credentialOperationTimeout     = credential.OperationTimeout
	credentialCleanupTimeout       = credential.CleanupTimeout
	maxKeyMaterialBytes            = 64 * 1024
	maxCredentialOutputBytes       = 1024 * 1024
)

var (
	errCredentialLocked                  = credential.ErrLocked
	errCredentialProviderChanged         = credential.ErrProviderChanged
	errCredentialReference               = credential.ErrReference
	errCredentialTooLarge                = credential.ErrTooLarge
	clearBytes                           = sensitive.Clear
	sanitizeKeyReadError                 = credential.SanitizeKeyReadError
	validRegistryID                      = credential.ValidRegistryID
	newCredentialBackendUnavailableError = credential.NewBackendUnavailableError
)

func New(ctx context.Context) (credential.BackendStore, error) {
	store, err := newSecretServiceStore(ctx)
	if err != nil {
		return nil, err
	}
	return store.(*secretServiceStore), nil
}
