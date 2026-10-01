package agent

import (
	"context"

	"github.com/jfardello/sshx/internal/credential"
	"github.com/jfardello/sshx/internal/sensitive"
)

type credentialBackend = credential.Backend
type credentialRef = credential.Ref
type credentialQuery = credential.Query
type credentialReadOptions = credential.ReadOptions
type keyMaterialStore = credential.KeyMaterialStore
type credentialKeyStore = credential.KeyStore

const (
	credentialBackendAuto          = credential.BackendAuto
	credentialBackendGopass        = credential.BackendGopass
	credentialBackendSecretService = credential.BackendSecretService
	credentialOperationTimeout     = credential.OperationTimeout
	maxKeyMaterialBytes            = 64 * 1024
)

var (
	errCredentialLocked          = credential.ErrLocked
	errCredentialProviderChanged = credential.ErrProviderChanged
	errCredentialRead            = credential.ErrRead
	errCredentialReference       = credential.ErrReference
	errCredentialTooLarge        = credential.ErrTooLarge
	errKeyUnsupported            = credential.ErrKeyUnsupported
	errKeyMismatch               = credential.ErrKeyMismatch
	clearBytes                   = sensitive.Clear
)

type Registry = agentRegistry
type Server = agentServer
type StoreOpener func(context.Context, credential.Backend) (credential.KeyStore, error)

func LoadRegistry() (*Registry, error)            { return loadAgentRegistry() }
func ReadRegistry(name string) (*Registry, error) { return readAgentRegistry(name) }
func NewServer(socketPath string, registry *Registry, opener StoreOpener) (*Server, error) {
	if opener == nil {
		return nil, errAgentDenied
	}
	var internal agentStoreOpener
	internal = func(ctx context.Context, backend credentialBackend) (credential.KeyStore, error) {
		return opener(ctx, backend)
	}
	return newAgentServer(socketPath, registry, internal)
}
