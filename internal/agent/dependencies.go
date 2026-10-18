package agent

import (
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
