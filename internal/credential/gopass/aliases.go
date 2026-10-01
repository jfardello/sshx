package gopass

import (
	"io"

	"github.com/jfardello/sshx/internal/credential"
	"github.com/jfardello/sshx/internal/sensitive"
)

type credentialRef = credential.Ref
type credentialQuery = credential.Query
type credentialReadOptions = credential.ReadOptions

const (
	credentialBackendGopass        = credential.BackendGopass
	credentialBackendSecretService = credential.BackendSecretService
	credentialOperationTimeout     = credential.OperationTimeout
)

var (
	errCredentialReference = credential.ErrReference
	errCredentialTooLarge  = credential.ErrTooLarge
	errCredentialRead      = credential.ErrRead
	clearBytes             = sensitive.Clear
	sanitizeKeyReadError   = credential.SanitizeKeyReadError
	validAgentGopassPath   = credential.ValidGopassReference
)

type Store = gopassStore

func New(stderrWriter io.Writer) *Store {
	return newGopassStore(stderrWriter)
}

func KeyEnvironment(inherited []string) []string { return gopassKeyEnvironment(inherited) }
