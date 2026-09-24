package cli

import (
	"context"
	"io"
	"os"

	"github.com/jfardello/sshx/internal/config"
	"github.com/jfardello/sshx/internal/credential"
	"github.com/jfardello/sshx/internal/credential/gopass"
	"github.com/jfardello/sshx/internal/credential/secretservice"
	sshpty "github.com/jfardello/sshx/internal/pty"
	"github.com/jfardello/sshx/internal/sensitive"
)

type credentialBackend = credential.Backend
type credentialRef = credential.Ref
type credentialQuery = credential.Query
type credentialReadOptions = credential.ReadOptions
type credentialStore = credential.Store
type credentialStoreProvider = credential.Provider
type optionOverrides = config.Overrides

const (
	credentialBackendAuto          = credential.BackendAuto
	credentialBackendSecretService = credential.BackendSecretService
	credentialBackendGopass        = credential.BackendGopass
)

const maxConfigBytes = config.MaxBytes

type selectedCredentialStore struct {
	backend credentialBackend
	store   credentialStore
}

var clearBytes = sensitive.Clear

func newGopassStore(stderr io.Writer) credentialStore { return gopass.New(stderr) }
func newSecretServiceStore(ctx context.Context) (credentialStore, error) {
	return secretservice.New(ctx)
}
func loadUserConfig() (optionOverrides, error)           { return config.LoadUser() }
func loadConfig(name string) (optionOverrides, error)    { return config.Load(name) }
func decodeConfig(data []byte) (optionOverrides, error)  { return config.Decode(data) }
func resolveConfigPath(home, xdg string) (string, error) { return config.ResolvePath(home, xdg) }
func runPTY(program string, args []string, password []byte, stdin *os.File, stdout io.Writer) error {
	return sshpty.Run(program, args, password, stdin, stdout)
}
func parseCredentialBackend(value string) (credentialBackend, error) {
	return credential.ParseBackend(value)
}
func newCredentialBackendUnavailableError(backend credentialBackend, err error) error {
	return credential.NewBackendUnavailableError(backend, err)
}
func selectCredentialStore(backend credentialBackend, goos string, gopassStore credentialStore, provider credentialStoreProvider, contexts ...context.Context) (selectedCredentialStore, error) {
	ctx := context.Background()
	if len(contexts) > 0 {
		ctx = contexts[0]
	}
	selection, err := credential.Select(backend, goos, gopassStore, provider, ctx)
	return selectedCredentialStore{backend: selection.Backend(), store: selection.Store()}, err
}
func matchCredentials(query string, refs []credentialRef) ([]credentialRef, error) {
	return credential.Match(query, refs)
}
func credentialsForListing(query string, refs []credentialRef) []credentialRef {
	return credential.ForListing(query, refs)
}
func credentialIdentity(ref credentialRef) string { return credential.Identity(ref) }
func credentialTarget(ref credentialRef, query string) (string, error) {
	return credential.Target(ref, query)
}
func isCredentialBackendUnavailable(err error) bool { return credential.IsBackendUnavailable(err) }
func copyOutputAndAnswer(input io.Reader, output io.Writer, ptyInput io.Writer, password []byte) error {
	return sshpty.CopyOutputAndAnswer(input, output, ptyInput, password)
}
