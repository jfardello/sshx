package agent

import (
	"context"

	"github.com/jfardello/sshx/internal/credential"
)

type Registry = agentRegistry

type Server = agentServer

type StoreOpener func(context.Context, credential.Backend) (credential.KeyStore, error)

func LoadRegistry() (*Registry, error) { return loadAgentRegistry() }

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
