package agent

import (
	"context"
	"errors"

	"golang.org/x/crypto/ssh"
)

const maxAgentRegistryBytes = 1024 * 1024

var errAgentRegistry = errors.New("invalid or untrusted SSH key registry")

// Registry data is public, owner-approved configuration. Backend metadata never
// changes enablement or policy. Version 2 adds explicitly pinned destinations.
type agentRegistryDocument struct {
	Version int              `json:"version"`
	Keys    []agentKeyRecord `json:"keys"`
}

type agentKeyRecord struct {
	Confirm      bool                    `json:"confirm,omitempty"`
	ID           string                  `json:"id"`
	PublicKey    string                  `json:"public_key"`
	Enabled      bool                    `json:"enabled"`
	Policy       string                  `json:"policy"`
	Comment      string                  `json:"comment,omitempty"`
	Backend      credentialBackend       `json:"backend"`
	Reference    string                  `json:"reference"`
	Collection   string                  `json:"collection,omitempty"`
	Destinations *agentDestinationPolicy `json:"destinations,omitempty"`
}

type registeredAgentKey struct {
	record    agentKeyRecord
	publicKey ssh.PublicKey
	policy    *agentPolicy
}

type agentRegistry struct {
	keys   []registeredAgentKey
	source string
}

type agentIdentity struct {
	ID        string
	PublicKey ssh.PublicKey
	Comment   string
}

func (r *agentRegistry) List(ctx context.Context) ([]agentIdentity, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	identities := []agentIdentity{}
	for _, key := range r.keys {
		if key.record.Enabled {
			// Return fresh parsed keys so callers cannot mutate the trusted registry.
			pub, err := ssh.ParsePublicKey(key.publicKey.Marshal())
			if err != nil {
				return nil, errAgentRegistry
			}
			identities = append(identities, agentIdentity{ID: key.record.ID, PublicKey: pub, Comment: key.record.Comment})
		}
	}
	return identities, nil
}
