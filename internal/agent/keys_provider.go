package agent

import (
	"context"
	"errors"

	"golang.org/x/crypto/ssh"
)

// withKey bounds ownership of private material to one local operation. The caller
// must authorize that operation first; this is not a public signing/agent API.
// Only the signing service may retain a signer under a revocable cache lease.
// Go does not guarantee secure erasure of parser allocations.
func (r *agentRegistry) withKey(ctx context.Context, id string, store keyMaterialStore, use func(ssh.Signer) error, parsers ...func([]byte, ssh.PublicKey) (ssh.Signer, error)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, key := range r.keys {
		if key.record.ID == id && key.record.Enabled {
			if store == nil || use == nil {
				return errCredentialRead
			}
			data, err := store.KeyMaterial(ctx, credentialRef{Backend: key.record.Backend, ID: key.record.Reference, Collection: key.record.Collection})
			defer clearBytes(data)
			if err != nil {
				return sanitizeKeyReadError(ctx, err)
			}
			parse := parseRegisteredPrivateKey
			if len(parsers) > 0 {
				parse = parsers[0]
			}
			signer, err := parse(data, key.publicKey)
			if err != nil {
				return err
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			return use(signer)
		}
	}
	return errCredentialReference
}

func sanitizeKeyReadError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	for _, known := range []error{context.Canceled, context.DeadlineExceeded, errCredentialLocked, errCredentialProviderChanged, errCredentialReference, errCredentialTooLarge, errKeyUnsupported, errKeyMismatch} {
		if errors.Is(err, known) {
			return known
		}
	}
	return errCredentialRead
}
