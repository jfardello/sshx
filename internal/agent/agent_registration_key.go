package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/pem"
	"errors"

	"golang.org/x/crypto/ssh"
)

// RegistrationPublicKey derives a public identity only after validating the
// complete private key. It accepts the same bounded formats and algorithms as
// ValidateKeyMaterial. Encrypted OpenSSH envelopes are checked before prompting
// or running the bounded KDF; their public identity alone is never sufficient.
//
// data is borrowed and is not modified. prompt is called at most once and must
// transfer ownership of its returned buffer (even on error); that buffer is
// always cleared. A nil prompt for an accepted encrypted key returns
// ErrKeyPassphrase. Unknown callback errors are also sanitized to ErrKeyPassphrase;
// only context errors and ErrKeyPassphrase are preserved, without wrapping.
// Callers can track missing-terminal failures separately in their callback.
//
// Errors use the categories documented by ValidateKeyMaterial. Cancellation is
// checked before and after parsing and prompting, but cannot interrupt the KDF.
func RegistrationPublicKey(ctx context.Context, data []byte, prompt func(context.Context) ([]byte, error)) (public ssh.PublicKey, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	defer func() {
		if contextErr := ctx.Err(); contextErr != nil {
			public, err = nil, contextErr
		}
	}()
	if len(data) > maxKeyMaterialBytes {
		return nil, errCredentialTooLarge
	}
	trimmed := bytes.TrimSpace(data)
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
		return nil, errKeyUnsupported
	}
	block, rest := pem.Decode(trimmed)
	if block == nil {
		return nil, errKeyUnsupported
	}
	defer clearBytes(block.Bytes)
	if bytes.Count(trimmed, []byte("-----BEGIN ")) != 1 || len(bytes.TrimSpace(rest)) != 0 || len(block.Headers) != 0 {
		return nil, errKeyUnsupported
	}
	switch block.Type {
	case "OPENSSH PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "PRIVATE KEY":
	default:
		return nil, errKeyUnsupported
	}
	if !boundedPrivateKeyDER(block) {
		return nil, errKeyUnsupported
	}
	var preliminary ssh.PublicKey
	if block.Type == "OPENSSH PRIVATE KEY" {
		var encrypted bool
		preliminary, encrypted, err = registrationEnvelopeIdentity(block.Bytes)
		if err != nil {
			return nil, err
		}
		if encrypted {
			// The preliminary wire parse is not admission: inspect the complete
			// envelope, including KDF limits, before invoking user code.
			if accepted, err := encryptedAgentEnvelope(data, preliminary); err != nil {
				return nil, err
			} else if !accepted {
				return nil, errKeyUnsupported
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if prompt == nil {
				return nil, ErrKeyPassphrase
			}
			passphrase, err := prompt(ctx)
			defer clearBytes(passphrase)
			if contextErr := ctx.Err(); contextErr != nil {
				return nil, contextErr
			}
			if err != nil {
				for _, known := range []error{context.Canceled, context.DeadlineExceeded, ErrKeyPassphrase} {
					if errors.Is(err, known) {
						return nil, known
					}
				}
				return nil, ErrKeyPassphrase
			}
			signer, err := parseAgentKeyWithPassphrase(data, preliminary, passphrase)
			if err != nil {
				return nil, err
			}
			return signer.PublicKey(), nil
		}
	}
	// The PEM and DER boundaries above must precede upstream parsing, which
	// may perform expensive arithmetic on ASN.1 integers.
	private, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		return nil, errKeyUnsupported
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		return nil, errKeyUnsupported
	}
	if preliminary == nil {
		preliminary = signer.PublicKey()
	}
	signer, err = validateRegisteredPrivateKey(private, preliminary)
	if err != nil {
		return nil, err
	}
	return signer.PublicKey(), nil
}

// Extract only enough envelope metadata to distinguish encryption and pin its
// preliminary public identity. encryptedAgentEnvelope performs admission.
func registrationEnvelopeIdentity(data []byte) (ssh.PublicKey, bool, error) {
	const magic = "openssh-key-v1\x00"
	if !bytes.HasPrefix(data, []byte(magic)) {
		return nil, false, errKeyUnsupported
	}
	cipher, data, ok := agentWireString(data[len(magic):])
	if !ok {
		return nil, false, errKeyUnsupported
	}
	kdf, data, ok := agentWireString(data)
	if !ok {
		return nil, false, errKeyUnsupported
	}
	opts, data, ok := agentWireString(data)
	if !ok {
		return nil, false, errKeyUnsupported
	}
	encrypted := string(cipher) != "none" || string(kdf) != "none"
	if !encrypted && len(opts) != 0 {
		return nil, false, errKeyUnsupported
	}
	if len(data) < 4 || binary.BigEndian.Uint32(data) != 1 {
		return nil, false, errKeyUnsupported
	}
	blob, _, ok := agentWireString(data[4:])
	if !ok {
		return nil, false, errKeyUnsupported
	}
	public, err := ssh.ParsePublicKey(blob)
	if err != nil || !supportedAgentPublicKey(public) {
		return nil, false, errKeyUnsupported
	}
	return public, encrypted, nil
}
