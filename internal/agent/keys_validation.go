package agent

import (
	"context"

	"golang.org/x/crypto/ssh"
)

// ErrKeyPassphrase is the sanitized error for a missing, excessive, or incorrect
// passphrase, or an encrypted OpenSSH key that could not be decrypted.
var ErrKeyPassphrase = errAgentPassphrase

// ValidateKeyMaterial validates bounded private key material against an expected
// public identity without prompting or accessing credential providers or files.
// The caller retains ownership of data and passphrase; neither buffer is cleared
// or modified. Passphrases are used only for encrypted OpenSSH keys. Cancellation
// is checked before and after validation, but cannot interrupt the bounded KDF.
//
// Errors are sanitized and can be classified with errors.Is: credential.ErrKeyUnsupported
// for unsupported or malformed material, credential.ErrKeyMismatch for a missing
// or mismatched expected public key, credential.ErrTooLarge for oversized material,
// ErrKeyPassphrase for encrypted-key passphrase or decryption failures, and
// context.Canceled or context.DeadlineExceeded for cancellation.
func ValidateKeyMaterial(ctx context.Context, data []byte, public ssh.PublicKey, passphrase []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err := parseAgentKeyWithPassphrase(data, public, passphrase)
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	return err
}

func parseAgentKeyWithPassphrase(data []byte, public ssh.PublicKey, passphrase []byte) (ssh.Signer, error) {
	if public == nil {
		return nil, errKeyMismatch
	}
	encrypted, err := encryptedAgentEnvelope(data, public)
	if err != nil {
		return nil, err
	}
	if !encrypted {
		return parseRegisteredPrivateKey(data, public)
	}
	if len(passphrase) == 0 || len(passphrase) > maxAgentPassphraseBytes {
		return nil, errAgentPassphrase
	}
	private, err := ssh.ParseRawPrivateKeyWithPassphrase(data, passphrase)
	if err != nil {
		return nil, errAgentPassphrase
	}
	return validateRegisteredPrivateKey(private, public)
}
