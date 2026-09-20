package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/pem"

	"golang.org/x/crypto/ssh"
)

const maxAgentBcryptRounds = 64

// Inspect the complete envelope before prompting or invoking a KDF. The only
// encrypted formats admitted are single-key OpenSSH bcrypt/AES-256 CTR or CBC.
func encryptedAgentEnvelope(data []byte, public ssh.PublicKey) (bool, error) {
	if len(data) > maxKeyMaterialBytes {
		return false, errCredentialTooLarge
	}
	trimmed := bytes.TrimSpace(data)
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN OPENSSH PRIVATE KEY-----")) {
		return false, nil
	}
	block, rest := pem.Decode(trimmed)
	if block == nil {
		return false, errKeyUnsupported
	}
	defer clearBytes(block.Bytes)
	if block.Type != "OPENSSH PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 || bytes.Count(trimmed, []byte("-----BEGIN ")) != 1 {
		return false, errKeyUnsupported
	}
	const magic = "openssh-key-v1\x00"
	if !bytes.HasPrefix(block.Bytes, []byte(magic)) {
		return false, errKeyUnsupported
	}
	cipher, data, ok := agentWireString(block.Bytes[len(magic):])
	if !ok {
		return false, errKeyUnsupported
	}
	kdf, data, ok := agentWireString(data)
	if !ok {
		return false, errKeyUnsupported
	}
	opts, data, ok := agentWireString(data)
	if !ok {
		return false, errKeyUnsupported
	}
	if string(cipher) == "none" && string(kdf) == "none" {
		return false, nil
	}
	if (string(cipher) != "aes256-ctr" && string(cipher) != "aes256-cbc") || string(kdf) != "bcrypt" {
		return false, errKeyUnsupported
	}
	salt, rounds, ok := agentWireString(opts)
	if !ok || len(salt) < 16 || len(salt) > 64 || len(rounds) != 4 || binary.BigEndian.Uint32(rounds) == 0 || binary.BigEndian.Uint32(rounds) > maxAgentBcryptRounds {
		return false, errKeyUnsupported
	}
	if len(data) < 4 || binary.BigEndian.Uint32(data) != 1 {
		return false, errKeyUnsupported
	}
	pub, data, ok := agentWireString(data[4:])
	if !ok {
		return false, errKeyUnsupported
	}
	if public == nil || !bytes.Equal(pub, public.Marshal()) {
		return false, errKeyMismatch
	}
	encrypted, rest, ok := agentWireString(data)
	if !ok || len(rest) != 0 || len(encrypted) < 16 || len(encrypted)%16 != 0 {
		return false, errKeyUnsupported
	}
	return true, nil
}

func parseAgentKeyWithPrompt(ctx context.Context, data []byte, public ssh.PublicKey, prompt *agentPrompter, request agentPromptRequest, revalidate func() error) (ssh.Signer, error) {
	encrypted, err := encryptedAgentEnvelope(data, public)
	if err != nil {
		return nil, err
	}
	if !encrypted {
		return parseRegisteredPrivateKey(data, public)
	}
	if err := revalidate(); err != nil {
		return nil, err
	}
	passphrase, err := askAgentPrompt(ctx, prompt, request, "passphrase")
	defer clearBytes(passphrase)
	if err != nil {
		return nil, err
	}
	if len(passphrase) == 0 || len(passphrase) > maxAgentPassphraseBytes {
		return nil, errAgentPassphrase
	}
	if err := revalidate(); err != nil {
		return nil, err
	}
	private, err := ssh.ParseRawPrivateKeyWithPassphrase(data, passphrase)
	if err != nil {
		return nil, errAgentPassphrase
	}
	if err := revalidate(); err != nil {
		return nil, err
	}
	return validateRegisteredPrivateKey(private, public)
}
