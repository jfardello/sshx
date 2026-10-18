package agent

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/pem"

	"golang.org/x/crypto/ssh"
)

func supportedAgentPublicKey(pub ssh.PublicKey) bool {
	crypto, ok := pub.(ssh.CryptoPublicKey)
	if !ok {
		return false
	}
	switch key := crypto.CryptoPublicKey().(type) {
	case ed25519.PublicKey:
		return len(key) == ed25519.PublicKeySize
	case *rsa.PublicKey:
		return key.N.BitLen() >= 2048 && key.N.BitLen() <= 8192 && key.E >= 3 && key.E%2 == 1
	case *ecdsa.PublicKey:
		return key.Curve.Params().Name == "P-256" || key.Curve.Params().Name == "P-384" || key.Curve.Params().Name == "P-521"
	}
	return false
}

func parseRegisteredPrivateKey(data []byte, public ssh.PublicKey) (ssh.Signer, error) {
	if len(data) > maxKeyMaterialBytes {
		return nil, errCredentialTooLarge
	}
	trimmed := bytes.TrimSpace(data)
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
		return nil, errKeyUnsupported
	}
	block, rest := pem.Decode(trimmed)
	if block == nil || bytes.Count(trimmed, []byte("-----BEGIN ")) != 1 {
		return nil, errKeyUnsupported
	}
	defer clearBytes(block.Bytes)
	if len(bytes.TrimSpace(rest)) != 0 || len(block.Headers) != 0 {
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
	private, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		return nil, errKeyUnsupported
	}
	return validateRegisteredPrivateKey(private, public)
}

func validateRegisteredPrivateKey(private any, public ssh.PublicKey) (ssh.Signer, error) {
	var ed ed25519.PrivateKey
	switch key := private.(type) {
	case *ed25519.PrivateKey:
		ed = *key
	case ed25519.PrivateKey:
		ed = key
	}
	if ed != nil {
		derived := ed25519.NewKeyFromSeed(ed.Seed())
		defer clearBytes(derived)
		if !bytes.Equal(derived, ed) {
			return nil, errKeyUnsupported
		}
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil || !supportedAgentPublicKey(signer.PublicKey()) {
		return nil, errKeyUnsupported
	}
	if public == nil || !bytes.Equal(signer.PublicKey().Marshal(), public.Marshal()) {
		return nil, errKeyMismatch
	}
	return signer, nil
}

// Bound RSA integers before x509 performs CRT validation/precomputation. PEM
// size alone would still allow disproportionate arithmetic on hostile material.
func boundedPrivateKeyDER(block *pem.Block) bool {
	data := block.Bytes
	if block.Type == "OPENSSH PRIVATE KEY" {
		return true
	} // upstream bounds wire integers
	if block.Type == "PRIVATE KEY" {
		var outer struct {
			Version    int
			Algorithm  asn1.RawValue
			PrivateKey []byte
		}
		if _, err := asn1.Unmarshal(data, &outer); err != nil {
			return false
		}
		data = outer.PrivateKey
		// Ed25519 PKCS#8 contains an OCTET STRING; RSA and EC contain a SEQUENCE.
	}
	return boundedASN1Integers(data, 0)
}

func boundedASN1Integers(data []byte, depth int) bool {
	if depth > 8 {
		return false
	}
	for len(data) > 0 {
		var value asn1.RawValue
		rest, err := asn1.Unmarshal(data, &value)
		if err != nil {
			return false
		}
		if value.Class == asn1.ClassUniversal && value.Tag == asn1.TagInteger && len(value.Bytes) > 1025 {
			return false
		}
		if value.IsCompound && !boundedASN1Integers(value.Bytes, depth+1) {
			return false
		}
		data = rest
	}
	return true
}
