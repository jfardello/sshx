package agent

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestRegisteredPrivateKeyFormats(t *testing.T) {
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keys := []any{ed, rsaKey}
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, key)
	}
	for _, key := range keys {
		signer, err := ssh.NewSignerFromKey(key)
		if err != nil {
			t.Fatal(err)
		}
		openssh, err := ssh.MarshalPrivateKey(key, "")
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		blocks := []*pem.Block{openssh, {Type: "PRIVATE KEY", Bytes: der}}
		switch k := key.(type) {
		case *rsa.PrivateKey:
			blocks = append(blocks, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
		case *ecdsa.PrivateKey:
			der, err := x509.MarshalECPrivateKey(k)
			if err != nil {
				t.Fatal(err)
			}
			blocks = append(blocks, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		}
		for _, block := range blocks {
			data := pem.EncodeToMemory(block)
			if _, err := parseRegisteredPrivateKey(data, signer.PublicKey()); err != nil {
				t.Fatalf("%T %s: %v", key, block.Type, err)
			}
		}
	}
	rec, raw := testAgentKey(t)
	pub, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(rec.PublicKey))
	encrypted, err := ssh.MarshalPrivateKeyWithPassphrase(ed, "", []byte("disposable"))
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{nil, []byte("not PEM"), append(append([]byte(nil), raw...), raw...), append(append([]byte(nil), raw...), []byte("metadata")...), pem.EncodeToMemory(encrypted), pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("invalid")}), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: []byte("invalid")}), []byte("-----BEGIN PRIVATE KEY-----\ninvalid"), bytes.Repeat([]byte("x"), maxKeyMaterialBytes+1)} {
		if _, err := parseRegisteredPrivateKey(data, pub); err == nil {
			t.Fatal("accepted unsupported key")
		}
	}
	if _, err := parseRegisteredPrivateKey(raw, nil); !errors.Is(err, errKeyMismatch) {
		t.Fatal(err)
	}
}

func TestPrivateKeyValidationRejectsInconsistentEd25519(t *testing.T) {
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	private[0] ^= 1 // retain the embedded public key but change the private seed
	block, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseRegisteredPrivateKey(pem.EncodeToMemory(block), public); err == nil {
		t.Fatal("accepted inconsistent Ed25519 key")
	}
}
