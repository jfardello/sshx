package agent_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/jfardello/sshx/internal/agent"
	"github.com/jfardello/sshx/internal/credential"
	"golang.org/x/crypto/ssh"
)

func TestValidateKeyMaterialExportedErrors(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	passphrase := []byte("external-test-secret")
	block, err := ssh.MarshalPrivateKeyWithPassphrase(private, "", passphrase)
	if err != nil {
		t.Fatal(err)
	}
	encrypted := pem.EncodeToMemory(block)
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPublic, err := ssh.NewPublicKey(other)
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, cancelDeadline := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelDeadline()

	categories := []error{
		agent.ErrKeyPassphrase, credential.ErrKeyUnsupported, credential.ErrKeyMismatch,
		credential.ErrTooLarge, context.Canceled, context.DeadlineExceeded,
	}
	for _, tc := range []struct {
		name       string
		ctx        context.Context
		data       []byte
		public     ssh.PublicKey
		passphrase []byte
		want       error
	}{
		{"valid", context.Background(), encrypted, public, passphrase, nil},
		{"missing passphrase", context.Background(), encrypted, public, nil, agent.ErrKeyPassphrase},
		{"wrong passphrase", context.Background(), encrypted, public, []byte("wrong-secret"), agent.ErrKeyPassphrase},
		{"unsupported", context.Background(), []byte("not a private key"), public, passphrase, credential.ErrKeyUnsupported},
		{"mismatch", context.Background(), encrypted, otherPublic, passphrase, credential.ErrKeyMismatch},
		{"missing public", context.Background(), encrypted, nil, passphrase, credential.ErrKeyMismatch},
		{"too large", context.Background(), make([]byte, 64*1024+1), public, passphrase, credential.ErrTooLarge},
		{"canceled", canceled, encrypted, public, nil, context.Canceled},
		{"deadline", expired, encrypted, public, nil, context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := agent.ValidateKeyMaterial(tc.ctx, tc.data, tc.public, tc.passphrase)
			if !errors.Is(err, tc.want) {
				t.Fatalf("validation error = %v, want %v", err, tc.want)
			}
			for _, category := range categories {
				if errors.Is(err, category) != (category == tc.want) {
					t.Fatalf("validation error %v classified incorrectly as %v", err, category)
				}
			}
		})
	}
}
