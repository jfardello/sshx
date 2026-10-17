package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jfardello/sshx/internal/agent"
	"github.com/jfardello/sshx/internal/credential"
	"github.com/jfardello/sshx/internal/fileupdate"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/sys/unix"
)

type registerTestStore struct {
	data              []byte
	readErr, closeErr error
	reads, closes     int
	ref               credential.Ref
	read              func(context.Context, credential.Ref)
	close             func()
}

func (s *registerTestStore) KeyMaterial(ctx context.Context, ref credential.Ref) ([]byte, error) {
	s.reads++
	s.ref = ref
	if s.read != nil {
		s.read(ctx, ref)
	}
	return s.data, s.readErr
}
func (s *registerTestStore) Close() error {
	s.closes++
	if s.close != nil {
		s.close()
	}
	return s.closeErr
}

type registerTestWriterFunc func([]byte) (int, error)

func (write registerTestWriterFunc) Write(data []byte) (int, error) {
	return write(data)
}

type registerTestPasswordStore struct{ t *testing.T }

func (s registerTestPasswordStore) Search(context.Context, credential.Query) ([]credential.Ref, error) {
	s.t.Fatal("registration searched password credentials")
	return nil, nil
}
func (s registerTestPasswordStore) Secret(context.Context, credential.Ref, credential.ReadOptions) ([]byte, error) {
	s.t.Fatal("registration read a password")
	return nil, nil
}
func (s registerTestPasswordStore) Close() error {
	s.t.Fatal("registration used the password store")
	return nil
}

type registerTestHarness struct {
	t              *testing.T
	dir, path      string
	deps           dependencies
	opens, prompts int
	backends       []credential.Backend
	store          *registerTestStore
}

func newRegisterTestHarness(t *testing.T, data []byte) *registerTestHarness {
	t.Helper()
	dir := agentCLIHome(t)
	t.Setenv("HOME", dir)
	path, err := agent.RegistryPath()
	if err != nil {
		t.Fatal(err)
	}
	h := &registerTestHarness{t: t, dir: dir, path: path, store: &registerTestStore{data: bytes.Clone(data)}}
	h.deps = dependencies{
		gopassStore: registerTestPasswordStore{t},
		loadConfig: func() (optionOverrides, error) {
			t.Fatal("registration loaded password/lifecycle configuration")
			return optionOverrides{}, nil
		},
		secretServiceStore: func(context.Context) (credentialStore, error) {
			t.Fatal("registration used password provider/fallback")
			return nil, nil
		},
		runProgram: func(string, []string, []byte) error {
			t.Fatal("registration launched password/remote program")
			return nil
		},
		openKeyStore: func(ctx context.Context, b credential.Backend) (credential.KeyStore, error) {
			h.opens++
			h.backends = append(h.backends, b)
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > credential.OperationTimeout || time.Until(deadline) <= 0 {
				t.Error("provider has no bounded operation deadline")
			}
			return h.store, nil
		},
		registrationPassphrase: func(context.Context) ([]byte, error) {
			h.prompts++
			t.Error("unexpected passphrase prompt")
			return nil, errRegistrationTTY
		},
	}
	return h
}
func (h *registerTestHarness) execute(ctx context.Context, args ...string) (string, string, error) {
	h.t.Helper()
	var out, diagnostic bytes.Buffer
	deps := h.deps
	deps.stdout = &out
	deps.stderr = &diagnostic
	cmd := newRootCommandWithDependencies(deps)
	cmd.SetArgs(append([]string{"agent", "register"}, args...))
	err := cmd.ExecuteContext(ctx)
	return out.String(), diagnostic.String(), err
}
func TestAgentRegisterErasesKeyBeforeSuccessOutput(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(fmt.Sprintf("encrypted=%t", encrypted), func(t *testing.T) {
			raw, public := registerTestKey(t, encrypted)
			h := newRegisterTestHarness(t, raw)
			// Retain the exact allocation returned by KeyMaterial, not a copy.
			ownedKey := h.store.data
			if len(ownedKey) == 0 || bytes.Equal(ownedKey, make([]byte, len(ownedKey))) {
				t.Fatal("fixture must start with nonzero private material")
			}
			var passphrase []byte
			if encrypted {
				passphrase = []byte("PASSPHRASE-MARKER")
				h.deps.registrationPassphrase = func(context.Context) ([]byte, error) {
					h.prompts++
					return passphrase, nil
				}
			}
			var output, diagnostic bytes.Buffer
			writes := 0
			deps := h.deps
			deps.stdout = registerTestWriterFunc(func(data []byte) (int, error) {
				writes++
				// RunE has not returned: deferred cleanup alone cannot satisfy this.
				registerTestZero(t, ownedKey)
				registerTestZero(t, passphrase)
				if h.store.reads != 1 || h.store.closes != 1 {
					t.Fatal("success output preceded provider cleanup")
				}
				return output.Write(data)
			})
			deps.stderr = &diagnostic
			cmd := newRootCommandWithDependencies(deps)
			cmd.SetArgs(append([]string{"agent", "register"}, registerTestArgs("key")...))
			if err := cmd.ExecuteContext(context.Background()); err != nil {
				t.Fatal(err)
			}
			want := fmt.Sprintf("Fingerprint: %s\nEnabled: false\n", ssh.FingerprintSHA256(public))
			if writes == 0 || output.String() != want || diagnostic.Len() != 0 {
				t.Fatalf("writes=%d stdout=%q stderr=%q", writes, output.String(), diagnostic.String())
			}
			wantPrompts := 0
			if encrypted {
				wantPrompts = 1
			}
			if h.opens != 1 || h.prompts != wantPrompts {
				t.Fatalf("opens=%d prompts=%d", h.opens, h.prompts)
			}
			h.document()
		})
	}
}

func registerTestArgs(id string) []string {
	return []string{id, "--backend", "gopass", "--reference", "exact/folder/key", "--unrestricted-local"}
}
func registerTestKey(t *testing.T, encrypted bool) ([]byte, ssh.PublicKey) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if encrypted {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(key, "PRIVATE-MARKER", []byte("PASSPHRASE-MARKER"))
	} else {
		block, err = ssh.MarshalPrivateKey(key, "PRIVATE-MARKER")
	}
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block), signer.PublicKey()
}
func registerTestZero(t *testing.T, b []byte) {
	t.Helper()
	if !bytes.Equal(b, make([]byte, len(b))) {
		t.Fatal("owned secret buffer not erased")
	}
}
func (h *registerTestHarness) absent() {
	h.t.Helper()
	for _, p := range []string{h.path, h.path + ".lock", filepath.Join(h.dir, "state"), filepath.Join(h.dir, "sshx")} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			h.t.Fatalf("unexpected side effect at %s: %v", p, err)
		}
	}
}
func (h *registerTestHarness) document() (int, []agent.RegistryRecord, []byte) {
	h.t.Helper()
	data, err := os.ReadFile(h.path)
	if err != nil {
		h.t.Fatal(err)
	}
	var doc struct {
		Version int                    `json:"version"`
		Keys    []agent.RegistryRecord `json:"keys"`
	}
	if err = json.Unmarshal(data, &doc); err != nil {
		h.t.Fatal(err)
	}
	if _, err = agent.LoadRegistry(); err != nil {
		h.t.Fatalf("published registry unusable: %v", err)
	}
	info, err := os.Stat(h.path)
	if err != nil || info.Mode().Perm() != 0600 {
		h.t.Fatal("registry permissions", err)
	}
	for _, marker := range []string{"PRIVATE-MARKER", "PASSPHRASE-MARKER", "PRIVATE KEY"} {
		if bytes.Contains(data, []byte(marker)) {
			h.t.Fatal("private data published")
		}
	}
	return doc.Version, doc.Keys, data
}

func TestAgentRegisterValidationBeforeSideEffects(t *testing.T) {
	base := registerTestArgs("key")
	cases := [][]string{
		{}, append(append([]string{}, base...), "extra"),
		{"bad/id", "--backend=gopass", "--reference=key", "--unrestricted-local"},
		{"key", "--reference=key", "--unrestricted-local"}, {"key", "--backend=gopass", "--unrestricted-local"},
		{"key", "--backend=auto", "--reference=key", "--unrestricted-local"},
		{"key", "--backend=unknown", "--reference=key", "--unrestricted-local"},
		{"key", "--backend=gopass", "--reference=key"},
		{"key", "--backend=secret-service", "--reference=stable", "--unrestricted-local"},
	}
	for _, ref := range []string{"", "/absolute", "../key", "a/../key", "a//key", "-option", "a/-option", "a\\key", "a\nkey"} {
		cases = append(cases, []string{"key", "--backend=gopass", "--reference=" + ref, "--unrestricted-local"})
	}
	for _, extra := range [][]string{
		{"--collection=login"}, {"--collection="}, {"--destination=user@host"}, {"--known-hosts=file"}, {"--port=22"},
		{"--comment=" + strings.Repeat("x", 129)}, {"--comment=line\nbreak"}, {"--verbose=false"}, {"--cache-ttl=0s"},
		{"--prompt-helper=/bin/true"}, {"--allow-forwarding=false"}, {"--allow-key-mutations=false"}, {"--state-file=/tmp/state"},
		{"--enable=invalid"}, {"--unknown"},
	} {
		cases = append(cases, append(append([]string{}, base...), extra...))
	}
	for _, extra := range [][]string{{"--reference=bad/id", "--collection=login"}, {"--reference=stable", "--collection="}, {"--reference=stable", "--collection=bad/id"}} {
		cases = append(cases, append([]string{"key", "--backend=secret-service", "--unrestricted-local"}, extra...))
	}
	for i, args := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			h := newRegisterTestHarness(t, nil)
			out, diag, err := h.execute(context.Background(), args...)
			if err == nil || out != "" || diag != "" || h.opens != 0 || h.prompts != 0 {
				t.Fatalf("args=%q out=%q stderr=%q err=%v opens=%d", args, out, diag, err, h.opens)
			}
			h.absent()
		})
	}
}

func TestAgentRegisterPublicMetadataAndExactProvider(t *testing.T) {
	raw, public := registerTestKey(t, false)
	for _, backend := range []credential.Backend{credential.BackendGopass, credential.BackendSecretService} {
		for _, enabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%t", backend, enabled), func(t *testing.T) {
				h := newRegisterTestHarness(t, raw)
				args := []string{"local-id", "--backend", string(backend), "--reference", "exact/folder/key", "--unrestricted-local", "--comment", "Public label"}
				ref := credential.Ref{Backend: backend, ID: "exact/folder/key"}
				if backend == credential.BackendSecretService {
					args = []string{"local-id", "--backend", string(backend), "--reference", "stable-id", "--collection", "login", "--unrestricted-local", "--comment", "Public label"}
					ref.ID = "stable-id"
					ref.Collection = "login"
				}
				if enabled {
					args = append(args, "--enable", "--confirm")
				}
				out, diag, err := h.execute(context.Background(), args...)
				want := fmt.Sprintf("Fingerprint: %s\nEnabled: %t\n", ssh.FingerprintSHA256(public), enabled)
				if err != nil || out != want || diag != "" {
					t.Fatalf("out=%q stderr=%q err=%v", out, diag, err)
				}
				version, records, _ := h.document()
				expected := agent.RegistryRecord{ID: "local-id", Backend: backend, Reference: ref.ID, Collection: ref.Collection, Comment: "Public label", Enabled: enabled, Confirm: enabled, Policy: "unrestricted-local", PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public)))}
				if version != 2 || !reflect.DeepEqual(records, []agent.RegistryRecord{expected}) {
					t.Fatalf("version=%d records=%+v", version, records)
				}
				if h.opens != 1 || h.store.reads != 1 || h.store.closes != 1 || !reflect.DeepEqual(h.store.ref, ref) || h.prompts != 0 || !reflect.DeepEqual(h.backends, []credential.Backend{backend}) {
					t.Fatal("provider was not exact, single-read and closed")
				}
				registerTestZero(t, h.store.data)
			})
		}
	}
}

func TestAgentRegisterProviderFailuresSanitizedAndErased(t *testing.T) {
	raw, _ := registerTestKey(t, false)
	categories := []error{errors.New("PROVIDER-SECRET"), credential.ErrLocked, credential.ErrProviderChanged, credential.ErrReference, credential.ErrTooLarge, credential.ErrKeyUnsupported, credential.ErrKeyMismatch, context.Canceled, context.DeadlineExceeded}
	for _, stage := range []string{"open", "read", "close"} {
		for i, category := range categories {
			t.Run(fmt.Sprintf("%s/%d", stage, i), func(t *testing.T) {
				h := newRegisterTestHarness(t, raw)
				failure := fmt.Errorf("PROVIDER-SECRET exact/folder/key: %w", category)
				switch stage {
				case "open":
					h.deps.openKeyStore = func(context.Context, credential.Backend) (credential.KeyStore, error) {
						h.opens++
						return h.store, failure
					}
				case "read":
					h.store.readErr = failure
				case "close":
					h.store.closeErr = failure
				}
				out, diag, err := h.execute(context.Background(), registerTestArgs("key")...)
				want := category
				if i == 0 {
					want = credential.ErrRead
				}
				if !errors.Is(err, want) || out != "" || diag != "" || strings.Contains(err.Error(), "PROVIDER-SECRET") || strings.Contains(err.Error(), "exact/folder/key") {
					t.Fatalf("unsanitized/wrong result: %q %q %v", out, diag, err)
				}
				if category == credential.ErrLocked && !strings.Contains(err.Error(), "unlock it separately") {
					t.Fatal("locked provider lacks actionable guidance")
				}
				if h.opens != 1 || h.store.closes != 1 || h.prompts != 0 {
					t.Fatal("fallback, prompt, or missing close")
				}
				if stage != "open" {
					registerTestZero(t, h.store.data)
				}
				h.absent()
			})
		}
	}
	t.Run("nil-store", func(t *testing.T) {
		h := newRegisterTestHarness(t, nil)
		h.deps.openKeyStore = func(context.Context, credential.Backend) (credential.KeyStore, error) { return nil, nil }
		_, _, err := h.execute(context.Background(), registerTestArgs("key")...)
		if !errors.Is(err, credential.ErrRead) {
			t.Fatal(err)
		}
		h.absent()
	})
}

func TestAgentRegisterEncryptedPromptAndCleanup(t *testing.T) {
	raw, public := registerTestKey(t, true)
	for _, tc := range []struct {
		name, pass      string
		promptErr, want error
	}{
		{"success", "PASSPHRASE-MARKER", nil, nil}, {"wrong", "WRONG-MARKER", nil, agent.ErrKeyPassphrase},
		{"empty", "", nil, agent.ErrKeyPassphrase}, {"missing-tty", "PASSPHRASE-MARKER", errRegistrationTTY, errRegistrationTTY},
		{"read-failure", "PASSPHRASE-MARKER", errRegistrationPassphrase, errRegistrationPassphrase},
		{"unknown", "PASSPHRASE-MARKER", errors.New("PROMPT-SECRET"), agent.ErrKeyPassphrase},
		{"cancel", "PASSPHRASE-MARKER", context.Canceled, context.Canceled},
		{"deadline", "PASSPHRASE-MARKER", context.DeadlineExceeded, context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRegisterTestHarness(t, raw)
			owned := []byte(tc.pass)
			h.deps.registrationPassphrase = func(ctx context.Context) ([]byte, error) {
				h.prompts++
				if h.store.reads != 1 || h.store.closes != 1 {
					t.Error("prompt ran before provider close")
				}
				if _, ok := ctx.Deadline(); ok {
					t.Error("provider operation deadline leaked into terminal interaction")
				}
				if _, err := os.Lstat(h.path + ".lock"); !errors.Is(err, os.ErrNotExist) {
					t.Error("registry lock created before prompt")
				}
				h.absent()
				return owned, tc.promptErr
			}
			out, diag, err := h.execute(context.Background(), registerTestArgs("key")...)
			if !errors.Is(err, tc.want) || diag != "" {
				t.Fatalf("out=%q err=%v want=%v", out, err, tc.want)
			}
			if tc.want == nil {
				if out != fmt.Sprintf("Fingerprint: %s\nEnabled: false\n", ssh.FingerprintSHA256(public)) {
					t.Fatal(out)
				}
				h.document()
			} else {
				if out != "" || strings.Contains(err.Error(), "PROMPT-SECRET") {
					t.Fatal("secret output", out, err)
				}
				h.absent()
			}
			if h.prompts != 1 || h.store.closes != 1 {
				t.Fatal("prompt retry or missing close")
			}
			registerTestZero(t, owned)
			registerTestZero(t, h.store.data)
		})
	}
}

func TestAgentRegisterRejectsPrivateMaterialBeforePromptOrLock(t *testing.T) {
	encrypted, _ := registerTestKey(t, true)
	block, _ := pem.Decode(encrypted)
	var envelope struct {
		Cipher, KDF     string
		Options         []byte
		Count           uint32
		Public, Private []byte
	}
	if err := ssh.Unmarshal(block.Bytes[len("openssh-key-v1\x00"):], &envelope); err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint32(envelope.Options[len(envelope.Options)-4:], ^uint32(0))
	excessive := pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: append([]byte("openssh-key-v1\x00"), ssh.Marshal(envelope)...)})
	for i, data := range [][]byte{[]byte("PRIVATE-MARKER invalid"), append(bytes.Clone(encrypted), encrypted...), excessive} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			h := newRegisterTestHarness(t, data)
			h.store.close = func() {
				if _, err := os.Lstat(h.path + ".lock"); !errors.Is(err, os.ErrNotExist) {
					t.Error("locked registry before private validation")
				}
			}
			out, diag, err := h.execute(context.Background(), registerTestArgs("key")...)
			if !errors.Is(err, credential.ErrKeyUnsupported) || out != "" || diag != "" || h.prompts != 0 || h.store.closes != 1 {
				t.Fatal(out, diag, err)
			}
			registerTestZero(t, h.store.data)
			h.absent()
		})
	}
}

func TestAgentRegisterCancellation(t *testing.T) {
	raw, _ := registerTestKey(t, true)
	for _, stage := range []string{"before-open", "read", "close", "prompt"} {
		t.Run(stage, func(t *testing.T) {
			h := newRegisterTestHarness(t, raw)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			owned := []byte("PASSPHRASE-MARKER")
			switch stage {
			case "before-open":
				cancel()
			case "read":
				h.store.read = func(got context.Context, _ credential.Ref) { cancel(); <-got.Done() }
			case "close":
				h.store.close = cancel
			case "prompt":
				h.deps.registrationPassphrase = func(got context.Context) ([]byte, error) { h.prompts++; cancel(); <-got.Done(); return owned, nil }
			}
			out, diag, err := h.execute(ctx, registerTestArgs("key")...)
			if !errors.Is(err, context.Canceled) || out != "" || diag != "" {
				t.Fatal(out, diag, err)
			}
			if stage == "before-open" {
				if h.opens != 0 {
					t.Fatal("opened canceled provider")
				}
			} else {
				registerTestZero(t, h.store.data)
				if h.store.closes != 1 {
					t.Fatal("cancellation skipped close")
				}
			}
			if stage == "prompt" {
				registerTestZero(t, owned)
			} else if h.prompts != 0 {
				t.Fatal("canceled registration prompted")
			}
			h.absent()
		})
	}
}

func TestAgentRegisterProviderDeadline(t *testing.T) {
	raw, _ := registerTestKey(t, false)
	for _, stage := range []string{"open", "read"} {
		t.Run(stage, func(t *testing.T) {
			h := newRegisterTestHarness(t, raw)
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			if stage == "open" {
				h.deps.openKeyStore = func(got context.Context, _ credential.Backend) (credential.KeyStore, error) {
					h.opens++
					<-got.Done()
					return h.store, fmt.Errorf("PROVIDER-SECRET: %w", got.Err())
				}
			} else {
				h.store.read = func(got context.Context, _ credential.Ref) { <-got.Done() }
			}
			out, diag, err := h.execute(ctx, registerTestArgs("key")...)
			if !errors.Is(err, context.DeadlineExceeded) || out != "" || diag != "" || h.store.closes != 1 || h.prompts != 0 {
				t.Fatal("provider deadline not propagated or cleanup skipped", out, diag, err)
			}
			if stage == "read" {
				registerTestZero(t, h.store.data)
			}
			h.absent()
		})
	}
}

func TestAgentRegisterProviderAndPromptBeforeRegistryLock(t *testing.T) {
	raw, _ := registerTestKey(t, true)
	h := newRegisterTestHarness(t, raw)
	if err := os.MkdirAll(filepath.Dir(h.path), 0700); err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(h.path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	owned := []byte("PASSPHRASE-MARKER")
	h.deps.registrationPassphrase = func(context.Context) ([]byte, error) {
		h.prompts++
		if h.store.closes != 1 {
			t.Error("provider still open")
		}
		return owned, nil
	}
	out, diag, err := h.execute(context.Background(), registerTestArgs("key")...)
	if !errors.Is(err, fileupdate.ErrBusy) || out != "" || diag != "" || h.store.closes != 1 || h.prompts != 1 {
		t.Fatal("lock attempted before provider/prompt", out, diag, err)
	}
	registerTestZero(t, owned)
	registerTestZero(t, h.store.data)
	if _, err = os.Stat(h.path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("busy registry published")
	}
}

func TestAgentRegisterReplaceAliasesNoopAndStatePreservation(t *testing.T) {
	raw, _ := registerTestKey(t, false)
	other, _ := registerTestKey(t, false)
	h := newRegisterTestHarness(t, raw)
	state, err := agent.DefaultMutationStatePath()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Dir(state), 0700); err != nil {
		t.Fatal(err)
	}
	stateData := []byte("existing lock/suppression state must remain byte-for-byte")
	if err = os.WriteFile(state, stateData, 0600); err != nil {
		t.Fatal(err)
	}
	run := func(data []byte, args []string, want error) {
		t.Helper()
		h.store.data = bytes.Clone(data)
		out, diag, err := h.execute(context.Background(), args...)
		if !errors.Is(err, want) || diag != "" || (want != nil && out != "") {
			t.Fatalf("args=%v out=%q err=%v want=%v", args, out, err, want)
		}
		registerTestZero(t, h.store.data)
		got, err := os.ReadFile(state)
		if err != nil || !bytes.Equal(got, stateData) {
			t.Fatal("registration modified mutation state", err)
		}
	}
	run(raw, registerTestArgs("primary"), nil)
	run(raw, registerTestArgs("alias"), nil)
	_, records, before := h.document()
	if len(records) != 2 {
		t.Fatal("alias dropped")
	}
	info, _ := os.Stat(h.path)
	for _, replace := range []bool{false, true} {
		args := registerTestArgs("primary")
		if replace {
			args = append(args, "--replace")
		}
		run(raw, args, nil)
		_, _, after := h.document()
		now, _ := os.Stat(h.path)
		if !bytes.Equal(before, after) || !os.SameFile(info, now) || !info.ModTime().Equal(now.ModTime()) {
			t.Fatal("identical record rewrote registry")
		}
	}
	run(other, registerTestArgs("primary"), agent.ErrRegistryReplaceRequired)
	_, _, after := h.document()
	if !bytes.Equal(before, after) {
		t.Fatal("failed replacement changed registry")
	}
	run(raw, append(registerTestArgs("primary"), "--enable", "--replace"), agent.ErrRegistryInvalid)
	_, _, after = h.document()
	if !bytes.Equal(before, after) {
		t.Fatal("conflicting alias partially published")
	}
	run(other, append(registerTestArgs("primary"), "--enable", "--confirm", "--replace"), nil)
	_, updated, _ := h.document()
	if len(updated) != 2 || !updated[0].Enabled || !updated[0].Confirm || !reflect.DeepEqual(updated[1], records[1]) {
		t.Fatal("replacement changed unrelated alias", updated)
	}
}

func TestAgentRegisterKnownHostsPins(t *testing.T) {
	raw, _ := registerTestKey(t, false)
	_, host1 := registerTestKey(t, false)
	_, host2 := registerTestKey(t, false)
	for _, mode := range []string{"default", "explicit", "ipv6-port-hashed"} {
		t.Run(mode, func(t *testing.T) {
			h := newRegisterTestHarness(t, raw)
			path := filepath.Join(h.dir, ".ssh", "known_hosts")
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			host, user, port := "never-resolves.invalid", "alice", 22
			destinations := []string{user + "@" + host, "bob@" + host}
			label := host
			if mode == "ipv6-port-hashed" {
				host = "2001:db8::40"
				port = 2222
				label = knownhosts.HashHostname("[" + host + "]:2222")
				destinations = []string{"alice@[" + host + "]", "bob@[" + host + "]"}
			}
			lines := label + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(host1))) + "\n" + label + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(host2))) + "\n" + label + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(host1))) + "\n"
			if err := os.WriteFile(path, []byte(lines), 0600); err != nil {
				t.Fatal(err)
			}
			args := []string{"key", "--backend=gopass", "--reference=exact/key"}
			for _, destination := range destinations {
				args = append(args, "--destination", destination)
			}
			if mode != "default" {
				args = append(args, "--known-hosts", path)
			}
			if port != 22 {
				args = append(args, "--port", fmt.Sprint(port))
			}
			h.store.read = func(context.Context, credential.Ref) {
				if err := os.Remove(path); err != nil {
					t.Error(err)
				}
			}
			out, diag, err := h.execute(context.Background(), args...)
			if err != nil || out == "" || diag != "" {
				t.Fatal(out, diag, err)
			}
			_, records, _ := h.document()
			policy := records[0].Destinations
			if records[0].Policy != "destination-constrained" || policy == nil || policy.Version != 1 || len(policy.Edges) != 2 {
				t.Fatal("bad policy", records)
			}
			pins := []string{strings.TrimSpace(string(ssh.MarshalAuthorizedKey(host1))), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(host2)))}
			for i, edge := range policy.Edges {
				user := "alice"
				if i == 1 {
					user = "bob"
				}
				if edge.To.Hostname != host || edge.To.Username != user || !reflect.DeepEqual(edge.To.HostKeys, pins) {
					t.Fatalf("bad edge: %+v", edge)
				}
			}
			if h.opens != 1 || h.prompts != 0 {
				t.Fatal("unexpected provider/prompt")
			}
			registerTestZero(t, h.store.data)
		})
	}
}

func TestAgentRegisterInvalidKnownHostsBeforeProvider(t *testing.T) {
	_, host := registerTestKey(t, false)
	pin := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(host)))
	for _, tc := range []struct{ name, contents, destination, port string }{
		{"missing", "", "alice@host.invalid", "22"}, {"malformed", "secret garbage", "alice@host.invalid", "22"},
		{"unmatched", "other.invalid " + pin, "alice@host.invalid", "22"},
		{"revoked", "@revoked host.invalid " + pin, "alice@host.invalid", "22"},
		{"ca-only", "@cert-authority host.invalid " + pin, "alice@host.invalid", "22"},
		{"no-user", "host.invalid " + pin, "host.invalid", "22"}, {"bad-port", "host.invalid " + pin, "alice@host.invalid", "0"},
		{"high-port", "host.invalid " + pin, "alice@host.invalid", "65536"},
		{"embedded-port", "host.invalid " + pin, "alice@host.invalid:2222", "22"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRegisterTestHarness(t, nil)
			path := filepath.Join(h.dir, "known_hosts")
			if tc.name != "missing" {
				if err := os.WriteFile(path, []byte(tc.contents), 0600); err != nil {
					t.Fatal(err)
				}
			}
			out, diag, err := h.execute(context.Background(), "key", "--backend=gopass", "--reference=key", "--destination", tc.destination, "--known-hosts", path, "--port", tc.port)
			if err == nil || out != "" || diag != "" || h.opens != 0 || h.prompts != 0 {
				t.Fatal(out, diag, err)
			}
			h.absent()
		})
	}
	t.Run("default-does-not-use-alternate-file", func(t *testing.T) {
		h := newRegisterTestHarness(t, nil)
		if err := os.WriteFile(filepath.Join(h.dir, "known_hosts"), []byte("host.invalid "+pin), 0600); err != nil {
			t.Fatal(err)
		}
		out, _, err := h.execute(context.Background(), "key", "--backend=gopass", "--reference=key", "--destination=alice@host.invalid")
		if err == nil || out != "" || h.opens != 0 {
			t.Fatal("used alternate known-hosts source", out, err)
		}
		h.absent()
	})
}

func TestAgentRegisterRealAgentSigning(t *testing.T) {
	raw, public := registerTestKey(t, false)
	h := newRegisterTestHarness(t, raw)
	args := append(registerTestArgs("key"), "--comment=Registered identity")
	if _, _, err := h.execute(context.Background(), args...); err != nil {
		t.Fatal(err)
	}
	registry, err := agent.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(h.dir, "registered.sock")
	store := &registerTestStore{data: bytes.Clone(raw)}
	server, err := agent.NewServer(socket, registry, func(ctx context.Context, b credential.Backend) (credential.KeyStore, error) {
		if b != credential.BackendGopass {
			t.Error("wrong backend")
		}
		return store, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	defer func() {
		cancel()
		if err := server.Close(); err != nil {
			t.Error(err)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("agent shutdown hung")
		}
	}()
	conn, err := net.DialTimeout("unix", socket, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	client := sshagent.NewClient(conn)
	disabled, err := client.List()
	if err != nil || len(disabled) != 0 {
		t.Fatal("disabled registration advertised", disabled, err)
	}
	if _, err := client.Sign(public, []byte("disabled signing")); err == nil {
		t.Fatal("disabled registered key signed")
	}
	h.store.data = bytes.Clone(raw)
	if _, _, err := h.execute(context.Background(), append(args, "--enable", "--replace")...); err != nil {
		t.Fatal(err)
	}
	identities, err := client.List()
	if err != nil || len(identities) != 1 || !bytes.Equal(identities[0].Blob, public.Marshal()) || identities[0].Comment != "Registered identity" {
		t.Fatal("registered identity not advertised", identities, err)
	}
	message := []byte("registration integration signature")
	signature, err := client.Sign(public, message)
	if err != nil {
		t.Fatal(err)
	}
	if err = public.Verify(message, signature); err != nil {
		t.Fatal(err)
	}
	// Close joins server workers before inspecting the fake provider under -race.
	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err = server.Close(); err != nil {
		t.Fatal(err)
	}
	if store.reads != 1 || store.closes != 1 || !reflect.DeepEqual(store.ref, credential.Ref{Backend: credential.BackendGopass, ID: "exact/folder/key"}) {
		t.Fatal("agent did not use exact registered reference", store.ref)
	}
	registerTestZero(t, store.data)
}

func TestAgentRegisterSignalCancellation(t *testing.T) {
	if os.Getenv("SSHX_REGISTER_SIGNAL_CHILD") == "1" {
		h := newRegisterTestHarness(t, []byte("owned secret"))
		h.store.read = func(ctx context.Context, _ credential.Ref) {
			if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			select {
			case <-ctx.Done():
			case <-time.After(2 * time.Second):
				t.Fatal("parent registration signal context did not cancel provider")
			}
		}
		out, diag, err := h.execute(context.Background(), registerTestArgs("key")...)
		if !errors.Is(err, context.Canceled) || out != "" || diag != "" || h.store.closes != 1 {
			t.Fatal(out, diag, err)
		}
		registerTestZero(t, h.store.data)
		h.absent()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAgentRegisterSignalCancellation$")
	cmd.Env = append(os.Environ(), "SSHX_REGISTER_SIGNAL_CHILD=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("signal subprocess: %v\n%s", err, output)
	}
}
