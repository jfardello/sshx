package gopass

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"strings"
	"syscall"
	"time"
)

const gopassNotFoundExitCode = 10

type gopassStore struct {
	stderr         io.Writer
	executeCommand func(args ...string) ([]byte, []byte, error)
}

func newGopassStore(stderr io.Writer) *gopassStore {
	return &gopassStore{stderr: stderr}
}

func (s *gopassStore) Search(ctx context.Context, query credentialQuery) ([]credentialRef, error) {
	if len(query.Attributes) > 0 {
		return nil, errCredentialReference
	}
	args := []string{"list", "--flat"}
	if query.Collection != "" {
		args = append(args, "--", query.Collection)
	}

	var output, stderr []byte
	var err error
	if query.AllowInteraction {
		output, stderr, err = s.execute(ctx, args...)
	} else {
		output, err = s.noninteractive(ctx, args...)
	}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == gopassNotFoundExitCode {
			return nil, nil
		}
		s.writeStderr(stderr)
		return nil, fmt.Errorf("gopass: %w", err)
	}
	s.writeStderr(stderr)

	value := strings.TrimRight(string(output), "\r\n")
	if value == "" {
		return nil, nil
	}

	entries := strings.Split(value, "\n")
	for i := range entries {
		entries[i] = strings.TrimSuffix(entries[i], "\r")
	}
	paths := filterEntries(entries, query.Collection, query.Text)
	credentials := make([]credentialRef, 0, len(paths))
	for _, entry := range paths {
		collection := query.Collection
		if collection == "" {
			collection = path.Dir(entry)
			if collection == "." {
				collection = ""
			}
		}
		credentials = append(credentials, credentialRef{
			Backend:    credentialBackendGopass,
			ID:         entry,
			Collection: collection,
			Label:      path.Base(entry),
			Target:     query.Text,
		})
	}
	return credentials, nil
}

func filterEntries(entries []string, prefix, query string) []string {
	query = strings.Trim(query, "/")
	exact := make([]string, 0)
	partial := make([]string, 0)
	lowerQuery := strings.ToLower(query)

	for _, entry := range entries {
		entry = strings.TrimSuffix(entry, "\r")
		if entry == "" {
			continue
		}

		relative := entry
		if prefix != "" {
			if entry != prefix && !strings.HasPrefix(entry, prefix+"/") {
				continue
			}
			relative = strings.TrimPrefix(entry, prefix+"/")
		}

		if entry == query || relative == query || path.Base(entry) == query {
			exact = appendUnique(exact, entry)
			continue
		}
		if strings.Contains(strings.ToLower(relative), lowerQuery) {
			partial = appendUnique(partial, entry)
		}
	}

	if len(exact) > 0 {
		return exact
	}
	return partial
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func (s *gopassStore) Secret(ctx context.Context, credential credentialRef, options credentialReadOptions) ([]byte, error) {
	if credential.Backend != credentialBackendGopass {
		return nil, fmt.Errorf("gopass cannot retrieve credential from backend %q", credential.Backend)
	}
	if credential.ID == "" {
		return nil, fmt.Errorf("gopass credential ID cannot be empty")
	}

	var output []byte
	var err error
	if options.AllowInteraction {
		output, err = s.run(ctx, "show", "--password", "--", credential.ID)
	} else {
		if !validAgentGopassPath(credential.ID) {
			return nil, errCredentialReference
		}
		output, err = s.noninteractive(ctx, "show", "--password", "--nofuzzysearch", "--nosync", "--alsoclip=false", "--", credential.ID)
	}
	if err != nil {
		return nil, err
	}
	password := append([]byte(nil), bytes.TrimRight(output, "\r\n")...)
	clearBytes(output)
	return password, nil
}

func (s *gopassStore) Close() error {
	return nil
}

func (s *gopassStore) run(ctx context.Context, args ...string) ([]byte, error) {
	stdout, stderr, err := s.execute(ctx, args...)
	s.writeStderr(stderr)
	if err != nil {
		return nil, fmt.Errorf("gopass: %w", err)
	}
	return stdout, nil
}

func (s *gopassStore) execute(ctx context.Context, args ...string) ([]byte, []byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if s.executeCommand != nil {
		return s.executeCommand(args...)
	}

	return runGopassCommand(ctx, false, args...)

}

func (s *gopassStore) writeStderr(message []byte) {
	if s.stderr != nil && len(message) > 0 {
		_, _ = s.stderr.Write(message)
	}
}

const maxKeyMaterialBytes = 64 * 1024
const maxCredentialOutputBytes = 1024 * 1024

type boundedCredentialBuffer struct {
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

func (b *boundedCredentialBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		b.exceeded = true
		return 0, errCredentialTooLarge
	}
	return b.buffer.Write(p)
}

// Kill the process group on cancellation, including helpers holding output pipes.
func runGopassCommand(ctx context.Context, keyRead bool, args ...string) ([]byte, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, credentialOperationTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "gopass", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if err == syscall.ESRCH {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = time.Second
	if keyRead {
		cmd.Env = gopassKeyEnvironment(os.Environ())
	}

	limit := maxCredentialOutputBytes
	if keyRead {
		limit = maxKeyMaterialBytes
	}
	stdout := &boundedCredentialBuffer{limit: limit}
	stderr := &boundedCredentialBuffer{limit: 64 * 1024}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	if stdout.exceeded || stderr.exceeded {
		err = errCredentialTooLarge
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		clearBytes(stdout.Bytes())
		return nil, stderr.Bytes(), err
	}
	return stdout.Bytes(), stderr.Bytes(), nil
}

func (s *gopassStore) KeyMaterial(ctx context.Context, ref credentialRef) ([]byte, error) {
	if ref.Backend != credentialBackendGopass || !validAgentGopassPath(ref.ID) {
		return nil, errCredentialReference
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	args := []string{"show", "--noparsing", "--unsafe", "--nofuzzysearch", "--nosync", "--alsoclip=false", "--", ref.ID}
	return s.noninteractive(ctx, args...)

}

// Keep the selected store locations, but suppress helper diagnostics, hooks,
// clipboard use, reference following, and all passphrase interaction.
func gopassKeyEnvironment(inherited []string) []string {
	env := []string{}
	for _, value := range inherited {
		name, _, _ := strings.Cut(value, "=")
		if strings.HasPrefix(name, "GOPASS_") && name != "GOPASS_CONFIG" && name != "GOPASS_HOMEDIR" {
			continue
		}
		if name == "PASSWORD_STORE_GPG_OPTS" || name == "GPG_TTY" || name == "SSH_AUTH_SOCK" || name == "SSH_AGENT_PID" || name == "LISTEN_FDS" || name == "LISTEN_PID" || name == "LISTEN_FDNAMES" {
			continue
		}
		env = append(env, value)
	}
	env = append(env, "GOPASS_GPG_OPTS=--batch --no-tty --pinentry-mode error", "GOPASS_HOOK=1", "GOPASS_AGE_STDIN_PASSPHRASE=1", "GOPASS_CONFIG_NO_MIGRATE=1")
	keys := []string{"core.follow-references", "core.autosync", "core.notifications", "show.autoclip", "age.usekeychain", "age.agent-enabled", "age.sshkeys"}
	env = append(env, fmt.Sprintf("GOPASS_CONFIG_COUNT=%d", len(keys)))
	for i, key := range keys {
		env = append(env, fmt.Sprintf("GOPASS_CONFIG_KEY_%d=%s", i, key), fmt.Sprintf("GOPASS_CONFIG_VALUE_%d=false", i))
	}
	return env
}

func (b *boundedCredentialBuffer) Len() int      { return b.buffer.Len() }
func (b *boundedCredentialBuffer) Bytes() []byte { return b.buffer.Bytes() }

func (s *gopassStore) noninteractive(ctx context.Context, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var data, stderr []byte
	var err error
	if s.executeCommand != nil {
		data, stderr, err = s.executeCommand(args...)
	} else {
		data, stderr, err = runGopassCommand(ctx, true, args...)
	}
	clearBytes(stderr)
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if len(data) > maxKeyMaterialBytes {
		err = errCredentialTooLarge
	}
	if err != nil {
		clearBytes(data)
		return nil, sanitizeKeyReadError(ctx, err)
	}
	return data, nil
}
