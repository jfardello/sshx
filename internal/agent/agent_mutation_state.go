package agent

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"

	"golang.org/x/sys/unix"
)

var errAgentState = errors.New("invalid, untrusted or busy agent mutation state")

type agentLockVerifier struct {
	Salt        []byte `json:"salt"`
	Hash        []byte `json:"hash"`
	Failures    uint32 `json:"failures"`
	NextAttempt int64  `json:"next_attempt"`
}
type agentMutationDocument struct {
	Version     int                `json:"version"`
	Suppressed  []string           `json:"suppressed"`
	SuppressAll bool               `json:"suppress_all"`
	Lock        *agentLockVerifier `json:"lock,omitempty"`
}
type agentStateFile struct {
	directory, lock int
	name            string
}

func DefaultMutationStatePath() (string, error) {
	base := os.Getenv("XDG_STATE_HOME")
	if !filepath.IsAbs(base) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", errAgentState
		}
		base = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(base, "sshx", "agent-state.json"), nil
}

func openAgentState(path string, create bool) (*agentStateFile, agentMutationDocument, error) {
	empty := agentMutationDocument{Version: 1, Suppressed: []string{}}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, empty, errAgentState
	}
	if !create {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			return nil, empty, nil
		}
	}
	if create {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, empty, errAgentState
		}
	}
	directory, err := openAgentPrivateDirectory(path)
	if err != nil {
		return nil, empty, errAgentState
	}
	state := &agentStateFile{directory: directory, lock: -1, name: filepath.Base(path)}
	success := false
	defer func() {
		if !success {
			state.close()
		}
	}()
	lock, err := unix.Openat(directory, state.name+".lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, empty, errAgentState
	}
	state.lock = lock
	if !trustedAgentStateFD(lock) || unix.Flock(lock, unix.LOCK_EX|unix.LOCK_NB) != nil {
		return nil, empty, errAgentState
	}
	fd, err := unix.Openat(directory, state.name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		if err = state.save(empty); err != nil {
			return nil, empty, err
		}
		success = true
		return state, empty, nil
	}
	if err != nil {
		return nil, empty, errAgentState
	}
	file := os.NewFile(uintptr(fd), "agent mutation state")
	defer file.Close()
	if !trustedAgentStateFD(fd) {
		return nil, empty, errAgentState
	}
	data, err := io.ReadAll(io.LimitReader(file, maxAgentRegistryBytes+1))
	defer clearBytes(data)
	if err != nil || len(data) > maxAgentRegistryBytes {
		return nil, empty, errAgentState
	}
	var document agentMutationDocument
	if json.Unmarshal(data, &document) != nil || document.Version != 1 || len(document.Suppressed) > maxAgentIdentities {
		return nil, empty, errAgentState
	}
	canonical, _ := json.Marshal(document)
	if !bytes.Equal(data, canonical) {
		return nil, empty, errAgentState
	} // Reject duplicate, unknown and noncanonical state fields.
	seen := map[string]bool{}
	for _, encoded := range document.Suppressed {
		blob, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || seen[encoded] {
			return nil, empty, errAgentState
		}
		if _, err := parseAgentPolicyHost(blob); err != nil {
			return nil, empty, errAgentState
		}
		seen[encoded] = true
	}
	if v := document.Lock; v != nil && (len(v.Salt) != 32 || len(v.Hash) != 32 || v.Failures > 6 || v.NextAttempt < 0) {
		return nil, empty, errAgentState
	}
	success = true
	return state, document, nil
}
func trustedAgentStateFD(fd int) bool {
	var st unix.Stat_t
	return unix.Fstat(fd, &st) == nil && st.Uid == uint32(os.Geteuid()) && st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&0077 == 0 && st.Nlink == 1 && st.Size <= maxAgentRegistryBytes
}
func (f *agentStateFile) save(document agentMutationDocument) error {
	data, err := json.Marshal(document)
	if err != nil || len(data) > maxAgentRegistryBytes {
		return errAgentState
	}
	defer clearBytes(data)
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return errAgentState
	}
	temp := ".agent-state-" + hex.EncodeToString(nonce[:])
	fd, err := unix.Openat(f.directory, temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return errAgentState
	}
	defer unix.Unlinkat(f.directory, temp, 0)
	file := os.NewFile(uintptr(fd), "agent state update")
	if err := writeAgentReply(file, data); err != nil {
		file.Close()
		return errAgentState
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return errAgentState
	}
	if err := file.Close(); err != nil {
		return errAgentState
	}
	if unix.Renameat(f.directory, temp, f.directory, f.name) != nil || unix.Fsync(f.directory) != nil {
		return errAgentState
	}
	return nil
}
func (f *agentStateFile) close() {
	if f == nil {
		return
	}
	if f.lock >= 0 {
		_ = unix.Close(f.lock)
	}
	_ = unix.Close(f.directory)
}
func ResetMutationState(path string) error {
	state, _, err := openAgentState(path, true)
	if err != nil {
		return err
	}
	defer state.close()
	return state.save(agentMutationDocument{Version: 1, Suppressed: []string{}})
}
func mutationDocument(suppressed map[string]bool, all bool, lock *agentLockVerifier) agentMutationDocument {
	keys := make([]string, 0, len(suppressed))
	for blob := range suppressed {
		keys = append(keys, base64.StdEncoding.EncodeToString([]byte(blob)))
	}
	sort.Strings(keys)
	return agentMutationDocument{Version: 1, Suppressed: keys, SuppressAll: all, Lock: lock}
}
