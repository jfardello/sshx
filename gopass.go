package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path"
	"strings"
)

const gopassNotFoundExitCode = 10

type gopassStore struct {
	stderr         io.Writer
	executeCommand func(args ...string) ([]byte, []byte, error)
}

func newGopassStore(stderr io.Writer) *gopassStore {
	return &gopassStore{stderr: stderr}
}

func (s *gopassStore) Search(query credentialQuery) ([]credentialRef, error) {
	args := []string{"list", "--flat"}
	if query.Collection != "" {
		args = append(args, "--", query.Collection)
	}

	output, stderr, err := s.execute(args...)
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
		credentials = append(credentials, credentialRef{
			Backend:    credentialBackendGopass,
			ID:         entry,
			Collection: query.Collection,
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

func (s *gopassStore) Secret(credential credentialRef) ([]byte, error) {
	if credential.Backend != credentialBackendGopass {
		return nil, fmt.Errorf("gopass cannot retrieve credential from backend %q", credential.Backend)
	}
	if credential.ID == "" {
		return nil, fmt.Errorf("gopass credential ID cannot be empty")
	}

	output, err := s.run("show", "--password", "--", credential.ID)
	if err != nil {
		return nil, err
	}
	password := append([]byte(nil), bytes.TrimRight(output, "\r\n")...)
	clearBytes(output)
	return password, nil
}

func (s *gopassStore) run(args ...string) ([]byte, error) {
	stdout, stderr, err := s.execute(args...)
	s.writeStderr(stderr)
	if err != nil {
		return nil, fmt.Errorf("gopass: %w", err)
	}
	return stdout, nil
}

func (s *gopassStore) execute(args ...string) ([]byte, []byte, error) {
	if s.executeCommand != nil {
		return s.executeCommand(args...)
	}

	cmd := exec.Command("gopass", args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, stderr.Bytes(), err
	}
	return stdout.Bytes(), stderr.Bytes(), nil
}

func (s *gopassStore) writeStderr(message []byte) {
	if s.stderr != nil && len(message) > 0 {
		_, _ = s.stderr.Write(message)
	}
}
