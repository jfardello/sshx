package pty

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
)

// Exercise the installed OpenSSH password client against a disposable local
// endpoint. No real hosts, accounts, credentials, or SSH configuration are used.
func TestRunOpenSSHPasswordBinaryTransfer(t *testing.T) {
	client, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("OpenSSH client unavailable")
	}
	t.Setenv("SSH_ASKPASS_REQUIRE", "never")
	payload := make([]byte, 128*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "foo", Mode: 0600, Size: int64(len(payload))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, command        string
		files, terminalInput bool
	}{
		{name: "download", command: "download"},
		{name: "upload", command: "upload"},
		{name: "download-files", command: "download", files: true},
		{name: "download-terminal-input", command: "download", terminalInput: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command := tc.command
			_, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			signer, err := ssh.NewSignerFromKey(private)
			if err != nil {
				t.Fatal(err)
			}
			config := &ssh.ServerConfig{PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
				if meta.User() != "sshx-fixture" || string(password) != "fixture-password" {
					return nil, errors.New("fixture password required")
				}
				return nil, nil
			}}
			config.AddHostKey(signer)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() {
				done <- servePasswordTransfer(listener, config, command, archive.Bytes())
			}()
			defer func() {
				listener.Close()
				if err := <-done; err != nil {
					t.Error(err)
				}
			}()
			dir := t.TempDir()
			knownHosts := filepath.Join(dir, "known_hosts")
			host, port, err := net.SplitHostPort(listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			entry := fmt.Sprintf("[%s]:%s %s", host, port, ssh.MarshalAuthorizedKey(signer.PublicKey()))
			if err := os.WriteFile(knownHosts, []byte(entry), 0600); err != nil {
				t.Fatal(err)
			}
			inputPath := os.DevNull
			if command == "upload" {
				inputPath = filepath.Join(dir, "input.tar.gz")
				if err := os.WriteFile(inputPath, archive.Bytes(), 0600); err != nil {
					t.Fatal(err)
				}
			}
			stdin, err := os.Open(inputPath)
			if err != nil {
				t.Fatal(err)
			}
			defer stdin.Close()
			if tc.terminalInput {
				master, slave, err := pty.Open()
				if err != nil {
					t.Fatal(err)
				}
				defer master.Close()
				defer slave.Close()
				stdin = slave
			}
			args := []string{"-F", os.DevNull,
				"-o", "UserKnownHostsFile=" + knownHosts,
				"-o", "GlobalKnownHostsFile=" + os.DevNull,
				"-o", "StrictHostKeyChecking=yes",
				"-o", "PreferredAuthentications=password",
				"-o", "NumberOfPasswordPrompts=1",
				"-o", "ConnectTimeout=5",
				"-p", port, "sshx-fixture@" + host, command}
			var output, diagnostic bytes.Buffer
			var stdout, stderr io.Writer = &output, &diagnostic
			if tc.files {
				out, err := os.Create(filepath.Join(dir, "output.tar.gz"))
				if err != nil {
					t.Fatal(err)
				}
				defer out.Close()
				diag, err := os.Create(filepath.Join(dir, "stderr"))
				if err != nil {
					t.Fatal(err)
				}
				defer diag.Close()
				stdout, stderr = out, diag
			}
			runErr := Run(client, args, []byte("fixture-password"), stdin, stdout, stderr)
			if tc.files {
				for _, pair := range []struct {
					name   string
					buffer *bytes.Buffer
				}{
					{"output.tar.gz", &output}, {"stderr", &diagnostic},
				} {
					data, err := os.ReadFile(filepath.Join(dir, pair.name))
					if err != nil {
						t.Fatal(err)
					}
					pair.buffer.Write(data)
				}
			}
			if runErr != nil {
				t.Fatalf("OpenSSH: %v; stderr=%q", runErr, diagnostic.String())
			}
			if !bytes.Equal(output.Bytes(), archive.Bytes()) {
				t.Fatalf("archive changed: got %d bytes, want %d", output.Len(), archive.Len())
			}
			if !strings.Contains(diagnostic.String(), "password:") || !strings.Contains(diagnostic.String(), "remote diagnostic\n") {
				t.Fatalf("missing diagnostics: %q", diagnostic.String())
			}
			if strings.Contains(diagnostic.String(), "fixture-password") {
				t.Fatal("password echoed")
			}
			reader, err := gzip.NewReader(&output)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			tr := tar.NewReader(reader)
			header, err := tr.Next()
			if err != nil || header.Name != "foo" {
				t.Fatalf("tar header=%v error=%v", header, err)
			}
			actual, err := io.ReadAll(tr)
			if err != nil || !bytes.Equal(actual, payload) {
				t.Fatalf("tar content changed: %v", err)
			}
			// Drain gzip to verify its checksum as well as the tar contents.
			if _, err := io.Copy(io.Discard, reader); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func servePasswordTransfer(listener net.Listener, config *ssh.ServerConfig, command string, archive []byte) error {
	conn, err := listener.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	server, channels, requests, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return err
	}
	defer server.Close()
	go ssh.DiscardRequests(requests)
	for channel := range channels {
		if channel.ChannelType() != "session" {
			channel.Reject(ssh.UnknownChannelType, "session required")
			continue
		}
		session, requests, err := channel.Accept()
		if err != nil {
			return err
		}
		defer session.Close()
		for request := range requests {
			var execRequest struct{ Command string }
			if request.Type != "exec" || ssh.Unmarshal(request.Payload, &execRequest) != nil || execRequest.Command != command {
				request.Reply(false, nil)
				continue
			}
			request.Reply(true, nil)
			if command == "upload" {
				input, err := io.ReadAll(session)
				if err != nil {
					return err
				}
				if !bytes.Equal(input, archive) {
					return errors.New("uploaded archive changed")
				}
			}
			if _, err := io.WriteString(session.Stderr(), "remote diagnostic\n"); err != nil {
				return err
			}
			if _, err := session.Write(archive); err != nil {
				return err
			}
			if _, err := session.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0})); err != nil {
				return err
			}
			if err := session.Close(); err != nil {
				return err
			}
			// Let OpenSSH send its disconnect before closing the transport;
			// otherwise a fast server can give the client a broken pipe.
			_ = server.Wait()
			return nil
		}
	}
	return errors.New("no transfer executed")
}
