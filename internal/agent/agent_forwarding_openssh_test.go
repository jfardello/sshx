package agent

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// All listeners and keys are disposable. The unprivileged daemons authenticate
// only the fixture key, never consult system authorized_keys, and force a small
// command allowlist. No user provisioning or system sshd configuration is used.
func TestAgentForwardingOpenSSHIntegration(t *testing.T) {
	bin := os.Getenv("SSHX_AGENT_FORWARDING_OPENSSH_DIR")
	if bin == "" {
		t.Skip("set SSHX_AGENT_FORWARDING_OPENSSH_DIR to the pinned OpenSSH build directory")
	}
	if !filepath.IsAbs(bin) {
		t.Fatal("OpenSSH build path must be absolute")
	}
	if os.Geteuid() == 0 {
		t.Fatal("run the forwarding fixture as an unprivileged user")
	}
	for _, tool := range []string{"ssh", "sshd"} {
		out, err := exec.Command(filepath.Join(bin, tool), "-V").CombinedOutput()
		if err != nil || !strings.Contains(string(out), "OpenSSH_10.5p1") {
			t.Fatalf("%s must be pinned OpenSSH 10.5p1: %v", tool, err)
		}
	}
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	dir := agentTestDirectory(t)
	write := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	record, raw := testAgentKey(t)
	pub := policyPublic(t, record)
	authorized := write("authorized_keys", ssh.MarshalAuthorizedKey(pub))
	identity := write("identity.pub", ssh.MarshalAuthorizedKey(pub))
	hosts := []ssh.Signer{bindingSigner(t), bindingSigner(t), bindingSigner(t)}
	ports := make([]int, 3)
	config := filepath.Join(dir, "ssh_config")
	// Only fixture-controlled commands run remotely. SSH_AUTH_SOCK is supplied by
	// sshd for each session, so nested clients cannot bypass forwarding via the
	// local agent path. Clear the rest of the inherited shell environment.
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
	handler := write("handler.sh", []byte("#!/bin/sh\ncase \"$SSH_ORIGINAL_COMMAND\" in\n"+
		" target) printf 'forwarding-authenticated\\n' ;;\n"+
		" via-d) exec env -i PATH=/usr/bin:/bin SSH_AUTH_SOCK=\"$SSH_AUTH_SOCK\" "+quote(filepath.Join(bin, "ssh"))+" -F "+quote(config)+" d target ;;\n"+
		" via-c) exec env -i PATH=/usr/bin:/bin SSH_AUTH_SOCK=\"$SSH_AUTH_SOCK\" "+quote(filepath.Join(bin, "ssh"))+" -A -F "+quote(config)+" c via-d ;;\n"+
		" legacy-d) exec env -i PATH=/usr/bin:/bin SSH_AUTH_SOCK=\"$SSH_AUTH_SOCK\" "+quote(filepath.Join(bin, "ssh"))+" -F "+quote(config)+" -o PubkeyAuthentication=unbound d target ;;\n"+
		" list) exec "+quote(filepath.Join(bin, "ssh-add"))+" -L ;;\n"+
		" clear) exec "+quote(filepath.Join(bin, "ssh-add"))+" -D ;;\n"+
		" *) exit 99 ;;\nesac\n"))
	for i := range hosts {
		// A separate key per host is essential: shared pins cannot distinguish hosts.
		private := mutationPrivate(t)
		hosts[i], err = ssh.NewSignerFromKey(private)
		if err != nil {
			t.Fatal(err)
		}
		block, err := ssh.MarshalPrivateKey(private, "fixture host")
		if err != nil {
			t.Fatal(err)
		}
		hostPath := write(fmt.Sprintf("host-%d", i), pem.EncodeToMemory(block))
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ports[i] = listener.Addr().(*net.TCPAddr).Port
		listener.Close()
		// StrictModes rejects /tmp even with our owner-only fixture directory.
		// Disable that sshd check only here; authorized_keys is an exact private path.
		cfg := fmt.Sprintf("Port %d\nListenAddress 127.0.0.1\nHostKey %s\nPidFile %s\nAuthorizedKeysFile %s\nAuthorizedKeysCommand none\nTrustedUserCAKeys none\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\nAuthenticationMethods publickey\nAllowUsers %s\nPermitRootLogin no\nAllowAgentForwarding yes\nAllowTcpForwarding no\nX11Forwarding no\nPermitTunnel no\nPermitTTY no\nPermitUserRC no\nPermitUserEnvironment no\nStrictModes no\nPerSourcePenalties no\nForceCommand /bin/sh %s\nLogLevel VERBOSE\n", ports[i], hostPath, filepath.Join(dir, fmt.Sprintf("pid-%d", i)), authorized, current.Username, handler)
		cfgPath := write(fmt.Sprintf("sshd-%d.conf", i), []byte(cfg))
		logPath := filepath.Join(dir, fmt.Sprintf("sshd-%d.log", i))
		log, err := os.Create(logPath)
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(filepath.Join(bin, "sshd"), "-D", "-e", "-f", cfgPath)
		cmd.Env = []string{"PATH=/usr/bin:/bin"}
		cmd.Stdout = log
		cmd.Stderr = log
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := cmd.Start(); err != nil {
			log.Close()
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		t.Cleanup(func() {
			syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			<-done
			log.Close()
			if t.Failed() {
				data, _ := os.ReadFile(logPath)
				t.Logf("sshd fixture: %s", data)
			}
		})
		deadline := time.Now().Add(5 * time.Second)
		for {
			conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(ports[i])), 50*time.Millisecond)
			if err == nil {
				conn.Close()
				break
			}
			if time.Now().After(deadline) {
				data, _ := os.ReadFile(logPath)
				t.Fatalf("sshd did not listen: %s", data)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	knownText := ""
	for i, host := range hosts {
		knownText += fmt.Sprintf("[127.0.0.1]:%d %s\n", ports[i], policyPin(host.PublicKey()))
	}
	known := write("known_hosts", []byte(knownText))
	cfg := fmt.Sprintf("Host *\n HostName 127.0.0.1\n User %s\n BatchMode yes\n IdentitiesOnly yes\n IdentityFile %s\n UserKnownHostsFile %s\n GlobalKnownHostsFile /dev/null\n StrictHostKeyChecking yes\n PreferredAuthentications publickey\n PasswordAuthentication no\n KbdInteractiveAuthentication no\n ControlMaster no\n ControlPath none\n ForwardAgent no\n ConnectTimeout 5\n LogLevel ERROR\n", current.Username, identity, known)
	for i, name := range []string{"b", "c", "d"} {
		cfg += fmt.Sprintf("Host %s\n Port %d\n", name, ports[i])
	}
	write("ssh_config", []byte(cfg))
	edge := func(from, to int) agentDestinationEdge {
		var source ssh.PublicKey
		if from >= 0 {
			source = hosts[from].PublicKey()
		}
		return policyEdge(source, hosts[to].PublicKey(), current.Username)
	}
	record.Policy = "destination-constrained"
	record.Destinations = &agentDestinationPolicy{Version: 1, Edges: []agentDestinationEdge{edge(-1, 0), edge(0, 1), edge(1, 2), edge(0, 2)}}
	registryPath := write("agent.json", policyJSON(t, record))
	registry, err := readAgentRegistry(registryPath)
	if err != nil {
		t.Fatal(err)
	}
	backend := &agentTestBackend{data: map[string][]byte{record.Reference: raw}}
	socket := filepath.Join(dir, "agent.sock")
	server, err := newAgentServer(socket, registry, backend.open)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	server.SetForwardingEnabled(true)
	if err := server.ConfigureMutations(filepath.Join(dir, "state"), true); err != nil {
		t.Fatal(err)
	}
	go server.Serve(context.Background())
	run := func(command string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, filepath.Join(bin, "ssh"), "-A", "-F", config, "b", command)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + dir, "SSH_AUTH_SOCK=" + socket}
		return cmd.CombinedOutput()
	}
	for _, command := range []string{"via-d", "via-c"} {
		t.Run(command, func(t *testing.T) {
			before := backend.reads.Load()
			out, err := run(command)
			if err != nil || string(out) != "forwarding-authenticated\n" {
				t.Fatalf("multi-hop authentication: %v: %s", err, out)
			}
			want := int32(2)
			if command == "via-c" {
				want = 3
			}
			if backend.reads.Load() != before+want {
				t.Fatal("expected every host to authenticate with agent")
			}
		})
	}
	t.Run("remote-list", func(t *testing.T) {
		out, err := run("list")
		if err != nil || !bytes.Contains(out, bytes.TrimSpace(ssh.MarshalAuthorizedKey(pub))) {
			t.Fatalf("forwarded list: %v: %s", err, out)
		}
	})
	t.Run("remote-control", func(t *testing.T) {
		out, err := run("clear")
		if err == nil {
			t.Fatalf("remote removal accepted: %s", out)
		}
		if server.keys.mutations.suppressAll {
			t.Fatal("remote removal changed state")
		}
	})
	t.Run("non-hostbound", func(t *testing.T) {
		before := backend.reads.Load()
		out, err := run("legacy-d")
		if err == nil {
			t.Fatalf("non-hostbound accepted: %s", out)
		}
		if backend.reads.Load() != before+1 {
			t.Fatal("legacy request fetched target key")
		}
	})
	t.Run("missing-edge", func(t *testing.T) {
		saved := record.Destinations.Edges
		record.Destinations.Edges = saved[:3]
		writePolicyFile(t, registryPath, policyJSON(t, record))
		before := backend.reads.Load()
		out, err := run("via-d")
		if err == nil {
			t.Fatalf("missing edge accepted: %s", out)
		}
		if backend.reads.Load() != before+1 {
			t.Fatal("missing edge fetched target key")
		}
		record.Destinations.Edges = saved
		writePolicyFile(t, registryPath, policyJSON(t, record))
	})
	t.Run("forwarding-disabled", func(t *testing.T) {
		server.SetForwardingEnabled(false)
		out, err := run("via-d")
		if err == nil {
			t.Fatalf("disabled forwarding accepted: %s", out)
		}
	})
	backend.assertCleared(t)
}
