package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

// This fixture never installs units or connects to the developer's user bus.
// The standalone activator works without cgroup delegation; the private user
// manager additionally needs a host that permits an isolated user manager.
func TestAgentSystemdIntegration(t *testing.T) {
	if os.Getenv("SSHX_SYSTEMD_INTEGRATION") != "1" {
		t.Skip("set SSHX_SYSTEMD_INTEGRATION=1 for disposable systemd activation tests")
	}
	for _, tool := range []string{"systemd-socket-activate", "systemctl", "systemd-analyze", "dbus-daemon"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatal("required integration tool unavailable", tool)
		}
	}
	version, err := exec.Command("systemctl", "--version").Output()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(strings.SplitN(string(version), "\n", 2)[0])
	root, err := os.MkdirTemp("", "sshx-sd-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	binary := filepath.Join(root, "sshx")
	build := exec.Command("go", "build", "-o", binary, "../../cmd/sshx")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v: %s", err, output)
	}
	for _, mode := range []string{"socket-activate", "user-manager"} {
		t.Run(mode, func(t *testing.T) {
			f := newSystemdFixture(t, filepath.Join(root, mode), binary)
			f.verifyTemplates(t)
			if mode == "socket-activate" {
				f.activate(t)
			} else {
				f.manager(t)
			}
		})
	}
}

type systemdFixture struct {
	root, binary, socket string
	env                  []string
	public               ssh.PublicKey
}

func newSystemdFixture(t *testing.T, root, binary string) *systemdFixture {
	t.Helper()
	for _, name := range []string{"", "runtime", "runtime/sshx-agent", "config", "config/sshx", "units", "bin"} {
		if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	f := &systemdFixture{root: root, binary: binary, socket: filepath.Join(root, "runtime/sshx-agent/agent.sock")}
	f.env = []string{"PATH=" + root + "/bin:/usr/bin:/bin", "HOME=" + root, "XDG_RUNTIME_DIR=" + root + "/runtime", "XDG_CONFIG_HOME=" + root + "/config", "XDG_DATA_HOME=" + root + "/data", "XDG_CACHE_HOME=" + root + "/cache", "SYSTEMD_UNIT_PATH=" + root + "/units", "SYSTEMD_LOG_TARGET=console", "DBUS_SESSION_BUS_ADDRESS=unix:path=" + root + "/runtime/bus"}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	f.public = signer.PublicKey()
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatal(err)
	}
	f.write(t, "key", pem.EncodeToMemory(block), 0600)
	registry := map[string]any{"version": 1, "keys": []any{map[string]any{"id": "fixture", "public_key": strings.TrimSpace(string(ssh.MarshalAuthorizedKey(f.public))), "enabled": true, "policy": "unrestricted-local", "backend": "gopass", "reference": "fixture-key"}}}
	data, err := json.Marshal(registry)
	if err != nil {
		t.Fatal(err)
	}
	f.write(t, "config/sshx/agent.json", data, 0600)
	// Only a generated fixture key is ever returned. Fail on leaked descriptors
	// or environment before recording access; no real gopass or GPG is invoked.
	script := `#!/bin/sh
test -z "${LISTEN_PID+x}${LISTEN_FDS+x}${LISTEN_FDNAMES+x}${LISTEN_PIDFDID+x}${SSH_AUTH_SOCK+x}${SSH_AGENT_PID+x}" || exit 81
for fd in /proc/$$/fd/*; do
  case "$(/usr/bin/readlink "$fd")" in socket:*) exit 82;; esac
done
printf 'read\n' >> ` + quoteShell(root+"/reads") + `
test ! -e ` + quoteShell(root+"/fail") + ` || exit 83
exec /bin/cat ` + quoteShell(root+"/key") + "\n"
	f.write(t, "bin/gopass", []byte(script), 0700)
	for _, unit := range []string{agentSocketUnit, agentServiceUnit} {
		data, err := os.ReadFile(filepath.Join("../../contrib/systemd", unit))
		if err != nil {
			t.Fatal(err)
		}
		data = bytes.ReplaceAll(data, []byte("/usr/bin/sshx"), []byte(binary))
		f.write(t, "units/"+unit, data, 0600)
	}
	for _, unit := range []string{"basic.target", "sockets.target", "shutdown.target"} {
		f.write(t, "units/"+unit, []byte("[Unit]\nDefaultDependencies=no\n"), 0600)
	}
	f.write(t, "units/sshx-test.target", []byte("[Unit]\nDefaultDependencies=no\nWants=sshx-agent.socket\n"), 0600)
	return f
}

func (f *systemdFixture) write(t *testing.T, name string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.root, name), data, mode); err != nil {
		t.Fatal(err)
	}
}

func (f *systemdFixture) command(program string, args ...string) *exec.Cmd {
	cmd := exec.Command(program, args...)
	cmd.Env = f.env
	cmd.WaitDelay = time.Second
	return cmd
}

func (f *systemdFixture) verifyTemplates(t *testing.T) {
	t.Helper()
	// Offline validation with an isolated unit search path and installed binary.
	cmd := f.command("systemd-analyze", "--user", "verify", filepath.Join(f.root, "units", agentSocketUnit), filepath.Join(f.root, "units", agentServiceUnit))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("unit verification: %v: %s", err, output)
	}
}

func fixtureWait(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("fixture readiness deadline exceeded")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (f *systemdFixture) start(t *testing.T, cmd *exec.Cmd) <-chan error {
	t.Helper()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait(); close(done) }()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})
	return done
}

func (f *systemdFixture) sign(t *testing.T, fail bool) {
	t.Helper()
	conn, err := net.DialTimeout("unix", f.socket, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	client := sshagent.NewClient(conn)
	keys, err := client.List()
	if err != nil || len(keys) != 1 {
		t.Fatal("activated listing failed", err)
	}
	data := []byte("isolated systemd signing")
	sig, err := client.Sign(keys[0], data)
	if fail {
		if err == nil {
			t.Fatal("backend failure did not deny signing")
		}
		return
	}
	if err != nil || f.public.Verify(data, sig) != nil {
		t.Fatal("activated signing failed", err)
	}
}

func (f *systemdFixture) activate(t *testing.T) {
	args := []string{"--listen=" + f.socket}
	for _, value := range f.env {
		args = append(args, "--setenv="+value)
	}
	args = append(args, "--", f.binary, "agent", "start", "--foreground", "--socket-activation", "--socket", f.socket)
	cmd := f.command("systemd-socket-activate", args...)
	done := f.start(t, cmd)
	fixtureWait(t, func() bool { _, err := os.Stat(f.socket); return err == nil })
	if err := os.Chmod(f.socket, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.root, "reads")); !os.IsNotExist(err) {
		t.Fatal("backend read before first connection")
	}
	f.sign(t, false) // first connection starts the real CLI through systemd's activator
	f.write(t, "fail", nil, 0600)
	f.sign(t, true)
	os.Remove(filepath.Join(f.root, "fail"))
	f.sign(t, false)
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("activated CLI did not stop")
	}
	if _, err := os.Stat(f.socket); err != nil {
		t.Fatal("activated CLI unlinked manager endpoint")
	}
	reads, err := os.ReadFile(filepath.Join(f.root, "reads"))
	if err != nil || string(reads) != "read\nread\nread\n" {
		t.Fatal("unexpected backend access count")
	}
}

func (f *systemdFixture) manager(t *testing.T) {
	if os.Getenv("SSHX_SYSTEMD_USER_MANAGER") != "1" {
		t.Skip("set SSHX_SYSTEMD_USER_MANAGER=1 only in a disposable container or VM with isolated, delegated cgroups")
	}
	dbus := f.command("dbus-daemon", "--session", "--nofork", "--nopidfile", "--address=unix:path="+f.root+"/runtime/bus")
	f.start(t, dbus)
	fixtureWait(t, func() bool { _, err := os.Stat(f.root + "/runtime/bus"); return err == nil })
	managerPath := "/lib/systemd/systemd"
	if _, err := os.Stat(managerPath); err != nil {
		managerPath = "/usr/lib/systemd/systemd"
	}
	cmd := f.command(managerPath, "--user", "--unit=sshx-test.target")
	var diagnostic bytes.Buffer
	cmd.Stderr = &diagnostic
	done := f.start(t, cmd)
	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case err := <-done:
			// A restricted runner cannot create /init.scope. Report this case as
			// skipped, never confuse standalone activation with manager coverage.
			if strings.Contains(diagnostic.String(), "Failed to allocate manager object") {
				t.Skipf("isolated user manager unavailable: %v: %s", err, &diagnostic)
			}
			t.Fatalf("isolated manager exited: %v: %s", err, &diagnostic)
		default:
		}
		if _, err := os.Stat(f.socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("isolated manager readiness timed out")
		}
		time.Sleep(10 * time.Millisecond)
	}
	run := func(program string, args ...string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, program, args...)
		command.Env = f.env
		command.WaitDelay = time.Second
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("fixture command %s: %v: %s", program, err, output)
		}
		return string(output)
	}
	status := run(f.binary, "agent", "status", "--systemd")
	if !strings.Contains(status, "inactive/dead") {
		t.Fatal("status activated the idle service")
	}
	// Ensure cleanup stops only this isolated manager's units before killing it.
	t.Cleanup(func() { _ = f.command("systemctl", "--user", "stop", agentSocketUnit, agentServiceUnit).Run() })
	f.sign(t, false)
	pid := strings.TrimSpace(run("systemctl", "--user", "show", "--property=MainPID", "--value", agentServiceUnit))
	f.sign(t, false)
	if next := strings.TrimSpace(run("systemctl", "--user", "show", "--property=MainPID", "--value", agentServiceUnit)); pid == "0" || next != pid {
		t.Fatal("connections did not share one service")
	}
	before, err := os.Stat(f.socket)
	if err != nil {
		t.Fatal(err)
	}
	run("systemctl", "--user", "restart", agentServiceUnit)
	f.sign(t, false)
	after, err := os.Stat(f.socket)
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("restart replaced manager socket")
	}
	f.write(t, "fail", nil, 0600)
	f.sign(t, true)
	run(f.binary, "agent", "stop", "--systemd")
	if _, err := os.Stat(f.socket); !os.IsNotExist(err) {
		t.Fatal("manager stop retained endpoint")
	}
	if c, err := net.DialTimeout("unix", f.socket, 100*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("stopped agent reactivated")
	}
	state := run("systemctl", "--user", "show", "--property=ActiveState", "--value", agentServiceUnit)
	if strings.TrimSpace(state) != "inactive" {
		t.Fatal(fmt.Sprintf("service state after stop: %s", state))
	}
}
