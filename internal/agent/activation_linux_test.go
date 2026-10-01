package agent

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	sshagent "golang.org/x/crypto/ssh/agent"
	"golang.org/x/sys/unix"
)

func TestActivatedHelperIsolation(t *testing.T) {
	if os.Getenv("SSHX_ACTIVATION_HELPER") != "1" {
		return
	}
	for _, name := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES", "LISTEN_PIDFDID"} {
		if _, ok := os.LookupEnv(name); ok {
			t.Fatal("helper inherited activation environment")
		}
	}
	files, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		target, _ := os.Readlink("/proc/self/fd/" + file.Name())
		if strings.HasPrefix(target, "socket:") {
			t.Fatal("helper inherited a socket")
		}
	}
}

// A subprocess preserves the real fd=3 contract without altering the test
// runner's descriptors or environment. The parent stands in for the manager.
func TestActivatedServerChild(t *testing.T) {
	mode := os.Getenv("SSHX_ACTIVATION_CHILD")
	if mode == "" {
		return
	}
	pid := strconv.Itoa(os.Getpid())
	if mode == "wrong-pid" {
		pid = "0"
	}
	os.Setenv("LISTEN_PID", pid)
	os.Setenv("LISTEN_FDS", "1")
	os.Setenv("LISTEN_FDNAMES", "sshx-agent")
	os.Unsetenv("LISTEN_PIDFDID")
	switch mode {
	case "extra", "bad-count", "missing-count":
		os.Setenv("LISTEN_FDS", map[string]string{"extra": "2", "bad-count": "-1", "missing-count": ""}[mode])
	case "wrong-pidfd":
		os.Setenv("LISTEN_PIDFDID", "1")
	case "pidfd":
		fd, err := unix.PidfdOpen(os.Getpid(), 0)
		if err != nil {
			t.Skip("kernel does not support pidfds")
		}
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			t.Fatal(err)
		}
		unix.Close(fd)
		os.Setenv("LISTEN_PIDFDID", strconv.FormatUint(st.Ino, 10))
	}
	service, backend, public := agentTestService(t)
	if mode == "backend-failure" {
		backend.openErr = errors.New("synthetic backend unavailable")
	}
	var opener StoreOpener = backend.open
	if mode == "nil-opener" {
		opener = nil
	}
	socket := os.Getenv("SSHX_ACTIVATION_SOCKET")
	server, err := NewActivatedServer(socket, service.registry, opener)
	for _, name := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES", "LISTEN_PIDFDID"} {
		if _, ok := os.LookupEnv(name); ok {
			t.Fatal("activation environment not consumed")
		}
	}
	wantSuccess := mode == "success" || mode == "backend-failure" || mode == "pidfd"
	if !wantSuccess {
		if err == nil {
			server.Close()
			t.Fatal("invalid activation accepted")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	// FileListener duplicated fd 3 and the original must have been closed.
	if _, err := unix.FcntlInt(3, unix.F_GETFD, 0); err != unix.EBADF {
		t.Fatal("original activation descriptor retained")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	conn := agentTestDial(t, socket)
	client := sshagent.NewClient(conn)
	keys, err := client.List()
	if err != nil || len(keys) != 1 || backend.opens.Load() != 0 {
		t.Fatal("activation list failed or read backend", err)
	}
	data := []byte("activated signing challenge")
	sig, err := client.Sign(keys[0], data)
	if mode == "backend-failure" {
		if err == nil || backend.opens.Load() != 1 {
			t.Fatal("unavailable backend did not fail signing")
		}
		if _, err := client.List(); err != nil {
			t.Fatal("backend failure broke public discovery")
		}
	} else if err != nil || public.Verify(data, sig) != nil {
		t.Fatal("activated signature failed", err)
	}
	helper := exec.Command(os.Args[0], "-test.run=^TestActivatedHelperIsolation$")
	helper.Env = append(os.Environ(), "SSHX_ACTIVATION_HELPER=1")
	if output, err := helper.CombinedOutput(); err != nil {
		t.Fatalf("helper isolation: %v: %s", err, output)
	}
	cancel()
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("activated shutdown blocked")
	}
	if _, err := client.List(); err == nil {
		t.Fatal("connection survived shutdown")
	}
	if _, err := os.Lstat(socket); err != nil {
		t.Fatal("service removed manager socket", err)
	}
}

func TestActivatedServer(t *testing.T) {
	for _, mode := range []string{"success", "backend-failure", "pidfd", "wrong-pid", "extra", "bad-count", "missing-count", "wrong-pidfd", "wrong-path", "relative", "symlink", "unsafe-directory", "unsafe-socket", "missing-socket", "nil-opener", "file", "datagram", "connected", "tcp", "abstract"} {
		t.Run(mode, func(t *testing.T) {
			dir := agentTestDirectory(t)
			socket := filepath.Join(dir, "agent.sock")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			if err := os.Chmod(socket, 0600); err != nil {
				t.Fatal(err)
			}
			file, err := listener.File()
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			switch mode {
			case "wrong-path":
				socket = filepath.Join(dir, "other.sock")
			case "relative":
				socket = "agent.sock"
			case "symlink":
				alias := filepath.Join(dir, "alias")
				if err := os.Symlink(dir, alias); err != nil {
					t.Fatal(err)
				}
				socket = filepath.Join(alias, "agent.sock")
			case "unsafe-directory":
				os.Chmod(dir, 0755)
			case "unsafe-socket":
				os.Chmod(socket, 0666)
			case "missing-socket":
				os.Remove(socket)
			case "file":
				file, err = os.Open("/dev/null")
			case "datagram":
				var c *net.UnixConn
				c, err = net.ListenUnixgram("unixgram", &net.UnixAddr{Name: filepath.Join(dir, "datagram"), Net: "unixgram"})
				if err == nil {
					defer c.Close()
					file, err = c.File()
				}
			case "connected":
				var c *net.UnixConn
				c, err = net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
				if err == nil {
					defer c.Close()
					file, err = c.File()
				}
			case "tcp":
				var l *net.TCPListener
				l, err = net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err == nil {
					defer l.Close()
					file, err = l.File()
				}
			case "abstract":
				var l *net.UnixListener
				l, err = net.ListenUnix("unix", &net.UnixAddr{Name: "@" + dir, Net: "unix"})
				if err == nil {
					defer l.Close()
					file, err = l.File()
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			attempts := 1
			if mode == "success" {
				attempts = 2
			} // restart on the same manager-owned listener
			for i := 0; i < attempts; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestActivatedServerChild$")
				cmd.Env = append(os.Environ(), "SSHX_ACTIVATION_CHILD="+mode, "SSHX_ACTIVATION_SOCKET="+socket)
				cmd.ExtraFiles = []*os.File{file}
				if mode == "extra" {
					cmd.ExtraFiles = append(cmd.ExtraFiles, file)
				}
				if output, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("activation %s: %v: %s", mode, err, output)
				}
			}
		})
	}
}
