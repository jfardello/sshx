package agent

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

var errActivation = errors.New("invalid systemd activation: expected one listening Unix stream descriptor for the configured private socket")

// NewActivatedServer consumes systemd's descriptor 3. The manager retains
// ownership of the endpoint: neither errors nor Close unlink or chmod it.
// Call once during startup, before launching any credential helpers.
func NewActivatedServer(socket string, registry *Registry, opener StoreOpener) (*Server, error) {
	pid, count, pidfdID := os.Getenv("LISTEN_PID"), os.Getenv("LISTEN_FDS"), os.Getenv("LISTEN_PIDFDID")
	for _, key := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES", "LISTEN_PIDFDID"} {
		_ = os.Unsetenv(key)
	}
	if pid != strconv.Itoa(os.Getpid()) || count != "1" {
		return nil, errActivation
	}
	// Protect the original immediately; net.FileListener creates a separate
	// close-on-exec descriptor and the original is closed on every path below.
	if _, err := unix.FcntlInt(3, unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
		return nil, errActivation
	}
	file := os.NewFile(3, "systemd-agent-listener")
	defer file.Close()
	if pidfdID != "" {
		fd, err := unix.PidfdOpen(os.Getpid(), 0)
		if err != nil {
			return nil, errActivation
		}
		var st unix.Stat_t
		err = unix.Fstat(fd, &st)
		_ = unix.Close(fd)
		if err != nil || pidfdID != strconv.FormatUint(st.Ino, 10) {
			return nil, errActivation
		}
	}
	kind, err := unix.GetsockoptInt(3, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil || kind != unix.SOCK_STREAM {
		return nil, errActivation
	}
	accepting, err := unix.GetsockoptInt(3, unix.SOL_SOCKET, unix.SO_ACCEPTCONN)
	if err != nil || accepting != 1 {
		return nil, errActivation
	}
	address, err := unix.Getsockname(3)
	path, ok := address.(*unix.SockaddrUnix)
	if err != nil || !ok || path.Name != socket {
		return nil, errActivation
	}
	directory, err := openAgentDirectory(socket)
	if err != nil {
		return nil, errActivation
	}
	retained := false
	defer func() {
		if !retained {
			_ = unix.Close(directory)
		}
	}()
	var st unix.Stat_t
	if unix.Fstatat(directory, filepath.Base(socket), &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Uid != uint32(os.Geteuid()) || st.Mode&0777 != 0600 {
		return nil, errActivation
	}
	if opener == nil {
		return nil, errAgentDenied
	}
	keys, err := newAgentKeyService(registry, agentStoreOpener(opener))
	if err != nil {
		return nil, err
	}
	listener, err := net.FileListener(file)
	if err != nil {
		return nil, errActivation
	}
	local, ok := listener.(*net.UnixListener)
	if !ok {
		_ = listener.Close()
		return nil, errActivation
	}
	local.SetUnlinkOnClose(false)
	ctx, cancel := context.WithCancel(context.Background())
	server := &agentServer{listener: local, keys: keys, ctx: ctx, cancel: cancel,
		connections: make(map[*net.UnixConn]struct{}), directoryFD: directory,
		socketName: filepath.Base(socket), readTimeout: 30 * time.Second, writeTimeout: 5 * time.Second}
	retained = true
	agentLoggingOnce.Do(func() { log.SetOutput(io.Discard) })
	return server, nil
}
