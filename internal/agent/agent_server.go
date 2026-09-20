package agent

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

const maxAgentConnections = 64

var agentLoggingOnce sync.Once

var errAgentSocket = errors.New("SSH agent requires an unused socket in a trusted owner-only directory")

type agentServer struct {
	listener     *net.UnixListener
	keys         *agentKeyService
	ctx          context.Context
	cancel       context.CancelFunc
	mutex        sync.Mutex
	connections  map[*net.UnixConn]struct{}
	workers      sync.WaitGroup
	started      atomic.Bool
	closeOnce    sync.Once
	closeErr     error
	directoryFD  int
	ownsSocket   bool
	socketName   string
	socketStat   unix.Stat_t
	readTimeout  time.Duration
	writeTimeout time.Duration
}

// The caller provides an existing private runtime directory.
func newAgentServer(socketPath string, registry *agentRegistry, opener agentStoreOpener) (*agentServer, error) {
	keys, err := newAgentKeyService(registry, opener)
	if err != nil {
		return nil, err
	}
	fd, err := openAgentDirectory(socketPath)
	if err != nil {
		return nil, err
	}
	name := filepath.Base(socketPath)
	var existing unix.Stat_t
	if err := unix.Fstatat(fd, name, &existing, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		unix.Close(fd)
		return nil, errAgentSocket
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		unix.Close(fd)
		return nil, errAgentSocket
	}
	// Never let net.UnixListener unlink a replacement endpoint by pathname.
	listener.SetUnlinkOnClose(false)
	ctx, cancel := context.WithCancel(context.Background())
	server := &agentServer{listener: listener, keys: keys, ctx: ctx, cancel: cancel, connections: make(map[*net.UnixConn]struct{}), directoryFD: fd, ownsSocket: true, socketName: name, readTimeout: 30 * time.Second, writeTimeout: 5 * time.Second}
	if unix.Fstatat(fd, name, &server.socketStat, unix.AT_SYMLINK_NOFOLLOW) != nil || server.socketStat.Mode&unix.S_IFMT != unix.S_IFSOCK || server.socketStat.Uid != uint32(os.Geteuid()) {
		_ = server.Close()
		return nil, errAgentSocket
	}
	// The owner-only parent prevents other users reaching the newly bound socket
	// during chmod. No process-wide umask changes are needed.
	if unix.Fchmodat(fd, name, 0600, 0) != nil {
		_ = server.Close()
		return nil, errAgentSocket
	}
	var final unix.Stat_t
	if unix.Fstatat(fd, name, &final, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameAgentSocket(server.socketStat, final) || final.Mode&0777 != 0600 {
		_ = server.Close()
		return nil, errAgentSocket
	}
	// Detect parent substitution during bind; the retained descriptor anchors
	// later cleanup even if the directory is renamed after successful startup.
	parent, err := os.Open(filepath.Dir(socketPath))
	if err != nil {
		_ = server.Close()
		return nil, errAgentSocket
	}
	var before, after unix.Stat_t
	e1 := unix.Fstat(fd, &before)
	e2 := unix.Fstat(int(parent.Fd()), &after)
	_ = parent.Close()
	if e1 != nil || e2 != nil || before.Dev != after.Dev || before.Ino != after.Ino {
		_ = server.Close()
		return nil, errAgentSocket
	}
	// Upstream ServeAgent uses the process-global logger with no per-agent hook.
	// Disable it once before serving; use explicit writers for future diagnostics.
	agentLoggingOnce.Do(func() { log.SetOutput(io.Discard) })
	return server, nil
}
func openAgentDirectory(socketPath string) (int, error) {
	if !filepath.IsAbs(socketPath) || filepath.Clean(socketPath) != socketPath || len(socketPath) > 100 {
		return -1, errAgentSocket
	}
	dir := filepath.Dir(socketPath)
	if dir == "/" {
		return -1, errAgentSocket
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, errAgentSocket
	}
	fail := func() (int, error) { _ = unix.Close(fd); return -1, errAgentSocket }
	var root unix.Stat_t
	if unix.Fstat(fd, &root) != nil {
		return fail()
	}
	parts := strings.Split(strings.TrimPrefix(dir, "/"), "/")
	for i, part := range parts {
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return fail()
		}
		_ = unix.Close(fd)
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil {
			return fail()
		}
		owner := st.Uid == uint32(os.Geteuid())
		if !owner && st.Uid != root.Uid {
			return fail()
		}
		if i == len(parts)-1 {
			if !owner || st.Mode&0777 != 0700 {
				return fail()
			}
		} else if st.Mode&0022 != 0 && !(st.Uid == root.Uid && st.Mode&unix.S_ISVTX != 0) {
			return fail()
		}
	}
	return fd, nil
}
func sameAgentSocket(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && b.Mode&unix.S_IFMT == unix.S_IFSOCK && b.Uid == uint32(os.Geteuid())
}

func (s *agentServer) Serve(ctx context.Context) error {
	if !s.started.CompareAndSwap(false, true) {
		return errAgentDenied
	}
	stop := context.AfterFunc(ctx, func() { _ = s.Close() })
	defer stop()
	defer s.Close()
	for {
		conn, err := s.listener.AcceptUnix()
		if err != nil {
			if s.ctx.Err() != nil {
				return nil
			}
			return errAgentSocket
		}
		s.mutex.Lock()
		if s.ctx.Err() != nil || len(s.connections) >= maxAgentConnections {
			s.mutex.Unlock()
			_ = conn.Close()
			continue
		}
		s.connections[conn] = struct{}{}
		s.workers.Add(1)
		s.mutex.Unlock()
		go func() {
			defer s.workers.Done()
			defer func() { _ = conn.Close(); s.mutex.Lock(); delete(s.connections, conn); s.mutex.Unlock() }()
			s.serveConnection(conn)
		}()
	}
}
func (s *agentServer) serveConnection(conn *net.UnixConn) {
	var identity [32]byte
	if _, err := rand.Read(identity[:]); err != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.WithValue(s.ctx, agentConnectionIdentity{}, identity))
	// A separate bounded reader observes disconnects while a local prompt waits.
	// Only one pending frame is retained; excessive pipelining closes the client.
	frames := make(chan []byte, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer cancel()
		for {
			if conn.SetReadDeadline(time.Now().Add(s.readTimeout)) != nil {
				return
			}
			var header [4]byte
			if _, err := io.ReadFull(conn, header[:]); err != nil {
				return
			}
			size := binary.BigEndian.Uint32(header[:])
			if size == 0 || size > maxAgentFrameBytes {
				return
			}
			body := make([]byte, int(size))
			if _, err := io.ReadFull(conn, body); err != nil {
				clearBytes(body)
				return
			}
			select {
			case frames <- body:
			case <-ctx.Done():
				clearBytes(body)
				return
			default:
				clearBytes(body)
				return
			}
		}
	}()
	defer func() {
		cancel()
		_ = conn.Close()
		<-done
		for {
			select {
			case body := <-frames:
				clearBytes(body)
			default:
				return
			}
		}
	}()
	adapter := &agentConnection{ctx: ctx, keys: s.keys}
	for {
		var body []byte
		select {
		case <-ctx.Done():
			return
		case body = <-frames:
		}
		reply, dispatchErr := dispatchAgentFrame(adapter, body)
		clearBytes(body)
		if ctx.Err() != nil || conn.SetWriteDeadline(time.Now().Add(s.writeTimeout)) != nil {
			clearBytes(reply)
			return
		}
		writeErr := writeAgentReply(conn, reply)
		clearBytes(reply)
		if dispatchErr != nil || writeErr != nil {
			return
		}
	}
}
func (s *agentServer) Close() error {
	s.closeOnce.Do(func() {
		s.cancel()
		_ = s.listener.Close()
		s.mutex.Lock()
		for conn := range s.connections {
			_ = conn.Close()
		}
		s.mutex.Unlock()
		s.workers.Wait()
		if s.ownsSocket {
			var current unix.Stat_t
			if err := unix.Fstatat(s.directoryFD, s.socketName, &current, unix.AT_SYMLINK_NOFOLLOW); err == nil && sameAgentSocket(s.socketStat, current) {
				if err := unix.Unlinkat(s.directoryFD, s.socketName, 0); err != nil {
					s.closeErr = errAgentSocket
				}
			}
		}
		if err := unix.Close(s.directoryFD); err != nil {
			s.closeErr = errAgentSocket
		}
	})
	return s.closeErr
}
