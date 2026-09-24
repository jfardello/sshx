package agent

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// A test-only transparent proxy observes the real client's wire proof and
// extension response. Negative modes alter only the binding; auth signatures
// and backend-read counters must then demonstrate fail-closed behavior.
type bindingProxy struct {
	path          string
	corrupt       atomic.Bool
	forward       atomic.Bool
	mutex         sync.Mutex
	verified      int
	failures      int
	host          ssh.PublicKey
	signedSession bool
}

func startBindingProxy(t *testing.T, upstream string) *bindingProxy {
	t.Helper()
	p := &bindingProxy{path: filepath.Join(agentTestDirectory(t), "proxy.sock")}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: p.path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	var mutex sync.Mutex
	connections := map[net.Conn]bool{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			mutex.Lock()
			connections[client] = true
			mutex.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer client.Close()
				defer func() { mutex.Lock(); delete(connections, client); mutex.Unlock() }()
				target, err := net.DialTimeout("unix", upstream, time.Second)
				if err != nil {
					return
				}
				defer target.Close()
				client.SetDeadline(time.Now().Add(10 * time.Second))
				target.SetDeadline(time.Now().Add(10 * time.Second))
				var session []byte
				for {
					body, err := readBindingProxyFrame(client)
					if err != nil {
						return
					}
					var proof *agentBindingState
					isBinding := false
					if body[0] == agentExtensionCode {
						name, contents, ok := agentWireString(body[1:])
						if ok && string(name) == sessionBindExtension {
							isBinding = true
							proof = &agentBindingState{}
							// Validate the client's untouched proof before injecting negative cases.
							if proof.record(contents) != nil {
								return
							}
							if p.corrupt.Load() {
								contents[len(contents)-2] ^= 1
							}
							if p.forward.Load() {
								contents[len(contents)-1] = 1
							}
						}
					}
					if err := writeAgentReply(target, agentPacket(body)); err != nil {
						return
					}
					reply, err := readBindingProxyFrame(target)
					if err != nil {
						return
					}
					p.mutex.Lock()
					if isBinding && len(reply) == 1 {
						if reply[0] == 6 {
							p.verified++
							p.host = proof.chain[0].hostKey
							session = bytes.Clone(proof.chain[0].session)

						} else if reply[0] == 28 {
							p.failures++
						}
					}
					if body[0] == agentSignCode && reply[0] == 14 {
						_, rest, ok := agentWireString(body[1:])
						if ok {
							data, _, ok := agentWireString(rest)
							if ok {
								sid, _, ok := agentWireString(data)
								if ok && len(session) > 0 && bytes.Equal(sid, session) {
									p.signedSession = true
								}
							}
						}
					}
					p.mutex.Unlock()
					clearBytes(body)
					if err := writeAgentReply(client, agentPacket(reply)); err != nil {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		<-done
		mutex.Lock()
		for conn := range connections {
			conn.Close()
		}
		mutex.Unlock()
		workers.Wait()
	})
	return p
}

func readBindingProxyFrame(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > maxAgentFrameBytes {
		return nil, errAgentProtocol
	}
	body := make([]byte, size)
	_, err := io.ReadFull(r, body)
	return body, err
}
