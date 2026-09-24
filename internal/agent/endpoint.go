package agent

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// ValidateDirectory requires an owner-only directory with trusted ancestors.
// It never creates or changes permissions on an existing directory.
func ValidateDirectory(directory string) error {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return errAgentSocket
	}
	fd, err := openAgentDirectory(filepath.Join(directory, "agent.sock"))
	if err != nil {
		return err
	}
	return unix.Close(fd)
}

// Probe checks endpoint ownership and requests public identities only. It does
// not open a credential backend or prove that a signing request would succeed.
func Probe(ctx context.Context, socket string) error {
	fd, err := openAgentDirectory(socket)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var before unix.Stat_t
	name := filepath.Base(socket)
	if unix.Fstatat(fd, name, &before, unix.AT_SYMLINK_NOFOLLOW) != nil || before.Mode&unix.S_IFMT != unix.S_IFSOCK || before.Uid != uint32(os.Geteuid()) || before.Mode&0077 != 0 {
		return errAgentSocket
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if err != nil {
		return errors.New("SSH agent endpoint is unavailable")
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	var after unix.Stat_t
	if unix.Fstatat(fd, name, &after, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameAgentSocket(before, after) {
		return errAgentSocket
	}
	if err := writeAgentReply(conn, agentPacket([]byte{agentListCode})); err != nil {
		return errAgentProtocol
	}
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return errAgentProtocol
	}
	size := binary.BigEndian.Uint32(header[:])
	if size < 5 || size > maxAgentFrameBytes {
		return errAgentProtocol
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(conn, body); err != nil {
		return errAgentProtocol
	}
	if body[0] != 12 {
		return errAgentProtocol
	}
	count := binary.BigEndian.Uint32(body[1:5])
	if count > maxAgentIdentities {
		return errAgentProtocol
	}
	rest := body[5:]
	for i := uint32(0); i < count; i++ {
		var ok bool
		_, rest, ok = agentWireString(rest)
		if !ok {
			return errAgentProtocol
		}
		_, rest, ok = agentWireString(rest)
		if !ok {
			return errAgentProtocol
		}
	}
	if len(rest) != 0 {
		return errAgentProtocol
	}
	return nil
}
