package agent

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func agentRegistryPath() (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if !filepath.IsAbs(base) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", errAgentRegistry
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "sshx", "agent.json"), nil
}

func loadAgentRegistry() (*agentRegistry, error) {
	name, err := agentRegistryPath()
	if err != nil {
		return nil, err
	}
	return readAgentRegistry(name)
}

// Traverse directory descriptors rather than checking paths then reopening them.
// O_NOFOLLOW protects both the file and ancestors from symlink substitution.
func readAgentRegistry(name string) (*agentRegistry, error) {
	registry, err := readAgentRegistrySnapshot(name)
	if err == nil {
		registry.source = name
	}
	return registry, err
}

func readAgentRegistrySnapshot(name string) (*agentRegistry, error) {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return nil, errAgentRegistry
	}
	parts := strings.Split(strings.TrimPrefix(name, "/"), "/")
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errAgentRegistry
	}
	defer func() { _ = unix.Close(fd) }()
	var rootStat unix.Stat_t
	if unix.Fstat(fd, &rootStat) != nil {
		return nil, errAgentRegistry
	}
	for i, part := range parts {
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		next, err := unix.Openat(fd, part, flags, 0)
		if errors.Is(err, unix.ENOENT) {
			return &agentRegistry{}, nil
		}
		if err != nil {
			return nil, errAgentRegistry
		}
		var st unix.Stat_t
		if err = unix.Fstat(next, &st); err != nil {
			unix.Close(next)
			return nil, errAgentRegistry
		}
		owner := st.Uid == uint32(os.Geteuid())
		trusted := owner || st.Uid == rootStat.Uid
		// Root-owned sticky ancestors such as /tmp cannot replace an owned child.
		writable := st.Mode&0022 != 0 && !(i < len(parts)-2 && st.Uid == rootStat.Uid && st.Mode&unix.S_ISVTX != 0)
		if !trusted || writable {
			unix.Close(next)
			return nil, errAgentRegistry
		}
		if i == len(parts)-1 {
			if !owner || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0077 != 0 || st.Size > maxAgentRegistryBytes {
				unix.Close(next)
				return nil, errAgentRegistry
			}
			file := os.NewFile(uintptr(next), "agent registry")
			defer file.Close()
			data, err := io.ReadAll(io.LimitReader(file, maxAgentRegistryBytes+1))
			if err != nil {
				return nil, errAgentRegistry
			}
			defer clearBytes(data)
			return parseAgentRegistry(data)
		}
		unix.Close(fd)
		fd = next
	}
	return nil, errAgentRegistry
}
