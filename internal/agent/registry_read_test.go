package agent

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestAgentRegistryFilesystem(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "agent.json")
	rec, _ := testAgentKey(t)
	data := registryJSON(t, rec)
	if reg, err := readAgentRegistry(name); err != nil || len(reg.keys) != 0 {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readAgentRegistry(name); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(name, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readAgentRegistry(name); err == nil {
		t.Fatal("accepted exposed registry")
	}
	os.Chmod(name, 0600)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(name, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readAgentRegistry(link); err == nil {
		t.Fatal("accepted symlink")
	}
	parentLink := filepath.Join(dir, "parent")
	os.Symlink(dir, parentLink)
	if _, err := readAgentRegistry(filepath.Join(parentLink, "agent.json")); err == nil {
		t.Fatal("accepted parent symlink")
	}
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readAgentRegistry(fifo); err == nil {
		t.Fatal("accepted FIFO")
	}
	for _, path := range []string{"relative", dir, dir + "/../agent.json"} {
		if _, err := readAgentRegistry(path); err == nil {
			t.Fatal("accepted unsafe path")
		}
	}
	os.Chmod(dir, 0777)
	if _, err := readAgentRegistry(name); err == nil {
		t.Fatal("accepted writable parent")
	}
	os.Chmod(dir, 0700)
	os.WriteFile(name, bytes.Repeat([]byte("x"), maxAgentRegistryBytes+1), 0600)
	if _, err := readAgentRegistry(name); err == nil {
		t.Fatal("accepted oversized registry")
	}
}

func TestAgentRegistryDefaultLocation(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	path, err := agentRegistryPath()
	if err != nil || path != filepath.Join(home, ".config", "sshx", "agent.json") {
		t.Fatal(path, err)
	}
	reg, err := loadAgentRegistry()
	if err != nil || len(reg.keys) != 0 {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", "relative")
	same, _ := agentRegistryPath()
	if same != path {
		t.Fatal(same)
	}
	t.Setenv("XDG_CONFIG_HOME", home)
	path, _ = agentRegistryPath()
	if path != filepath.Join(home, "sshx", "agent.json") {
		t.Fatal(path)
	}
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	if _, err := loadAgentRegistry(); err == nil {
		t.Fatal("accepted missing home")
	}
}
