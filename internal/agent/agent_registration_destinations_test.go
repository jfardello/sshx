package agent

import (
	"context"
	"crypto/dsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func registrationHostsFile(t *testing.T, contents string) string {
	t.Helper()
	name := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(name, []byte(contents), 0644); err != nil {
		t.Fatal(err)
	}
	return name
}

func registrationKeyLine(host string, key ssh.PublicKey) string {
	return host + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))) + " secret comment with many words\n"
}

func TestRegistrationDestinationsHosts(t *testing.T) {
	key := bindingSigner(t).PublicKey()
	for _, tc := range []struct {
		name, destination, pattern, label string
		port                              int
	}{
		{"dns", "alice@host.invalid", "host.invalid", "host.invalid", 22},
		{"ipv4", "alice@192.0.2.1", "192.0.2.1", "192.0.2.1", 22},
		{"ipv6", "alice@[2001:db8::1]", "2001:db8::1", "2001:db8::1", 22},
		{"bare ipv6", "alice@2001:db8::1", "2001:db8::1", "2001:db8::1", 22},
		{"dns port", "alice@host.invalid", "[host.invalid]:2222", "host.invalid", 2222},
		{"ipv4 port", "alice@192.0.2.1", "[192.0.2.1]:2222", "192.0.2.1", 2222},
		{"ipv6 port", "alice@[2001:db8::1]", "[2001:db8::1]:2222", "2001:db8::1", 2222},

		{"hashed dns", "alice@host.invalid", knownhosts.HashHostname("host.invalid"), "host.invalid", 22},
		{"hashed ipv6", "alice@[2001:db8::1]", knownhosts.HashHostname("2001:db8::1"), "2001:db8::1", 22},
		{"hashed port", "alice@[2001:db8::1]", knownhosts.HashHostname("[2001:db8::1]:2222"), "2001:db8::1", 2222},
		{"wildcard", "alice@host.invalid", "*.invalid,!excluded.invalid", "host.invalid", 22},
		{"question wildcard", "alice@host.invalid", "h?st.invalid", "host.invalid", 22},
		{"case insensitive", "alice@HOST.invalid", "host.invalid", "HOST.invalid", 22},
		{"maximum port", "alice@host.invalid", "[host.invalid]:65535", "host.invalid", 65535},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := registrationHostsFile(t, "# comment\n\n"+registrationKeyLine(tc.pattern, key))
			policy, err := RegistrationDestinations(context.Background(), []string{tc.destination}, tc.port, path)
			if err != nil {
				t.Fatal(err)
			}
			want := &DestinationPolicy{Version: 1, Edges: []DestinationEdge{{To: DestinationHop{Hostname: tc.label, Username: "alice", HostKeys: []string{strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))}}}}}
			if !reflect.DeepEqual(policy, want) {
				t.Fatalf("policy = %#v, want %#v", policy, want)
			}
			if _, err := compileAgentPolicy(policy); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRegistrationDestinationsExactInput(t *testing.T) {
	key := bindingSigner(t).PublicKey()
	path := registrationHostsFile(t, registrationKeyLine("*", key))
	for _, value := range []string{
		"", "host", "@host", "alice@", "a*@host", "a?@host", "a!@host", "a[b]@host", "a\\b@host", "a b@host", "a\n@host", "a\x00@host",
		"alice@*.invalid", "alice@h?st", "alice@!host", "alice@host name", "alice@host\t", "alice@host\x7f", "alice@host\u2003",
		"alice@host:22", "alice@192.0.2.1:22", "alice@[host]", "alice@[192.0.2.1]", "alice@[2001:db8::1]:2222", "alice@[2001:db8::1", "alice@2001:db8::1]",
		"alice@fe80::1%eth0", "alice@[fe80::1%eth0]", "ssh://alice@host", "alice@ssh://host", "alice@host/path", "alice@@host",
		strings.Repeat("a", 257) + "@host", "alice@" + strings.Repeat("h", 256),
	} {
		t.Run(value, func(t *testing.T) {
			if p, err := RegistrationDestinations(context.Background(), []string{value}, 22, path); err == nil || p != nil {
				t.Fatal("invalid destination accepted")
			}
		})
	}
	for _, port := range []int{-1, 0, 65536} {
		if _, err := RegistrationDestinations(context.Background(), []string{"alice@host"}, port, path); err == nil {
			t.Fatalf("invalid port %d accepted", port)
		}
	}
	if _, err := RegistrationDestinations(context.Background(), []string{"alice@host", "bob@other"}, 2222, registrationHostsFile(t, registrationKeyLine("host,other", key))); err == nil {
		t.Fatal("default-port pins used for nonstandard port")
	}
	if _, err := RegistrationDestinations(context.Background(), nil, 22, path); err == nil {
		t.Fatal("empty destinations accepted")
	}
	user, host := strings.Repeat("u", 256), strings.Repeat("h", 255)
	if _, err := RegistrationDestinations(context.Background(), []string{user + "@" + host}, 22, path); err != nil {
		t.Fatalf("policy text boundary: %v", err)
	}
}

func TestRegistrationDestinationsPinsAndEdges(t *testing.T) {
	first, second := bindingSigner(t).PublicKey(), bindingSigner(t).PublicKey()
	path := registrationHostsFile(t, registrationKeyLine("host", first)+registrationKeyLine("host", second)+registrationKeyLine("host", first))
	policy, err := RegistrationDestinations(context.Background(), []string{"alice@host", "bob@host", "alice@host"}, 22, path)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Edges) != 3 || len(policy.Edges[0].To.HostKeys) != 2 || policy.Edges[1].To.Username != "bob" || !reflect.DeepEqual(policy.Edges[0], policy.Edges[2]) {
		t.Fatalf("unexpected policy: %#v", policy)
	}
	if got := policy.Edges[0].To.HostKeys; got[0] != strings.TrimSpace(string(ssh.MarshalAuthorizedKey(first))) || got[1] != strings.TrimSpace(string(ssh.MarshalAuthorizedKey(second))) {
		t.Fatal("pin order changed")
	}
	values := make([]string, 65)
	for i := range values {
		values[i] = "alice@host"
	}
	if _, err := RegistrationDestinations(context.Background(), values[:64], 22, path); err != nil {
		t.Fatal(err)
	}
	if _, err := RegistrationDestinations(context.Background(), values, 22, path); err == nil {
		t.Fatal("65 edges accepted")
	}
	var lines strings.Builder
	for i := 0; i < 16; i++ {
		lines.WriteString(registrationKeyLine("host", bindingSigner(t).PublicKey()))
	}
	path = registrationHostsFile(t, lines.String())
	if _, err := RegistrationDestinations(context.Background(), []string{"alice@host"}, 22, path); err != nil {
		t.Fatal(err)
	}
	path = registrationHostsFile(t, lines.String()+registrationKeyLine("host", bindingSigner(t).PublicKey()))
	if _, err := RegistrationDestinations(context.Background(), []string{"alice@host"}, 22, path); err == nil {
		t.Fatal("17 pins accepted")
	}
}

func TestRegistrationDestinationsFailClosed(t *testing.T) {
	key := bindingSigner(t).PublicKey()
	valid := registrationKeyLine("host", key)
	weak, err := ssh.NewPublicKey(&rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 1023), E: 65537})
	if err != nil {
		t.Fatal(err)
	}
	dsaKey, err := ssh.NewPublicKey(&dsa.PublicKey{Parameters: dsa.Parameters{P: big.NewInt(23), Q: big.NewInt(11), G: big.NewInt(2)}, Y: big.NewInt(4)})
	if err != nil {
		t.Fatal(err)
	}
	cert := &ssh.Certificate{Key: key, CertType: ssh.HostCert, ValidPrincipals: []string{"host"}, ValidBefore: ssh.CertTimeInfinity}
	if err := cert.SignCert(rand.Reader, bindingSigner(t)); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, contents string }{
		{"empty", ""}, {"no pins", registrationKeyLine("other", key)},
		{"wrong port", registrationKeyLine("[host]:2222", key)},
		{"explicit default", registrationKeyLine("[host]:22", key)},
		{"negated", registrationKeyLine("*,!host", key)},
		{"negation after", registrationKeyLine("!host,*", key)},
		{"revoked", valid + "@revoked " + registrationKeyLine("host", key)},
		{"different revoked key", valid + "@revoked " + registrationKeyLine("host", bindingSigner(t).PublicKey())},
		{"unsupported", valid + registrationKeyLine("host", weak)},
		{"unsupported algorithm", valid + registrationKeyLine("host", dsaKey)},
		{"ca only", "@cert-authority " + valid},
		{"cert only", registrationKeyLine("host", cert)},
		{"cert alongside plain", valid + registrationKeyLine("host", cert)},
		{"malformed unrelated", valid + "unrelated malformed SECRET\n"},
		{"one word", valid + "SECRET\n"},
		{"unknown marker", valid + "@unknown " + registrationKeyLine("other", key)},
		{"bad base64", valid + "other ssh-ed25519 SECRET\n"},
		{"bad hash", valid + registrationKeyLine("|2|SECRET|SECRET", key)},
		{"bad hash sizes", valid + registrationKeyLine("|1|YQ==|YQ==", key)},
		{"bad negation", valid + registrationKeyLine("!", key)},
		{"bad list", valid + registrationKeyLine("other,,else", key)},
		{"bad bracket", valid + registrationKeyLine("[other]", key)},
		{"bad port", valid + registrationKeyLine("[other]:65536", key)},
		{"bad revoked pattern", valid + "@revoked " + registrationKeyLine("!", key)},
		{"type mismatch", valid + "other ssh-rsa " + base64.StdEncoding.EncodeToString(key.Marshal()) + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := registrationHostsFile(t, tc.contents)
			p, err := RegistrationDestinations(context.Background(), []string{"alice@host"}, 22, path)
			if err == nil || p != nil {
				t.Fatal("untrusted input accepted")
			}
			if strings.Contains(err.Error(), path) || strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "secret comment") {
				t.Fatal("error leaks file data")
			}
		})
	}
	for _, contents := range []string{
		valid + "@cert-authority " + valid,
		valid + "@revoked " + registrationKeyLine("other", key),
		valid + registrationKeyLine("other", weak),
		valid + registrationKeyLine("other", cert),
		valid + registrationKeyLine("*,!host", weak),
	} {
		if _, err := RegistrationDestinations(context.Background(), []string{"alice@host"}, 22, registrationHostsFile(t, contents)); err != nil {
			t.Fatalf("unrelated/CA entry rejected: %v", err)
		}
	}
}

func TestRegistrationDestinationsFileAndContext(t *testing.T) {
	key := bindingSigner(t).PublicKey()
	valid := registrationKeyLine("host", key)
	path := registrationHostsFile(t, valid)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := RegistrationDestinations(context.Background(), []string{"alice@host"}, 22, link); err != nil {
		t.Fatalf("working symlink rejected: %v", err)
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := RegistrationDestinations(context.Background(), []string{"alice@host"}, 22, path); err != nil {
		t.Fatalf("reader imposed ownership/permission rules: %v", err)
	}
	for _, name := range []string{t.TempDir(), filepath.Join(t.TempDir(), "missing")} {
		if _, err := RegistrationDestinations(context.Background(), []string{"alice@host"}, 22, name); err == nil || strings.Contains(err.Error(), name) {
			t.Fatal("nonregular/missing file accepted or path leaked")
		}
	}
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := RegistrationDestinations(context.Background(), []string{"alice@host"}, 22, fifo)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("FIFO open blocked")
	}
	boundary := valid + "#" + strings.Repeat("x", registrationKnownHostsLimit-len(valid)-1)
	if _, err := RegistrationDestinations(context.Background(), []string{"alice@host"}, 22, registrationHostsFile(t, boundary)); err != nil {
		t.Fatalf("1 MiB rejected: %v", err)
	}
	if _, err := RegistrationDestinations(context.Background(), []string{"alice@host"}, 22, registrationHostsFile(t, boundary+"x")); err == nil {
		t.Fatal("oversized file accepted")
	}
	if p, err := RegistrationDestinations(&registrationCancelContext{Context: context.Background()}, []string{"alice@host"}, 22, path); p != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation during processing: %v, %v", p, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if p, err := RegistrationDestinations(ctx, []string{"alice@host"}, 22, path); p != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context: %v, %v", p, err)
	}
	ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if _, err := RegistrationDestinations(ctx, []string{"alice@host"}, 22, path); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired context: %v", err)
	}
}

// Cancel after the initial checks, once the reader starts processing lines.
// This makes cancellation during the operation deterministic without timing races.
type registrationCancelContext struct {
	context.Context
	checks int
}

func (c *registrationCancelContext) Err() error {
	c.checks++
	if c.checks >= 3 {
		return context.Canceled
	}
	return nil
}

func TestRegistrationDestinationsOpenSSHMatching(t *testing.T) {
	sshKeygen, keygenErr := exec.LookPath("ssh-keygen")
	key := bindingSigner(t).PublicKey()
	for _, tc := range []struct {
		name, pattern, host, lookup string
		port                        int
		match, revoked              bool
	}{
		{"dns bare default", "host", "host", "host", 22, true, false},
		{"dns bracket default", "[host]:22", "host", "host", 22, false, false},
		{"dns bare default revoked", "host", "host", "host", 22, true, true},
		{"dns bracket default revoked", "[host]:22", "host", "host", 22, false, true},
		{"dns hash bracket default", knownhosts.HashHostname("[host]:22"), "host", "host", 22, false, false},
		{"dns hash bracket default revoked", knownhosts.HashHostname("[host]:22"), "host", "host", 22, false, true},
		{"mixed case hash default", knownhosts.HashHostname("host.invalid"), "HOST.invalid", "host.invalid", 22, true, false},
		{"mixed case hash port", knownhosts.HashHostname("[host.invalid]:2222"), "HOST.invalid", "[host.invalid]:2222", 2222, true, false},
		{"mixed case hash default revoked", knownhosts.HashHostname("host.invalid"), "HOST.invalid", "host.invalid", 22, true, true},
		{"mixed case hash port revoked", knownhosts.HashHostname("[host.invalid]:2222"), "HOST.invalid", "[host.invalid]:2222", 2222, true, true},
		{"uppercase hash default", knownhosts.HashHostname("HOST.invalid"), "HOST.invalid", "host.invalid", 22, false, false},
		{"uppercase hash port", knownhosts.HashHostname("[HOST.invalid]:2222"), "HOST.invalid", "[host.invalid]:2222", 2222, false, false},
		{"all ports wildcard", "*", "host", "[host]:2222", 2222, true, false},
		{"port suffix wildcard", "*:2222", "host", "[host]:2222", 2222, true, false},
		{"bracket wildcard", "[*]:2222", "host", "[host]:2222", 2222, true, false},
		{"host wildcard", "[h?st]:2222", "host", "[host]:2222", 2222, true, false},
		{"port wildcard", "[host]:22??", "host", "[host]:2222", 2222, true, false},
		{"any port", "[host]:*", "host", "[host]:2222", 2222, true, false},
		{"wrong wildcard port", "[*]:2223", "host", "[host]:2222", 2222, false, false},
		{"unbracketed exact", "host", "host", "[host]:2222", 2222, false, false},
		{"unbracketed suffix", "*.invalid", "host.invalid", "[host.invalid]:2222", 2222, false, false},
		{"exact negation", "*,![host]:2222", "host", "[host]:2222", 2222, false, false},
		{"wildcard negation", "*,![h?st]:*", "host", "[host]:2222", 2222, false, false},
		{"negation first", "![*]:2222,*", "host", "[host]:2222", 2222, false, false},
		{"other port negation", "*,![host]:2223", "host", "[host]:2222", 2222, true, false},
		{"bare negation", "*,!host", "host", "[host]:2222", 2222, true, false},
		{"revoked all ports", "*", "host", "[host]:2222", 2222, true, true},
		{"revoked port wildcard", "[*]:22??", "host", "[host]:2222", 2222, true, true},
		{"revoked excluded", "*,![host]:2222", "host", "[host]:2222", 2222, false, true},
		{"ipv6 bare", "2001:db8::1", "2001:db8::1", "2001:db8::1", 22, true, false},
		{"ipv6 bracket default", "[2001:db8::1]:22", "2001:db8::1", "2001:db8::1", 22, false, false},
		{"ipv6 bare default revoked", "2001:db8::1", "2001:db8::1", "2001:db8::1", 22, true, true},
		{"ipv6 bracket default revoked", "[2001:db8::1]:22", "2001:db8::1", "2001:db8::1", 22, false, true},
		{"ipv6 hash bracket default", knownhosts.HashHostname("[2001:db8::1]:22"), "2001:db8::1", "2001:db8::1", 22, false, false},
		{"ipv6 hash bracket default revoked", knownhosts.HashHostname("[2001:db8::1]:22"), "2001:db8::1", "2001:db8::1", 22, false, true},
		{"ipv6 hash bare default revoked", knownhosts.HashHostname("2001:db8::1"), "2001:db8::1", "2001:db8::1", 22, true, true},
		{"ipv6 bare wrong port", "2001:db8::1", "2001:db8::1", "[2001:db8::1]:2222", 2222, false, false},
		{"ipv6 bare wildcard", "2001:db8::*", "2001:db8::1", "2001:db8::1", 22, true, false},
		{"ipv6 bracket wildcard", "[2001:db8::*]:2222", "2001:db8::1", "[2001:db8::1]:2222", 2222, true, false},
		{"ipv6 wildcard port", "[2001:db8::?]:*", "2001:db8::1", "[2001:db8::1]:2222", 2222, true, false},
		{"ipv6 negated", "*,![2001:db8::*]:*", "2001:db8::1", "[2001:db8::1]:2222", 2222, false, false},
		{"ipv6 revoked", "[2001:db8::*]:*", "2001:db8::1", "[2001:db8::1]:2222", 2222, true, true},
		{"ipv6 hash default", knownhosts.HashHostname("2001:db8::1"), "2001:db8::1", "2001:db8::1", 22, true, false},
		{"ipv6 hash port", knownhosts.HashHostname("[2001:db8::1]:2222"), "2001:db8::1", "[2001:db8::1]:2222", 2222, true, false},
		{"ipv6 hash wrong port", knownhosts.HashHostname("2001:db8::1"), "2001:db8::1", "[2001:db8::1]:2222", 2222, false, false},
		{"ipv6 hash revoked", knownhosts.HashHostname("[2001:db8::1]:2222"), "2001:db8::1", "[2001:db8::1]:2222", 2222, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if lookup := registrationHostLookup(tc.host, tc.port); lookup != tc.lookup {
				t.Fatalf("canonical lookup = %q, want %q", lookup, tc.lookup)
			}
			matcher, err := registrationHostMatcher(tc.pattern)
			if err != nil {
				t.Fatal(err)
			}
			if got := matcher(tc.host, tc.port); got != tc.match {
				t.Fatalf("matcher = %v, want %v", got, tc.match)
			}
			line := registrationKeyLine(tc.pattern, key)
			if tc.revoked {
				line = "@revoked " + line
			}
			path := registrationHostsFile(t, line)
			if keygenErr == nil {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				output, err := exec.CommandContext(ctx, sshKeygen, "-F", tc.lookup, "-f", path).CombinedOutput()
				if err != nil {
					var exit *exec.ExitError
					if !errors.As(err, &exit) || exit.ExitCode() != 1 || len(output) != 0 {
						t.Fatalf("ssh-keygen lookup failed: %v: %s", err, output)
					}
				}
				if got := err == nil; got != tc.match {
					t.Fatalf("ssh-keygen match = %v, matcher = %v: %s", got, tc.match, output)
				}
			} else {
				t.Log("ssh-keygen unavailable; differential check skipped")
			}
			if tc.revoked {
				// A supported wildcard pin must never mask a matching revocation,
				// including hashed revocations of a mixed-case destination.
				path = registrationHostsFile(t, registrationKeyLine("*", bindingSigner(t).PublicKey())+line)
			}
			policy, err := RegistrationDestinations(context.Background(), []string{"alice@" + tc.host}, tc.port, path)
			wantAccepted := tc.match
			if tc.revoked {
				wantAccepted = !tc.match
			}
			if (err == nil) != wantAccepted || (policy != nil) != wantAccepted {
				t.Fatalf("builder accepted = %v, want %v: %v", err == nil, wantAccepted, err)
			}
			if wantAccepted && policy.Edges[0].To.Hostname != tc.host {
				t.Fatalf("stored hostname = %q, want original %q", policy.Edges[0].To.Hostname, tc.host)
			}
		})
	}
}

func TestRegistrationWildcard(t *testing.T) {
	for _, tc := range []struct {
		pattern, value string
		match          bool
	}{
		{"*", "", true}, {"a*", "a", true}, {"*a", "ba", true}, {"a?", "a", false},
		{"*a*b", "axayb", true}, {"*a*b", "axayc", false}, {"*.invalid", "a.b.invalid", true},
	} {
		if got := registrationWildcard(tc.pattern, tc.value); got != tc.match {
			t.Errorf("match(%q, %q) = %v", tc.pattern, tc.value, got)
		}
	}
}
