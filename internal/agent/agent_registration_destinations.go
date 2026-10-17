package agent

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unicode"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const registrationKnownHostsLimit = 1 << 20

var errRegistrationDestinations = errors.New("invalid registration destinations or known-hosts input")

// RegistrationDestinations builds direct, exact-user edges from only the specified
// known-hosts file. The caller supplies the common port (including the default 22).
// Host labels are metadata; only supported plain public keys establish trust.
func RegistrationDestinations(ctx context.Context, destinations []string, port int, knownHostsPath string) (*DestinationPolicy, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if port < 1 || port > 65535 || len(destinations) == 0 || len(destinations) > maxAgentPolicyEdges {
		return nil, errRegistrationDestinations
	}
	policy := &DestinationPolicy{Version: 1}
	for _, destination := range destinations {
		hop, err := registrationDestination(destination)
		if err != nil {
			return nil, errRegistrationDestinations
		}
		policy.Edges = append(policy.Edges, DestinationEdge{To: hop})
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Follow working symlinks, like the normal known-hosts reader, but check the
	// opened handle. O_NONBLOCK prevents a FIFO substitution from hanging open.
	f, err := os.OpenFile(knownHostsPath, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errRegistrationDestinations
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > registrationKnownHostsLimit {
		return nil, errRegistrationDestinations
	}
	data, err := io.ReadAll(io.LimitReader(f, registrationKnownHostsLimit+1))
	if err != nil || len(data) > registrationKnownHostsLimit {
		return nil, errRegistrationDestinations
	}
	seen := make([]map[string]bool, len(policy.Edges))
	for i := range seen {
		seen[i] = make(map[string]bool)
	}
	for _, raw := range bytes.Split(data, []byte{'\n'}) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		line := strings.Trim(string(raw), " \t\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '\t' })
		marker := ""
		if strings.HasPrefix(fields[0], "@") {
			marker, fields = fields[0], fields[1:]
			if marker != "@revoked" && marker != "@cert-authority" {
				return nil, errRegistrationDestinations
			}
		}
		if len(fields) < 3 {
			return nil, errRegistrationDestinations
		}
		matcher, err := registrationHostMatcher(fields[0])
		if err != nil {
			return nil, errRegistrationDestinations
		}
		blob, err := base64.StdEncoding.DecodeString(fields[2])
		if err != nil {
			return nil, errRegistrationDestinations
		}
		key, err := ssh.ParsePublicKey(blob)
		if err != nil || key.Type() != fields[1] || !bytes.Equal(key.Marshal(), blob) {
			return nil, errRegistrationDestinations
		}
		for i := range policy.Edges {
			hop := &policy.Edges[i].To
			if !matcher(hop.Hostname, port) {
				continue
			}
			if marker == "@revoked" {
				return nil, errRegistrationDestinations
			}
			// CA entries are not pins, even alongside valid plain-key entries.
			if marker == "@cert-authority" {
				continue
			}
			if _, err := parseAgentPolicyHost(blob); err != nil {
				return nil, errRegistrationDestinations
			}
			pin := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
			if !seen[i][pin] {
				seen[i][pin] = true
				hop.HostKeys = append(hop.HostKeys, pin)
				if len(hop.HostKeys) > maxAgentPolicyHostKeys {
					return nil, errRegistrationDestinations
				}
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := compileAgentPolicy(policy); err != nil {
		return nil, errRegistrationDestinations
	}
	return policy, nil
}

func registrationDestination(value string) (DestinationHop, error) {
	user, host, ok := strings.Cut(value, "@")
	if !ok || user == "" || !policyText(user, 256) || strings.Contains(user, "/") || strings.ContainsAny(host, "@/%") {
		return DestinationHop{}, errRegistrationDestinations
	}
	bracketed := strings.HasPrefix(host, "[")
	if bracketed {
		if !strings.HasSuffix(host, "]") {
			return DestinationHop{}, errRegistrationDestinations
		}
		host = host[1 : len(host)-1]
	}
	if host == "" || !policyText(host, 255) {
		return DestinationHop{}, errRegistrationDestinations
	}
	if bracketed || strings.Contains(host, ":") {
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.Is6() || ip.Zone() != "" {
			return DestinationHop{}, errRegistrationDestinations
		}
	}
	return DestinationHop{Username: user, Hostname: host}, nil
}

type registrationPattern struct {
	text   string
	negate bool
}

func registrationHostLookup(host string, port int) string {
	return knownhosts.Normalize(net.JoinHostPort(strings.ToLower(host), strconv.Itoa(port)))
}

// OpenSSH host patterns use * and ? against the entire lookup spelling,
// including brackets and the port, with any matching negation overriding
// positive matches. Hashes use HMAC-SHA1 over the same normalized spelling.
// All patterns are validated, including unrelated and revoked lines.
func registrationHostMatcher(value string) (func(string, int) bool, error) {
	if strings.HasPrefix(value, "|") {
		parts := strings.Split(value, "|")
		if len(parts) != 4 || parts[1] != "1" {
			return nil, errRegistrationDestinations
		}
		salt, e1 := base64.StdEncoding.DecodeString(parts[2])
		hash, e2 := base64.StdEncoding.DecodeString(parts[3])
		if e1 != nil || e2 != nil || len(salt) != sha1.Size || len(hash) != sha1.Size {
			return nil, errRegistrationDestinations
		}
		return func(host string, port int) bool {
			mac := hmac.New(sha1.New, salt)
			mac.Write([]byte(registrationHostLookup(host, port)))
			return hmac.Equal(hash, mac.Sum(nil))
		}, nil
	}
	var patterns []registrationPattern
	for _, text := range strings.Split(value, ",") {
		p := registrationPattern{}
		if strings.HasPrefix(text, "!") {
			p.negate, text = true, text[1:]
		}
		if text == "" || strings.ContainsAny(text, "!|\\/@%") {
			return nil, errRegistrationDestinations
		}
		p.text = text
		host := text
		wildcard := strings.ContainsAny(text, "*?")
		if strings.HasPrefix(text, "[") {
			var port string
			var err error
			host, port, err = net.SplitHostPort(text)
			if err != nil || host == "" || port == "" {
				return nil, errRegistrationDestinations
			}
			if strings.ContainsAny(port, "*?") {
				if strings.Trim(port, "0123456789*?") != "" {
					return nil, errRegistrationDestinations
				}
			} else if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
				return nil, errRegistrationDestinations
			}

		} else if !wildcard && strings.Contains(text, ":") {
			// Bare IPv6 is a default-port host, never an embedded port.
			if ip, err := netip.ParseAddr(text); err != nil || !ip.Is6() {
				return nil, errRegistrationDestinations
			}
		}
		if strings.ContainsAny(host, "[]") || strings.IndexFunc(host, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
			return nil, errRegistrationDestinations
		}
		patterns = append(patterns, p)
	}
	return func(host string, port int) bool {
		lookup := registrationHostLookup(host, port)
		matched := false
		for _, p := range patterns {
			if registrationWildcard(strings.ToLower(p.text), lookup) {
				if p.negate {
					return false
				}
				matched = true
			}
		}
		return matched
	}, nil
}

// Iterative glob matching avoids recursive backtracking on untrusted patterns.
func registrationWildcard(pattern, value string) bool {
	p, v, star, retry := 0, 0, -1, 0
	for v < len(value) {
		if p < len(pattern) && (pattern[p] == '?' || pattern[p] == value[v]) {
			p++
			v++
		} else if p < len(pattern) && pattern[p] == '*' {
			star, retry = p, v
			p++
		} else if star >= 0 {
			retry++
			p, v = star+1, retry
		} else {
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}
