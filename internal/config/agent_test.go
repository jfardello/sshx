package config

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func pointer[T any](value T) *T { return &value }

func TestAgentOverridesPresence(t *testing.T) {
	for _, data := range []string{"", "{}", "verbose: false"} {
		got, err := Decode([]byte(data))
		if err != nil || got.Agent != nil {
			t.Fatalf("absent agent: %#v, %v", got, err)
		}
	}
	for _, data := range []string{"agent: {}", "agent: !!map {}"} {
		got, err := Decode([]byte(data))
		if err != nil || got.Agent == nil || !reflect.DeepEqual(*got.Agent, AgentOverrides{}) {
			t.Fatalf("empty agent mapping: %#v, %v", got, err)
		}
	}
	got, err := Decode([]byte("verbose: true\nagent:\n  verbose: false\n  cache-ttl: 0s\n  prompt-helper: ''\n  allow-forwarding: false\n  allow-key-mutations: false\n  socket: ''\n  state-file: ''\n"))
	want := &AgentOverrides{
		Verbose: pointer(false), CacheTTL: pointer(time.Duration(0)), PromptHelper: pointer(""),
		AllowForwarding: pointer(false), AllowKeyMutations: pointer(false), Socket: pointer(""), StateFile: pointer(""),
	}
	if err != nil || !reflect.DeepEqual(got.Agent, want) || got.Verbose == nil || !*got.Verbose {
		t.Fatalf("explicit zero values: %#v, %v; want %#v", got, err, want)
	}
	got, err = Decode([]byte("agent:\n  verbose: true\n  cache-ttl: 1m30s\n  prompt-helper: /nonexistent/helper\n  allow-forwarding: true\n  allow-key-mutations: true\n  socket: /nonexistent/socket\n  state-file: /nonexistent/state\n"))
	want = &AgentOverrides{
		Verbose: pointer(true), CacheTTL: pointer(90 * time.Second), PromptHelper: pointer("/nonexistent/helper"),
		AllowForwarding: pointer(true), AllowKeyMutations: pointer(true), Socket: pointer("/nonexistent/socket"), StateFile: pointer("/nonexistent/state"),
	}
	if err != nil || !reflect.DeepEqual(got.Agent, want) {
		t.Fatalf("populated agent: %#v, %v; want %#v", got, err, want)
	}
	got, err = Decode([]byte("agent: {cache-ttl: 5m}"))
	if err != nil || got.Agent == nil || got.Agent.CacheTTL == nil || *got.Agent.CacheTTL != MaxAgentCacheTTL || got.Agent.Verbose != nil || got.Agent.Socket != nil {
		t.Fatalf("partial agent: %#v, %v", got, err)
	}
}

func TestAgentStrictYAML(t *testing.T) {
	invalid := []string{
		"agent:", "agent: null", "agent: ~", "agent: []", "agent: true", "agent: ''",
		"agent: {}\nagent: {}", "agent: &secret {}", "agent: !secret {}",
		"agent: {}\n---\n{}", "agent: {}\n---", "agent: {",
		"&secret {agent: {}}", "!secret {agent: {}}",
		"? &secret agent\n: {}", "? !secret agent\n: {}",
		"agent:\n  secret-unknown-key: secret-value",
		"agent:\n  <<: {verbose: true}",
		"agent:\n  ? [verbose, socket]\n  : true",
		"agent:\n  ? &secret verbose\n  : true",
		"agent:\n  ? !secret verbose\n  : true",
		"agent:\n  verbose: true\n  verbose: false",
		"agent:\n  socket: /one\n  socket: /two",
		"agent:\n  cache-ttl: 1s\n  cache-ttl: 2s",
		"agent:\n  socket: &secret /path\n  state-file: *secret",
		"agent: *undefined",
	}
	for _, field := range []string{"verbose", "allow-forwarding", "allow-key-mutations"} {
		for _, value := range []string{"null", "~", "''", "'true'", "True", "TRUE", "False", "FALSE", "yes", "no", "on", "off", "1", "0", "[]", "{}", "&secret true", "!secret true", "*undefined"} {
			invalid = append(invalid, fmt.Sprintf("agent:\n  %s: %s", field, value))
		}
	}
	for _, field := range []string{"cache-ttl", "prompt-helper", "socket", "state-file"} {
		for _, value := range []string{"null", "~", "123", "true", "[]", "{}", "&secret /path", "!secret /path", "*undefined"} {
			invalid = append(invalid, fmt.Sprintf("agent:\n  %s: %s", field, value))
		}
	}
	for _, value := range []string{"''", "secret-duration", "'1'", "'999999999999999999999999999999s'", "-1ns", "5m1ns"} {
		invalid = append(invalid, "agent:\n  cache-ttl: "+value)
	}
	for _, field := range []string{"prompt-helper", "socket", "state-file"} {
		for _, value := range []string{"relative-secret", "'/secret/../path'", "'/secret/./path'", "'/secret//path'", "'/secret/path/'", `"/secret/\npath"`, `"/secret/\x00path"`, `"/secret/\u0085path"`} {
			invalid = append(invalid, fmt.Sprintf("agent:\n  %s: %s", field, value))
		}
	}
	for _, data := range invalid {
		t.Run(data, func(t *testing.T) {
			got, err := Decode([]byte(data))
			if err == nil {
				t.Fatal("invalid YAML accepted")
			}
			if !reflect.DeepEqual(got, Overrides{}) {
				t.Fatalf("failed decode returned partial overrides: %#v", got)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatalf("payload leaked in error: %v", err)
			}
		})
	}
}

func TestAgentErrorPaths(t *testing.T) {
	for _, tc := range []struct{ data, want string }{
		{"agent:\n  unknown-sensitive-key: value", "unknown agent key on line 2"},
		{"agent:\n  verbose: true\n  verbose: false", "duplicate key agent.verbose on line 3"},
		{"agent:\n  allow-forwarding: True", "agent.allow-forwarding must be true or false on line 2"},
		{"agent:\n  cache-ttl: sensitive-value", "invalid duration for agent.cache-ttl on line 2"},
		{"agent:\n  socket: null", "invalid type for agent.socket on line 2"},
	} {
		_, err := Decode([]byte(tc.data))
		if err == nil || err.Error() != tc.want {
			t.Fatalf("error = %v; want %q", err, tc.want)
		}
	}
}

func TestValidateAgentCacheTTL(t *testing.T) {
	if MaxAgentCacheTTL != 5*time.Minute {
		t.Fatal("incorrect TTL limit")
	}
	for _, ttl := range []time.Duration{0, time.Nanosecond, time.Minute, MaxAgentCacheTTL} {
		if err := ValidateAgentCacheTTL(ttl); err != nil {
			t.Fatalf("valid TTL %s: %v", ttl, err)
		}
		if err := ValidateAgent(AgentOverrides{CacheTTL: &ttl}); err != nil {
			t.Fatal(err)
		}
	}
	for _, ttl := range []time.Duration{-time.Nanosecond, -time.Minute, MaxAgentCacheTTL + time.Nanosecond, time.Duration(1<<63 - 1)} {
		if err := ValidateAgentCacheTTL(ttl); err == nil {
			t.Fatalf("invalid TTL %s accepted", ttl)
		}
		if err := Validate(Overrides{Agent: &AgentOverrides{CacheTTL: &ttl}}); err == nil {
			t.Fatalf("Validate accepted invalid TTL %s", ttl)
		}
	}
}

func TestValidateAgentPaths(t *testing.T) {
	for _, field := range []string{"prompt-helper", "socket", "state-file"} {
		for _, value := range []string{"", "/", "/nonexistent/path", "/path with spaces", "relative-secret", "/secret/../path", "/secret/./path", "/secret//path", "/secret/path/", "/secret/\x00path", "/secret/\npath", "/secret/\rpath", "/secret/\tpath", "/secret/\x7fpath", "/secret/\u0085path"} {
			t.Run(field+":"+value, func(t *testing.T) {
				agent := AgentOverrides{}
				switch field {
				case "prompt-helper":
					agent.PromptHelper = &value
				case "socket":
					agent.Socket = &value
				case "state-file":
					agent.StateFile = &value
				}
				wantValid := !strings.Contains(value, "secret")
				err := ValidateAgent(agent)
				if (err == nil) != wantValid {
					t.Fatalf("valid = %v, error = %v", wantValid, err)
				}
				if err != nil && (!strings.Contains(err.Error(), "agent."+field) || strings.Contains(err.Error(), "secret")) {
					t.Fatalf("unsafe or missing field diagnostic: %v", err)
				}
				if outer := Validate(Overrides{Agent: &agent}); (outer == nil) != wantValid {
					t.Fatalf("Validate disagrees: %v", outer)
				}
			})
		}
	}
	// Runtime, not config validation, decides whether these combinations make sense.
	if err := ValidateAgent(AgentOverrides{CacheTTL: pointer(time.Minute), PromptHelper: pointer(""), AllowForwarding: pointer(true), AllowKeyMutations: pointer(true)}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateOverrides(t *testing.T) {
	for _, values := range []Overrides{
		{}, {Agent: &AgentOverrides{}}, {CredentialBackend: pointer("auto")},
		{CredentialBackend: pointer("secret-service")}, {CredentialBackend: pointer("gopass")},
		{GopassPrefix: pointer("")}, {GopassPrefix: pointer("valid/prefix/")},
		{Verbose: pointer(false), Options: pointer(""), SecretCollection: pointer("")},
	} {
		if err := Validate(values); err != nil {
			t.Fatalf("valid overrides %#v: %v", values, err)
		}
	}
	for _, values := range []Overrides{
		{CredentialBackend: pointer("")}, {CredentialBackend: pointer("sensitive-backend")},
		{GopassPrefix: pointer("/sensitive-prefix")}, {GopassPrefix: pointer("sensitive/../prefix")},
		{GopassPrefix: pointer("sensitive/./prefix")},
	} {
		if err := Validate(values); err == nil || strings.Contains(err.Error(), "sensitive") {
			t.Fatalf("invalid overrides returned unsafe error: %v", err)
		}
	}
}

func TestDecodeSizeBound(t *testing.T) {
	for _, size := range []int{MaxBytes - 1, MaxBytes, MaxBytes + 1} {
		data := bytes.Repeat([]byte("#"), size)
		_, err := Decode(data)
		if size <= MaxBytes && err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if size > MaxBytes && (err == nil || !strings.Contains(err.Error(), "64 KiB")) {
			t.Fatalf("oversize Decode: %v", err)
		}
	}
}
