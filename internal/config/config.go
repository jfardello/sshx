package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode"

	"go.yaml.in/yaml/v3"
)

const maxConfigBytes = 64 << 10
const MaxBytes = maxConfigBytes

const MaxAgentCacheTTL = 5 * time.Minute

// A nil field is absent; a pointer to false or an empty string is an override.
type Overrides struct {
	CredentialBackend *string         `yaml:"credential-backend"`
	SecretCollection  *string         `yaml:"secret-collection"`
	GopassPrefix      *string         `yaml:"gopass-prefix"`
	Verbose           *bool           `yaml:"verbose"`
	Options           *string         `yaml:"options"`
	Agent             *AgentOverrides `yaml:"agent"`
	SSH               *SSHOverrides   `yaml:"ssh"`
	Source            string          `yaml:"-"`
}

// SSHOverrides applies only to password SSH and its root shorthand.
type SSHOverrides struct {
	UI           *string `yaml:"ui"`
	PromptHelper *string `yaml:"prompt-helper"`
}

// Pointer fields distinguish absent settings from explicit false, zero, or empty values.
type AgentOverrides struct {
	Verbose           *bool          `yaml:"verbose"`
	CacheTTL          *time.Duration `yaml:"cache-ttl"`
	PromptHelper      *string        `yaml:"prompt-helper"`
	AllowForwarding   *bool          `yaml:"allow-forwarding"`
	AllowKeyMutations *bool          `yaml:"allow-key-mutations"`
	Socket            *string        `yaml:"socket"`
	StateFile         *string        `yaml:"state-file"`
}

type optionOverrides = Overrides

func resolveConfigPath(home, xdg string) (string, error) {
	if filepath.IsAbs(xdg) {
		return filepath.Join(xdg, "sshx", "config.yaml"), nil
	}
	if home == "" {
		return "", errors.New("cannot locate sshx configuration: home directory is unavailable")
	}
	return filepath.Join(home, ".config", "sshx", "config.yaml"), nil
}

func loadUserConfig() (optionOverrides, error) {
	xdg := os.Getenv("XDG_CONFIG_HOME")
	var home string
	if !filepath.IsAbs(xdg) {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			return optionOverrides{}, fmt.Errorf("locate sshx configuration: %w", err)
		}
	}
	name, err := resolveConfigPath(home, xdg)
	if err != nil {
		return optionOverrides{}, err
	}
	return loadConfig(name)
}

func LoadUser() (Overrides, error)                 { return loadUserConfig() }
func Load(name string) (Overrides, error)          { return loadConfig(name) }
func Decode(data []byte) (Overrides, error)        { return decodeConfig(data) }
func ResolvePath(home, xdg string) (string, error) { return resolveConfigPath(home, xdg) }

// A dangling symlink (including an ancestor) is an error, not an absent config.
func missingConfig(name string) bool {
	for current := filepath.Clean(name); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				_, err = os.Stat(current)
				return err == nil
			}
			return true
		}
		if !errors.Is(err, os.ErrNotExist) {
			return false
		}
		if filepath.Dir(current) == current {
			return true
		}
	}
}

func loadConfig(name string) (optionOverrides, error) {
	info, err := os.Stat(name)
	if errors.Is(err, os.ErrNotExist) && missingConfig(name) {
		return optionOverrides{}, nil
	}
	if err != nil {
		return optionOverrides{}, fmt.Errorf("read configuration %q: %w", name, err)
	}
	if !info.Mode().IsRegular() {
		return optionOverrides{}, fmt.Errorf("configuration %q must be a regular file", name)
	}
	// Nonblocking open avoids hanging if a checked file is replaced by a FIFO.
	f, err := os.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return optionOverrides{}, fmt.Errorf("open configuration %q: %w", name, err)
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil {
		return optionOverrides{}, fmt.Errorf("inspect configuration %q: %w", name, err)
	}
	if !info.Mode().IsRegular() {
		return optionOverrides{}, fmt.Errorf("configuration %q must be a regular file", name)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return optionOverrides{}, fmt.Errorf("read configuration %q: %w", name, err)
	}
	if len(data) > maxConfigBytes {
		return optionOverrides{}, fmt.Errorf("configuration %q exceeds 64 KiB", name)
	}
	config, err := decodeConfig(data)
	if err != nil {
		return optionOverrides{}, fmt.Errorf("configuration %q: %w", name, err)
	}
	config.Source = fmt.Sprintf("configuration file %q", name)
	return config, nil
}

func decodeConfig(data []byte) (optionOverrides, error) {
	var result optionOverrides
	if len(data) > maxConfigBytes {
		return result, errors.New("configuration exceeds 64 KiB")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	err := decoder.Decode(&document)
	if errors.Is(err, io.EOF) {
		return result, nil
	}
	// Parser errors can include input values. Do not include raw YAML in diagnostics.
	if err != nil {
		return result, errors.New("invalid YAML syntax")
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return result, errors.New("expected exactly one YAML document")
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return result, errors.New("expected a YAML mapping")
	}
	root := document.Content[0]
	if err := validateMapping(root, "configuration"); err != nil {
		return result, err
	}
	if err := root.Decode(&result); err != nil {
		return optionOverrides{}, errors.New("invalid configuration fields")
	}
	if err := Validate(result); err != nil {
		return optionOverrides{}, err
	}
	return result, nil
}

// Validate checks configuration values without command-specific or filesystem checks.
func Validate(values Overrides) error {
	if values.CredentialBackend != nil {
		switch *values.CredentialBackend {
		case "auto", "secret-service", "gopass":
		default:
			return errors.New("invalid credential backend (expected auto, secret-service, or gopass)")
		}
	}
	if values.GopassPrefix != nil && *values.GopassPrefix != "" {
		if _, err := normalizeGopassPrefix(*values.GopassPrefix); err != nil {
			return fmt.Errorf("invalid gopass-prefix: %w", err)
		}
	}
	if values.SSH != nil {
		if err := ValidateSSH(*values.SSH); err != nil {
			return err
		}
	}
	if values.Agent != nil {
		return ValidateAgent(*values.Agent)
	}
	return nil
}

func ValidateSSH(values SSHOverrides) error {
	if values.UI != nil && *values.UI != "none" && *values.UI != "shell" && *values.UI != "desktop" {
		return errors.New("ssh.ui must be none, shell, or desktop")
	}
	if values.PromptHelper != nil && *values.PromptHelper != "" {
		value := *values.PromptHelper
		if !filepath.IsAbs(value) || filepath.Clean(value) != value || strings.ContainsFunc(value, unicode.IsControl) {
			return errors.New("ssh.prompt-helper must be empty or an absolute clean path without control characters")
		}
	}
	return nil
}

func validateOverrides(values optionOverrides) error { return Validate(values) }

// ValidateAgentCacheTTL accepts zero (no caching) through MaxAgentCacheTTL.
func ValidateAgentCacheTTL(ttl time.Duration) error {
	if ttl < 0 || ttl > MaxAgentCacheTTL {
		return errors.New("agent.cache-ttl must be between zero and five minutes")
	}
	return nil
}

// ValidateAgent checks scalar values only; runtime owns path existence and trust.
func ValidateAgent(values AgentOverrides) error {
	if values.CacheTTL != nil {
		if err := ValidateAgentCacheTTL(*values.CacheTTL); err != nil {
			return err
		}
	}
	for _, field := range []struct {
		name  string
		value *string
	}{
		{"prompt-helper", values.PromptHelper},
		{"socket", values.Socket},
		{"state-file", values.StateFile},
	} {
		if field.value == nil || *field.value == "" {
			continue
		}
		value := *field.value
		if !filepath.IsAbs(value) || filepath.Clean(value) != value || strings.ContainsFunc(value, unicode.IsControl) {
			return fmt.Errorf("agent.%s must be empty or an absolute clean path without control characters", field.name)
		}
	}
	return nil
}

// Only known schema names are ever incorporated into diagnostics.
func validateMapping(node *yaml.Node, scope string) error {
	if node.Kind != yaml.MappingNode || node.Tag != "!!map" || node.Anchor != "" {
		return fmt.Errorf("invalid mapping for %s on line %d", scope, node.Line)
	}
	seen := make(map[string]bool)
	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Anchor != "" {
			return fmt.Errorf("invalid %s key on line %d", scope, key.Line)
		}
		expected := ""
		if scope == "configuration" {
			switch key.Value {
			case "credential-backend", "secret-collection", "gopass-prefix", "options":
				expected = "!!str"
			case "verbose":
				expected = "!!bool"
			case "agent", "ssh":
				expected = "!!map"
			}
		} else if scope == "ssh" {
			switch key.Value {
			case "ui", "prompt-helper":
				expected = "!!str"
			}
		} else {
			switch key.Value {
			case "cache-ttl", "prompt-helper", "socket", "state-file":
				expected = "!!str"
			case "verbose", "allow-forwarding", "allow-key-mutations":
				expected = "!!bool"
			}
		}
		if expected == "" {
			return fmt.Errorf("unknown %s key on line %d", scope, key.Line)
		}
		name := key.Value
		if scope != "configuration" {
			name = scope + "." + name
		}
		if seen[key.Value] {
			return fmt.Errorf("duplicate key %s on line %d", name, key.Line)
		}
		seen[key.Value] = true
		if expected == "!!map" {
			if err := validateMapping(value, name); err != nil {
				return err
			}
			continue
		}
		if value.Kind != yaml.ScalarNode || value.Tag != expected || value.Anchor != "" {
			return fmt.Errorf("invalid type for %s on line %d", name, value.Line)
		}
		if expected == "!!bool" && value.Value != "true" && value.Value != "false" {
			return fmt.Errorf("%s must be true or false on line %d", name, value.Line)
		}
		if name == "agent.cache-ttl" {
			if _, err := time.ParseDuration(value.Value); err != nil {
				return fmt.Errorf("invalid duration for %s on line %d", name, value.Line)
			}
		}
	}
	return nil
}

func normalizeGopassPrefix(value string) (string, error) {
	if strings.HasPrefix(value, "/") {
		return "", errors.New("gopass prefix must be relative")
	}
	trimmed := strings.TrimRight(value, "/")
	for _, component := range strings.Split(trimmed, "/") {
		if component == "." || component == ".." {
			return "", fmt.Errorf("gopass prefix cannot contain %q components", component)
		}
	}
	return path.Clean(trimmed), nil
}
