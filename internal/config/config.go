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

	"go.yaml.in/yaml/v3"
)

const maxConfigBytes = 64 << 10
const MaxBytes = maxConfigBytes

// A nil field is absent; a pointer to false or an empty string is an override.
type Overrides struct {
	CredentialBackend *string `yaml:"credential-backend"`
	SecretCollection  *string `yaml:"secret-collection"`
	GopassPrefix      *string `yaml:"gopass-prefix"`
	Verbose           *bool   `yaml:"verbose"`
	Options           *string `yaml:"options"`
	Source            string  `yaml:"-"`
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
	if root.Anchor != "" || root.Tag != "!!map" {
		return result, errors.New("YAML anchors and custom tags are not supported")
	}
	seen := make(map[string]bool)
	for i := 0; i < len(root.Content); i += 2 {
		key, value := root.Content[i], root.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Anchor != "" {
			return result, fmt.Errorf("invalid configuration key on line %d", key.Line)
		}
		expected := "!!str"
		switch key.Value {
		case "credential-backend", "secret-collection", "gopass-prefix", "options":
		case "verbose":
			expected = "!!bool"
		default:
			return result, fmt.Errorf("unknown configuration key on line %d", key.Line)
		}
		if seen[key.Value] {
			return result, fmt.Errorf("duplicate configuration key %q on line %d", key.Value, key.Line)
		}
		seen[key.Value] = true
		if value.Kind != yaml.ScalarNode || value.Tag != expected || value.Anchor != "" {
			return result, fmt.Errorf("invalid type for %s on line %d", key.Value, value.Line)
		}
		if key.Value == "verbose" && value.Value != "true" && value.Value != "false" {
			return result, errors.New("verbose must be true or false")
		}
	}
	if err := root.Decode(&result); err != nil {
		return optionOverrides{}, errors.New("invalid configuration fields")
	}
	if err := validateOverrides(result); err != nil {
		return optionOverrides{}, err
	}
	return result, nil
}

func validateOverrides(values optionOverrides) error {
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
