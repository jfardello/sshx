package config

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jfardello/sshx/internal/fileupdate"
	"go.yaml.in/yaml/v3"
)

// UserPath locates the user configuration without reading it.
func UserPath() (string, error) {
	xdg := os.Getenv("XDG_CONFIG_HOME")
	var home string
	if !filepath.IsAbs(xdg) {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			return "", errors.New("cannot locate sshx configuration: home directory is unavailable")
		}
	}
	return resolveConfigPath(home, xdg)
}

// Setting is a canonical setting and its origin ("file" or "default").
type Setting struct {
	Key    string
	Value  string
	Source string
}

var settingKeys = []string{
	"credential-backend", "secret-collection", "gopass-prefix", "verbose", "options",
	"agent.verbose", "agent.cache-ttl", "agent.prompt-helper", "agent.allow-forwarding",
	"agent.allow-key-mutations", "agent.socket", "agent.state-file",
	"ssh.ui", "ssh.prompt-helper",
}

// NormalizeKey accepts only known settings, with underscores as hyphen aliases.
func NormalizeKey(key string) (string, error) {
	key = strings.ReplaceAll(key, "_", "-")
	for _, known := range settingKeys {
		if key == known {
			return key, nil
		}
	}
	return "", fmt.Errorf("unknown configuration setting: %w", fileupdate.ErrInvalid)
}

// Settings reads with Load's compatibility rules. Effective queries fill only
// built-in defaults, not environment or command-line overrides.
func Settings(name string, effective bool) ([]Setting, error) {
	values, err := Load(name)
	if err != nil {
		return nil, err
	}
	return settingsFor(values, effective), nil
}

func settingsFor(values Overrides, effective bool) []Setting {
	var result []Setting
	add := func(key, value string, present bool) {
		if !present && !effective {
			return
		}
		source := "default"
		if present {
			source = "file"
		}
		result = append(result, Setting{key, value, source})
	}
	str := func(key string, value *string, fallback string) {
		if value != nil {
			add(key, *value, true)
		} else {
			add(key, fallback, false)
		}
	}
	boolean := func(key string, value *bool) {
		add(key, strconv.FormatBool(value != nil && *value), value != nil)
	}
	str("credential-backend", values.CredentialBackend, "auto")
	str("secret-collection", values.SecretCollection, "")
	str("gopass-prefix", values.GopassPrefix, "")
	boolean("verbose", values.Verbose)
	str("options", values.Options, "")
	agent := AgentOverrides{}
	if values.Agent != nil {
		agent = *values.Agent
	}
	boolean("agent.verbose", agent.Verbose)
	ttl := time.Duration(0)
	if agent.CacheTTL != nil {
		ttl = *agent.CacheTTL
	}
	add("agent.cache-ttl", ttl.String(), agent.CacheTTL != nil)
	str("agent.prompt-helper", agent.PromptHelper, "")
	boolean("agent.allow-forwarding", agent.AllowForwarding)
	boolean("agent.allow-key-mutations", agent.AllowKeyMutations)
	str("agent.socket", agent.Socket, "")
	str("agent.state-file", agent.StateFile, "")
	ssh := SSHOverrides{}
	if values.SSH != nil {
		ssh = *values.SSH
	}
	str("ssh.ui", ssh.UI, "none")
	str("ssh.prompt-helper", ssh.PromptHelper, "")
	return result
}

func settingNode(key, value string) (*yaml.Node, error) {
	tag := "!!str"
	switch key {
	case "verbose", "agent.verbose", "agent.allow-forwarding", "agent.allow-key-mutations":
		if value != "true" && value != "false" {
			return nil, fmt.Errorf("%s must be true or false: %w", key, fileupdate.ErrInvalid)
		}
		tag = "!!bool"
	case "agent.cache-ttl":
		ttl, err := time.ParseDuration(value)
		if err != nil {
			return nil, fmt.Errorf("invalid duration for %s: %w", key, fileupdate.ErrInvalid)
		}
		value = ttl.String()
	}
	node := &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: value}
	root := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	mapping, leaf := editMapping(root, key, true)
	mapping.Content = append(mapping.Content, stringNode(leaf), node)
	data, err := yaml.Marshal(root)
	if err != nil {
		return nil, fileupdate.ErrInvalid
	}
	if _, err := Decode(data); err != nil {
		return nil, fmt.Errorf("%w: %s", fileupdate.ErrInvalid, err)
	}
	return node, nil
}

func stringNode(value string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
}

// Set validates the CLI value before starting a filesystem transaction.
func Set(ctx context.Context, name, key, value string) (fileupdate.Publication, error) {
	key, err := NormalizeKey(key)
	if err != nil {
		return fileupdate.Unchanged, err
	}
	node, err := settingNode(key, value)
	if err != nil {
		return fileupdate.Unchanged, err
	}
	return editSetting(ctx, name, key, node)
}

// Unset removes a stored override, leaving built-in defaults implicit.
func Unset(ctx context.Context, name, key string) (fileupdate.Publication, error) {
	key, err := NormalizeKey(key)
	if err != nil {
		return fileupdate.Unchanged, err
	}
	return editSetting(ctx, name, key, nil)
}

func editMapping(root *yaml.Node, key string, create bool) (*yaml.Node, string) {
	section, leaf, nested := strings.Cut(key, ".")
	if !nested {
		return root, key
	}
	for i := 0; i < len(root.Content); i += 2 {
		if root.Content[i].Value == section {
			return root.Content[i+1], leaf
		}
	}
	if !create {
		return nil, leaf
	}
	mapping := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	root.Content = append(root.Content, stringNode(section), mapping)
	return mapping, leaf
}

func editSetting(ctx context.Context, name, key string, replacement *yaml.Node) (fileupdate.Publication, error) {
	return fileupdate.Update(ctx, name, fileupdate.Policy{MaxBytes: MaxBytes, Private: false}, func(data []byte, _ bool) ([]byte, bool, error) {
		values, err := Decode(data)
		if err != nil {
			return nil, false, err
		}
		for _, stored := range settingsFor(values, false) {
			if stored.Key == key && replacement != nil && stored.Value == replacement.Value {
				return nil, false, nil
			}
		}
		var doc yaml.Node
		err = yaml.NewDecoder(bytes.NewReader(data)).Decode(&doc)
		if errors.Is(err, io.EOF) {
			// The emitter expects each comment marker at column zero. Only
			// remove indentation before it, retaining text and blank paragraphs.
			lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
			for i := range lines {
				lines[i] = strings.TrimLeft(lines[i], " \t")
			}
			root := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", HeadComment: strings.Trim(strings.Join(lines, "\n"), "\n")}
			doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{root}}
		} else if err != nil {
			return nil, false, errors.New("invalid YAML syntax")
		}
		mapping, leaf := editMapping(doc.Content[0], key, replacement != nil)
		index := -1
		if mapping != nil {
			for i := 0; i < len(mapping.Content); i += 2 {
				if mapping.Content[i].Value == leaf {
					index = i
					break
				}
			}
		}
		if replacement == nil {
			if index < 0 {
				return nil, false, nil
			}
			// Keep comments from removed nodes, including on the last agent key.
			var comments []string
			for _, node := range mapping.Content[index : index+2] {
				for _, comment := range []string{node.HeadComment, node.LineComment, node.FootComment} {
					if comment != "" {
						comments = append(comments, comment)
					}
				}
			}
			mapping.Content = append(mapping.Content[:index], mapping.Content[index+2:]...)
			if len(mapping.Content) == 0 {
				// yaml's block emitter places an empty map at column zero when
				// it has foot comments; an explicit flow map remains valid YAML.
				mapping.Style = yaml.FlowStyle
				if mapping.LineComment != "" {
					comments = append(comments, mapping.LineComment)
					mapping.LineComment = ""
				}
				if strings.Contains(key, ".") {
					root := doc.Content[0]
					for i := 0; i < len(root.Content); i += 2 {
						if root.Content[i+1] == mapping && root.Content[i].LineComment != "" {
							comments = append(comments, root.Content[i].LineComment)
							root.Content[i].LineComment = ""
						}
					}
				}
			}
			if index < len(mapping.Content) {
				next := mapping.Content[index]
				next.HeadComment = strings.Join(append(comments, next.HeadComment), "\n")
			} else {
				mapping.FootComment = strings.Join(append(comments, mapping.FootComment), "\n")
			}
		} else if index >= 0 {
			// Mutate the scalar in place so its comments and quoting survive.
			old := mapping.Content[index+1]
			old.Tag, old.Value = replacement.Tag, replacement.Value
		} else {
			mapping.Content = append(mapping.Content, stringNode(leaf), replacement)
		}
		next, err := yaml.Marshal(&doc)
		if err != nil {
			return nil, false, errors.New("cannot encode configuration")
		}
		if _, err := Decode(next); err != nil {
			return nil, false, err
		}
		return next, true, nil
	})
}
