package cli

import (
	"fmt"
	"time"

	"github.com/jfardello/sshx/internal/config"
	"github.com/spf13/cobra"
)

type agentOptions struct {
	verbose, allowForwarding, allowKeyMutations bool
	cacheTTL                                    time.Duration
	promptHelper, socket, stateFile             string
}

func configuredAgentOptions(cmd *cobra.Command, deps dependencies) (agentOptions, error) {
	var file optionOverrides
	if deps.loadConfig != nil {
		var err error
		file, err = deps.loadConfig()
		if err != nil {
			return agentOptions{}, err
		}
	}
	if err := config.Validate(file); err != nil {
		source := file.Source
		if source == "" {
			source = "configuration file"
		}
		return agentOptions{}, fmt.Errorf("%s: %w", source, err)
	}
	var cli config.AgentOverrides
	for _, field := range []struct {
		name  string
		value **bool
	}{
		{"verbose", &cli.Verbose},
		{"allow-forwarding", &cli.AllowForwarding},
		{"allow-key-mutations", &cli.AllowKeyMutations},
	} {
		if flag := cmd.Flag(field.name); flag != nil && flag.Changed {
			value, err := cmd.Flags().GetBool(field.name)
			if err != nil {
				return agentOptions{}, err
			}
			*field.value = &value
		}
	}
	for _, field := range []struct {
		name  string
		value **string
	}{
		{"prompt-helper", &cli.PromptHelper},
		{"socket", &cli.Socket},
		{"state-file", &cli.StateFile},
	} {
		if flag := cmd.Flag(field.name); flag != nil && flag.Changed {
			value, err := cmd.Flags().GetString(field.name)
			if err != nil {
				return agentOptions{}, err
			}
			*field.value = &value
		}
	}
	if flag := cmd.Flag("cache-ttl"); flag != nil && flag.Changed {
		value, err := cmd.Flags().GetDuration("cache-ttl")
		if err != nil {
			return agentOptions{}, err
		}
		cli.CacheTTL = &value
	}
	if err := config.ValidateAgent(cli); err != nil {
		return agentOptions{}, fmt.Errorf("command line: %w", err)
	}
	var result agentOptions
	for _, layer := range []*config.AgentOverrides{file.Agent, &cli} {
		if layer == nil {
			continue
		}
		if layer.Verbose != nil {
			result.verbose = *layer.Verbose
		}
		if layer.AllowForwarding != nil {
			result.allowForwarding = *layer.AllowForwarding
		}
		if layer.AllowKeyMutations != nil {
			result.allowKeyMutations = *layer.AllowKeyMutations
		}
		if layer.CacheTTL != nil {
			result.cacheTTL = *layer.CacheTTL
		}
		if layer.PromptHelper != nil {
			result.promptHelper = *layer.PromptHelper
		}
		if layer.Socket != nil {
			result.socket = *layer.Socket
		}
		if layer.StateFile != nil {
			result.stateFile = *layer.StateFile
		}
	}
	return result, nil
}
