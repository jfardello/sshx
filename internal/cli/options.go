package cli

import (
	"fmt"
	"strings"
)

func validateOverrides(values optionOverrides) error {
	if values.CredentialBackend != nil {
		if _, err := parseCredentialBackend(*values.CredentialBackend); err != nil {
			return fmt.Errorf("invalid credential backend (expected auto, secret-service, or gopass)")
		}
	}
	if values.GopassPrefix != nil && *values.GopassPrefix != "" {
		if _, err := normalizeGopassPrefix(*values.GopassPrefix); err != nil {
			return fmt.Errorf("invalid gopass-prefix: %w", err)
		}
	}
	return nil
}

func configuredCommandOptions(invocation commandOptions, cli optionOverrides, deps dependencies) (commandOptions, error) {
	var file optionOverrides
	if deps.loadConfig != nil {
		var err error
		file, err = deps.loadConfig()
		if err != nil {
			return commandOptions{}, err
		}
	}
	return mergeCommandOptions(file, cli, invocation)
}

func mergeCommandOptions(file, cli optionOverrides, invocation commandOptions) (commandOptions, error) {
	result := invocation
	result.credentialBackend = credentialBackendAuto
	sources := map[string]string{"credential-backend": "built-in default", "secret-collection": "built-in default", "gopass-prefix": "built-in default"}
	for index, layer := range []optionOverrides{file, cli} {
		source := "command line"
		if index == 0 {
			source = file.Source
			if source == "" {
				source = "configuration file"
			}
		}
		if err := validateOverrides(layer); err != nil {
			return commandOptions{}, fmt.Errorf("%s: %w", source, err)
		}
		if layer.CredentialBackend != nil {
			result.credentialBackend = credentialBackend(*layer.CredentialBackend)
			sources["credential-backend"] = source
		}
		if layer.SecretCollection != nil {
			result.secretCollection = *layer.SecretCollection
			sources["secret-collection"] = source
		}
		if layer.GopassPrefix != nil {
			result.gopassPrefix = *layer.GopassPrefix
			if result.gopassPrefix != "" {
				result.gopassPrefix, _ = normalizeGopassPrefix(result.gopassPrefix)
			}
			sources["gopass-prefix"] = source
		}
		if layer.Verbose != nil {
			result.verbose = *layer.Verbose
		}
		if layer.Options != nil {
			result.programOptions = strings.Fields(*layer.Options)
		}
	}
	result.credentialBackendSet = cli.CredentialBackend != nil
	final, err := finalizeCommandOptions(result)
	if err != nil {
		return commandOptions{}, fmt.Errorf("%w (credential-backend: %s; secret-collection: %s; gopass-prefix: %s)", err, sources["credential-backend"], sources["secret-collection"], sources["gopass-prefix"])
	}
	return final, nil
}
