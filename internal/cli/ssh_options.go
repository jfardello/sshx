package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/jfardello/sshx/internal/config"
)

// SSH has an optional query when UI is enabled. SCP and credential listing retain
// their existing parsers. Once a remote command starts, its tokens are untouched.
func parseConfiguredSSHOptions(args []string, deps dependencies) (commandOptions, error) {
	invocation, cli, err := parseSSHOverrides(args)
	if err != nil {
		return commandOptions{}, err
	}
	var file optionOverrides
	if deps.loadConfig != nil {
		file, err = deps.loadConfig()
		if err != nil {
			return commandOptions{}, err
		}
	}
	result, err := mergeCommandOptions(file, cli, invocation)
	if err != nil {
		return commandOptions{}, err
	}
	result.ui = "none"
	for _, layer := range []optionOverrides{file, cli} {
		if layer.SSH == nil {
			continue
		}
		if layer.SSH.UI != nil {
			result.ui = *layer.SSH.UI
		}
		if layer.SSH.PromptHelper != nil {
			result.promptHelper = *layer.SSH.PromptHelper
		}
	}
	if result.target == "" && result.ui == "none" {
		return commandOptions{}, errors.New("missing credential or host (select --ui shell to browse)")
	}
	return result, nil
}

func parseSSHOverrides(args []string) (commandOptions, optionOverrides, error) {
	var result commandOptions
	var ui config.SSHOverrides
	common := []string{"query-placeholder"}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			if result.target != "" {
				result.extraArgs = append(result.extraArgs, args[i:]...)
			} else if i+1 < len(args) {
				result.target = args[i+1]
				if result.target == "" {
					return result, optionOverrides{}, errors.New("credential or host cannot be empty")
				}
				result.extraArgs = append(result.extraArgs, args[i+2:]...)
			}
			break
		}
		name, value, attached := strings.Cut(arg, "=")
		switch name {
		case "--ui", "--prompt-helper":
			if !attached {
				if i+1 >= len(args) {
					return result, optionOverrides{}, fmt.Errorf("%s requires an argument", name)
				}
				i++
				value = args[i]
			}
			destination := &ui.UI
			if name == "--prompt-helper" {
				destination = &ui.PromptHelper
			}
			if *destination != nil {
				return result, optionOverrides{}, fmt.Errorf("%s may only be specified once", name)
			}
			*destination = &value
		case "--verbose":
			common = append(common, arg)
		case "-x", "--options", "--credential-backend", "--secret-collection", "--gopass-prefix":
			if name == "-x" && attached {
				if result.target == "" {
					return result, optionOverrides{}, errors.New("use --options for OpenSSH options before the credential query")
				}
				result.extraArgs = append(result.extraArgs, arg)
				continue
			}
			common = append(common, arg)
			if !attached {
				if i+1 >= len(args) {
					return result, optionOverrides{}, fmt.Errorf("%s requires an argument", name)
				}
				i++
				common = append(common, args[i])
			}
		default:
			if strings.HasPrefix(arg, "-") {
				if result.target == "" {
					return result, optionOverrides{}, errors.New("use --options for OpenSSH options before the credential query")
				}
				result.extraArgs = append(result.extraArgs, arg)
				// Preserve OpenSSH option arguments as data, including strings
				// which happen to look like sshx flags.
				if sshOptionNeedsValue(arg) {
					if i+1 >= len(args) {
						return result, optionOverrides{}, fmt.Errorf("%s requires an argument", arg)
					}
					i++
					result.extraArgs = append(result.extraArgs, args[i])
				}
				continue
			}
			if arg == "" && result.target == "" {
				return result, optionOverrides{}, errors.New("credential or host cannot be empty")
			}
			if result.target == "" {
				result.target = arg
			} else {
				result.extraArgs = append(result.extraArgs, args[i:]...)
				i = len(args)
			}
		}
	}
	_, overrides, err := parseCommandOverrides(common)
	if err != nil {
		return result, overrides, err
	}
	if ui.UI != nil || ui.PromptHelper != nil {
		overrides.SSH = &ui
	}
	if err := validateOverrides(overrides); err != nil {
		return result, overrides, err
	}
	return result, overrides, nil
}

func sshOptionNeedsValue(arg string) bool {
	if strings.HasPrefix(arg, "--") {
		return false
	}
	for i := 1; i < len(arg); i++ {
		if strings.ContainsRune("BbcDEeFIiJLlmOoPpQRSWw", rune(arg[i])) {
			return i == len(arg)-1
		}
	}
	return false
}
