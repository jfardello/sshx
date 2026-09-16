package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

type commandOptions struct {
	target               string
	credentialBackend    credentialBackend
	credentialBackendSet bool
	gopassPrefix         string
	secretCollection     string
	verbose              bool
	programOptions       []string
	extraArgs            []string
}

type dependencies struct {
	ctx                context.Context
	gopassStore        credentialStore
	secretServiceStore credentialStoreProvider
	goos               string
	loadConfig         func() (optionOverrides, error)
	runProgram         func(program string, args []string, password []byte) error
	stdout             io.Writer
	stderr             io.Writer
	systemctl          func(context.Context, ...string) ([]byte, error)
}

func newRootCommand() *cobra.Command {
	return newRootCommandWithDependencies(dependencies{
		gopassStore:        newGopassStore(os.Stderr),
		secretServiceStore: newSecretServiceStore,
		goos:               runtime.GOOS,
		loadConfig:         loadUserConfig,
		runProgram: func(program string, args []string, password []byte) error {
			return runPTY(program, args, password, os.Stdin, os.Stdout)
		},
		stdout: os.Stdout,
		stderr: os.Stderr,
	})
}

func NewRootCommand() *cobra.Command { return newRootCommand() }

func newRootCommandWithDependencies(deps dependencies) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sshx <target|credential> [--credential-backend <backend>] [--secret-collection <collection>] [--gopass-prefix <path>] [--verbose] [-x '<ssh opts>'] [remote_command]",
		Short: "Run SSH or SCP with a stored password",
		Long: `sshx retrieves a credential from Secret Service or gopass and runs OpenSSH in a new PTY.

The child process uses the PTY slave as stdin, stdout, stderr, and its
controlling terminal. sshx detects the password prompt, writes the password to
the PTY master, and then maintains a normal interactive session.

Defaults are read from ~/.config/sshx/config.yaml (or $XDG_CONFIG_HOME/sshx/config.yaml).
Explicit command-line options override file defaults.`,
		Example: `  sshx user@example.com --gopass-prefix infrastructure/production
  sshx ssh servers/user@example.com -x "-L 8080:localhost:8080"
  sshx scp user@example.com -x "-P 2222" file.txt :/tmp/
  sshx credentials list production --secret-collection Login`,
		Args:               cobra.ArbitraryArgs,
		DisableFlagParsing: true,
		SilenceErrors:      true,
		SilenceUsage:       true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if isHelpRequest(args) {
				return cmd.Help()
			}
			deps.ctx = cmd.Context()
			return executeSSH(args, deps)
		},
	}

	// Cobra remains responsible for command dispatch and generated help.
	// Parsing is manual so options not owned by sshx pass through to
	// OpenSSH unchanged.
	addPassthroughFlag(cmd, "SSH")
	cmd.AddCommand(newSSHCommand(deps), newSCPCommand(deps), newCredentialsCommand(deps), newAgentCommand(deps))
	return cmd
}

func newSSHCommand(deps dependencies) *cobra.Command {
	cmd := &cobra.Command{
		Use:                "ssh <target|credential> [--credential-backend <backend>] [--secret-collection <collection>] [--gopass-prefix <path>] [--verbose] [-x '<ssh opts>'] [remote_command]",
		Short:              "Open an SSH session or run a remote command",
		Args:               cobra.ArbitraryArgs,
		DisableFlagParsing: true,
		SilenceErrors:      true,
		SilenceUsage:       true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if isHelpRequest(args) {
				return cmd.Help()
			}
			deps.ctx = cmd.Context()
			return executeSSH(args, deps)
		},
	}
	addPassthroughFlag(cmd, "SSH")
	return cmd
}

func newSCPCommand(deps dependencies) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scp <target|credential> [--credential-backend <backend>] [--secret-collection <collection>] [--gopass-prefix <path>] [--verbose] [-x '<scp opts>'] <source> <destination>",
		Short: "Copy a file between the local system and a remote host",
		Long: `Copy a file with OpenSSH scp using a stored password.

An operand beginning with ":" is expanded using the host resolved from the
credential. For example, ":/tmp/file" becomes "user@host:/tmp/file".`,
		Example: `  sshx scp user@example.com file.txt :/tmp/
  sshx scp servers/user@example.com :/var/log/app.log ./
  sshx scp user@example.com -x "-r -P 2222" directory/ :/opt/app/`,
		Args:               cobra.ArbitraryArgs,
		DisableFlagParsing: true,
		SilenceErrors:      true,
		SilenceUsage:       true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if isHelpRequest(args) {
				return cmd.Help()
			}
			deps.ctx = cmd.Context()
			return executeSCP(args, deps)
		},
	}
	addPassthroughFlag(cmd, "SCP")
	return cmd
}

func isHelpRequest(args []string) bool {
	return len(args) == 1 && (args[0] == "-h" || args[0] == "--help")
}

func addPassthroughFlag(cmd *cobra.Command, program string) {
	cmd.Flags().StringP("options", "x", "", strings.ToLower(program)+" options separated by spaces")
	cmd.Flags().String("credential-backend", "auto", "credential backend: auto, secret-service, or gopass")
	cmd.Flags().String("secret-collection", "", "limit Secret Service lookup (empty clears the configured collection)")
	cmd.Flags().String("gopass-prefix", "", "limit gopass lookup (empty clears the configured prefix)")
	cmd.Flags().Bool("verbose", false, "log the selected credential identity (--verbose=false disables)")
}

func executeSSH(args []string, deps dependencies) (returnErr error) {
	opts, err := parseConfiguredCommandOptions(args, deps)
	if err != nil {
		return fmt.Errorf("usage: sshx [ssh] <target|credential> [--credential-backend <backend>] [--secret-collection <collection>] [--gopass-prefix <path>] [--verbose] [-x '<ssh opts>'] [remote_command]: %w", err)
	}

	selection, err := selectCredentialStore(
		opts.credentialBackend,
		dependencyGOOS(deps),
		deps.gopassStore,
		deps.secretServiceStore,
		dependencyContext(deps),
	)
	if err != nil {
		return fmt.Errorf("could not select credential backend: %w", err)
	}
	defer func() {
		if err := selection.store.Close(); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("close credential store: %w", err))
		}
	}()

	credential, selected, err := resolveCredential(opts, selection, deps)
	if err != nil || !selected {
		return err
	}

	password, err := selection.store.Secret(dependencyContext(deps), credential, credentialReadOptions{AllowInteraction: true})
	if err != nil {
		return fmt.Errorf("could not retrieve password: %w", err)
	}
	defer clearBytes(password)

	sshArgs := make([]string, 0, len(opts.programOptions)+1+len(opts.extraArgs))
	sshArgs = append(sshArgs, opts.programOptions...)
	sshArgs = append(sshArgs, credential.Target)
	sshArgs = append(sshArgs, opts.extraArgs...)
	return deps.runProgram("ssh", sshArgs, password)
}

func executeSCP(args []string, deps dependencies) (returnErr error) {
	opts, err := parseConfiguredCommandOptions(args, deps)
	if err != nil {
		return fmt.Errorf("usage: sshx scp <target|credential> [--credential-backend <backend>] [--secret-collection <collection>] [--gopass-prefix <path>] [--verbose] [-x '<scp opts>'] <source> <destination>: %w", err)
	}
	if len(opts.extraArgs) != 2 {
		return fmt.Errorf("scp requires exactly one source and one destination")
	}

	selection, err := selectCredentialStore(
		opts.credentialBackend,
		dependencyGOOS(deps),
		deps.gopassStore,
		deps.secretServiceStore,
		dependencyContext(deps),
	)
	if err != nil {
		return fmt.Errorf("could not select credential backend: %w", err)
	}
	defer func() {
		if err := selection.store.Close(); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("close credential store: %w", err))
		}
	}()

	credential, selected, err := resolveCredential(opts, selection, deps)
	if err != nil || !selected {
		return err
	}

	operands := append([]string(nil), opts.extraArgs...)
	for i := range operands {
		if strings.HasPrefix(operands[i], ":") {
			operands[i] = credential.Target + operands[i]
		}
	}

	remoteCount := 0
	for _, operand := range operands {
		if isRemoteOperand(operand) {
			remoteCount++
		}
	}
	if remoteCount == 0 {
		return fmt.Errorf("scp requires one remote operand; prefix the remote path with ':'")
	}
	if remoteCount > 1 {
		return fmt.Errorf("remote-to-remote copies are not supported")
	}

	password, err := selection.store.Secret(dependencyContext(deps), credential, credentialReadOptions{AllowInteraction: true})
	if err != nil {
		return fmt.Errorf("could not retrieve password: %w", err)
	}
	defer clearBytes(password)

	scpArgs := make([]string, 0, len(opts.programOptions)+len(operands))
	scpArgs = append(scpArgs, opts.programOptions...)
	scpArgs = append(scpArgs, operands...)
	return deps.runProgram("scp", scpArgs, password)
}

func dependencyGOOS(deps dependencies) string {
	if deps.goos != "" {
		return deps.goos
	}
	return runtime.GOOS
}

func resolveCredential(
	opts commandOptions,
	selection selectedCredentialStore,
	deps dependencies,
) (credentialRef, bool, error) {
	if selection.backend == credentialBackendGopass && strings.Contains(opts.target, "/") {
		targetPath, err := normalizeGopassEntryPath(opts.target)
		if err != nil {
			return credentialRef{}, false, err
		}
		entry := path.Join(opts.gopassPrefix, targetPath)
		credential := credentialRef{
			Backend:    credentialBackendGopass,
			ID:         entry,
			Collection: opts.gopassPrefix,
			Label:      path.Base(entry),
			Target:     path.Base(opts.target),
		}
		logSelectedEntry(credential.ID, opts.verbose, deps.stderr)
		return credential, true, nil
	}

	collection := opts.gopassPrefix
	if selection.backend == credentialBackendSecretService {
		collection = opts.secretCollection
	}
	credentials, err := selection.store.Search(dependencyContext(deps), credentialQuery{AllowInteraction: true,
		Collection: collection,
		Text:       opts.target,
	})
	if err != nil {
		return credentialRef{}, false, fmt.Errorf("could not retrieve credentials: %w", err)
	}

	credentials, err = matchCredentials(opts.target, credentials)
	if err != nil {
		return credentialRef{}, false, err
	}
	credential, selected := selectCredential(credentials)
	if len(credentials) == 0 {
		if selection.backend == credentialBackendSecretService {
			location := "Secret Service"
			if opts.secretCollection != "" {
				location = fmt.Sprintf("Secret Service collection %q", opts.secretCollection)
			}
			return credentialRef{}, false, fmt.Errorf(
				"no credential matching %q in %s",
				opts.target,
				location,
			)
		}
		location := "the gopass tree"
		if opts.gopassPrefix != "" {
			location = fmt.Sprintf("gopass path %q", opts.gopassPrefix)
		}
		return credentialRef{}, false, fmt.Errorf("no gopass entry matching %q under %s", opts.target, location)
	}
	if !selected {
		stdout := deps.stdout
		if stdout == nil {
			stdout = io.Discard
		}
		_, _ = fmt.Fprintln(stdout, "Please choose one of:")
		for _, candidate := range credentials {
			_, _ = fmt.Fprintln(stdout, credentialIdentity(candidate))
		}
		return credentialRef{}, false, nil
	}
	logSelectedCredential(credential, opts.verbose, deps.stderr)
	return credential, selected, nil
}

func logSelectedCredential(credential credentialRef, verbose bool, stderr io.Writer) {
	if credential.Backend == credentialBackendGopass {
		logSelectedEntry(credential.ID, verbose, stderr)
		return
	}
	if !verbose {
		return
	}
	if stderr == nil {
		stderr = io.Discard
	}
	_, _ = fmt.Fprintf(stderr, "sshx: using secret-service credential %q\n", credentialIdentity(credential))
}

func logSelectedEntry(entry string, verbose bool, stderr io.Writer) {
	if !verbose {
		return
	}
	if stderr == nil {
		stderr = io.Discard
	}
	_, _ = fmt.Fprintf(stderr, "sshx: using gopass entry %q\n", entry)
}

func isRemoteOperand(operand string) bool {
	if strings.HasPrefix(operand, "/") ||
		strings.HasPrefix(operand, "./") ||
		strings.HasPrefix(operand, "../") {
		return false
	}
	return strings.IndexByte(operand, ':') > 0
}

func parseCommandOptions(args []string) (commandOptions, error) {
	return parseConfiguredCommandOptions(args, dependencies{})
}

func parseConfiguredCommandOptions(args []string, deps dependencies) (commandOptions, error) {
	invocation, overrides, err := parseCommandOverrides(args)
	if err != nil {
		return commandOptions{}, err
	}
	return configuredCommandOptions(invocation, overrides, deps)
}

func parseCommandOverrides(args []string) (commandOptions, optionOverrides, error) {
	var overrides optionOverrides
	if len(args) == 0 {
		return commandOptions{}, overrides, fmt.Errorf("missing credential or host")
	}
	if args[0] == "" {
		return commandOptions{}, overrides, fmt.Errorf("credential or host cannot be empty")
	}
	result := commandOptions{target: args[0]}
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			result.extraArgs = append(result.extraArgs, args[i:]...)
			break
		}
		name, value, attached := strings.Cut(arg, "=")
		switch name {
		case "--verbose":
			enabled := true
			if attached {
				if value != "true" && value != "false" {
					return commandOptions{}, overrides, fmt.Errorf("--verbose must be true or false")
				}
				enabled = value == "true"
			}
			overrides.Verbose = &enabled
		case "-x", "--options", "--credential-backend", "--secret-collection", "--gopass-prefix":
			// Only long flags accept attached values; preserve unknown short forms.
			if name == "-x" && attached {
				result.extraArgs = append(result.extraArgs, arg)
				continue
			}
			if !attached {
				if i+1 >= len(args) {
					return commandOptions{}, overrides, fmt.Errorf("%s requires an argument", name)
				}
				i++
				value = args[i]
			}
			var destination **string
			switch name {
			case "--credential-backend":
				destination = &overrides.CredentialBackend
			case "--secret-collection":
				destination = &overrides.SecretCollection
			case "--gopass-prefix":
				destination = &overrides.GopassPrefix
			default:
				if overrides.Options == nil {
					overrides.Options = &value
				} else {
					joined := *overrides.Options + " " + value
					overrides.Options = &joined
				}
				continue
			}
			if *destination != nil {
				return commandOptions{}, overrides, fmt.Errorf("%s may only be specified once", name)
			}
			*destination = &value
		default:
			result.extraArgs = append(result.extraArgs, arg)
		}
	}
	if err := validateOverrides(overrides); err != nil {
		return commandOptions{}, overrides, err
	}
	return result, overrides, nil
}

func finalizeCommandOptions(result commandOptions) (commandOptions, error) {
	if result.gopassPrefix != "" && result.credentialBackend == credentialBackendSecretService {
		return commandOptions{}, fmt.Errorf("--gopass-prefix cannot be used with the secret-service backend")
	}
	if result.secretCollection != "" && result.credentialBackend == credentialBackendGopass {
		return commandOptions{}, fmt.Errorf("--secret-collection cannot be used with the gopass backend")
	}
	if result.gopassPrefix != "" && result.credentialBackend == credentialBackendAuto {
		result.credentialBackend = credentialBackendGopass
	}
	if result.secretCollection != "" && result.credentialBackend == credentialBackendGopass {
		return commandOptions{}, fmt.Errorf("--secret-collection cannot be combined with --gopass-prefix")
	}
	return result, nil
}

func normalizeGopassPrefix(value string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("gopass prefix cannot be empty")
	}
	return normalizeGopassPath(value, "gopass prefix")
}

func normalizeGopassEntryPath(value string) (string, error) {
	return normalizeGopassPath(value, "gopass entry path")
}

func normalizeGopassPath(value, label string) (string, error) {
	if strings.HasPrefix(value, "/") {
		return "", fmt.Errorf("%s must be relative", label)
	}

	trimmed := strings.TrimRight(value, "/")
	for _, component := range strings.Split(trimmed, "/") {
		if component == "." || component == ".." {
			return "", fmt.Errorf("%s cannot contain %q components", label, component)
		}
	}
	return path.Clean(trimmed), nil
}

func selectCredential(credentials []credentialRef) (credentialRef, bool) {
	if len(credentials) == 1 {
		return credentials[0], true
	}
	return credentialRef{}, false
}

func dependencyContext(deps dependencies) context.Context {
	if deps.ctx != nil {
		return deps.ctx
	}
	return context.Background()
}
