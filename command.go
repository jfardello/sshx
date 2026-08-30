package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/spf13/cobra"
)

type commandOptions struct {
	target               string
	credentialBackend    credentialBackend
	credentialBackendSet bool
	gopassPrefix         string
	verbose              bool
	programOptions       []string
	extraArgs            []string
}

type dependencies struct {
	gopassStore        credentialStore
	secretServiceStore credentialStoreProvider
	runProgram         func(program string, args []string, password []byte) error
	stdout             io.Writer
	stderr             io.Writer
}

func newRootCommand() *cobra.Command {
	return newRootCommandWithDependencies(dependencies{
		gopassStore: newGopassStore(os.Stderr),
		runProgram: func(program string, args []string, password []byte) error {
			return runPTY(program, args, password, os.Stdin, os.Stdout)
		},
		stdout: os.Stdout,
		stderr: os.Stderr,
	})
}

func newRootCommandWithDependencies(deps dependencies) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sshx <userhost|gopass/path> [--credential-backend <backend>] [--gopass-prefix <path>] [--verbose] [-x '<ssh opts>'] [remote_command]",
		Short: "Run SSH or SCP with a password stored in gopass",
		Long: `sshx retrieves a credential from gopass and runs OpenSSH in a new PTY.

The child process uses the PTY slave as stdin, stdout, stderr, and its
controlling terminal. sshx detects the password prompt, writes the password to
the PTY master, and then maintains a normal interactive session.`,
		Example: `  sshx user@example.com --gopass-prefix infrastructure/production
  sshx ssh servers/user@example.com -x "-L 8080:localhost:8080"
  sshx scp user@example.com -x "-P 2222" file.txt :/tmp/`,
		Args:               cobra.ArbitraryArgs,
		DisableFlagParsing: true,
		SilenceErrors:      true,
		SilenceUsage:       true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if isHelpRequest(args) {
				return cmd.Help()
			}
			return executeSSH(args, deps)
		},
	}

	// Cobra remains responsible for command dispatch and generated help.
	// Parsing is manual because every option other than -x belongs to the
	// wrapped OpenSSH program and must pass through unchanged.
	addPassthroughFlag(cmd, "SSH")
	cmd.AddCommand(newSSHCommand(deps), newSCPCommand(deps))
	return cmd
}

func newSSHCommand(deps dependencies) *cobra.Command {
	cmd := &cobra.Command{
		Use:                "ssh <userhost|gopass/path> [--credential-backend <backend>] [--gopass-prefix <path>] [--verbose] [-x '<ssh opts>'] [remote_command]",
		Short:              "Open an SSH session or run a remote command",
		Args:               cobra.ArbitraryArgs,
		DisableFlagParsing: true,
		SilenceErrors:      true,
		SilenceUsage:       true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if isHelpRequest(args) {
				return cmd.Help()
			}
			return executeSSH(args, deps)
		},
	}
	addPassthroughFlag(cmd, "SSH")
	return cmd
}

func newSCPCommand(deps dependencies) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scp <userhost|gopass/path> [--credential-backend <backend>] [--gopass-prefix <path>] [--verbose] [-x '<scp opts>'] <source> <destination>",
		Short: "Copy a file between the local system and a remote host",
		Long: `Copy a file with OpenSSH scp using a password stored in gopass.

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
	cmd.Flags().String("gopass-prefix", "", "limit credential lookup to this gopass path")
	cmd.Flags().Bool("verbose", false, "log the selected gopass entry path")
}

func executeSSH(args []string, deps dependencies) (returnErr error) {
	opts, err := parseCommandOptions(args)
	if err != nil {
		return fmt.Errorf("usage: sshx [ssh] <userhost|gopass/path> [--credential-backend <backend>] [--gopass-prefix <path>] [--verbose] [-x '<ssh opts>'] [remote_command]: %w", err)
	}

	store, err := selectCredentialStore(opts.credentialBackend, deps.gopassStore, deps.secretServiceStore)
	if err != nil {
		return fmt.Errorf("could not select credential backend: %w", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("close credential store: %w", err))
		}
	}()

	credential, selected, err := resolveCredential(opts, store, deps)
	if err != nil || !selected {
		return err
	}

	password, err := store.Secret(credential)
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
	opts, err := parseCommandOptions(args)
	if err != nil {
		return fmt.Errorf("usage: sshx scp <userhost|gopass/path> [--credential-backend <backend>] [--gopass-prefix <path>] [--verbose] [-x '<scp opts>'] <source> <destination>: %w", err)
	}
	if len(opts.extraArgs) != 2 {
		return fmt.Errorf("scp requires exactly one source and one destination")
	}

	store, err := selectCredentialStore(opts.credentialBackend, deps.gopassStore, deps.secretServiceStore)
	if err != nil {
		return fmt.Errorf("could not select credential backend: %w", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("close credential store: %w", err))
		}
	}()

	credential, selected, err := resolveCredential(opts, store, deps)
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

	password, err := store.Secret(credential)
	if err != nil {
		return fmt.Errorf("could not retrieve password: %w", err)
	}
	defer clearBytes(password)

	scpArgs := make([]string, 0, len(opts.programOptions)+len(operands))
	scpArgs = append(scpArgs, opts.programOptions...)
	scpArgs = append(scpArgs, operands...)
	return deps.runProgram("scp", scpArgs, password)
}

func resolveCredential(opts commandOptions, store credentialStore, deps dependencies) (credentialRef, bool, error) {
	if strings.Contains(opts.target, "/") {
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

	credentials, err := store.Search(credentialQuery{
		Collection: opts.gopassPrefix,
		Text:       opts.target,
	})
	if err != nil {
		return credentialRef{}, false, fmt.Errorf("could not retrieve credentials: %w", err)
	}

	credential, selected := selectCredential(opts.target, credentials)
	if len(credentials) == 0 {
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
		fmt.Fprintln(stdout, "Please choose one of:")
		for _, candidate := range credentials {
			fmt.Fprintln(stdout, candidate.ID)
		}
		return credentialRef{}, false, nil
	}
	logSelectedEntry(credential.ID, opts.verbose, deps.stderr)
	return credential, selected, nil
}

func logSelectedEntry(entry string, verbose bool, stderr io.Writer) {
	if !verbose {
		return
	}
	if stderr == nil {
		stderr = io.Discard
	}
	fmt.Fprintf(stderr, "sshx: using gopass entry %q\n", entry)
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
	if len(args) == 0 {
		return commandOptions{}, fmt.Errorf("missing credential or host")
	}
	if args[0] == "" {
		return commandOptions{}, fmt.Errorf("credential or host cannot be empty")
	}

	result := commandOptions{target: args[0], credentialBackend: credentialBackendAuto}
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "-x", "--options":
			if i+1 >= len(args) {
				return commandOptions{}, fmt.Errorf("%s requires an argument", args[i])
			}
			result.programOptions = append(result.programOptions, strings.Fields(args[i+1])...)
			i++
		case "--gopass-prefix":
			if i+1 >= len(args) {
				return commandOptions{}, fmt.Errorf("--gopass-prefix requires an argument")
			}
			if result.gopassPrefix != "" {
				return commandOptions{}, fmt.Errorf("--gopass-prefix may only be specified once")
			}
			prefix, err := normalizeGopassPrefix(args[i+1])
			if err != nil {
				return commandOptions{}, err
			}
			result.gopassPrefix = prefix
			i++
		case "--credential-backend":
			if i+1 >= len(args) {
				return commandOptions{}, fmt.Errorf("--credential-backend requires an argument")
			}
			if result.credentialBackendSet {
				return commandOptions{}, fmt.Errorf("--credential-backend may only be specified once")
			}
			backend, err := parseCredentialBackend(args[i+1])
			if err != nil {
				return commandOptions{}, err
			}
			result.credentialBackend = backend
			result.credentialBackendSet = true
			i++
		case "--verbose":
			result.verbose = true
		case "--":
			result.extraArgs = append(result.extraArgs, args[i:]...)
			return result, nil
		default:
			result.extraArgs = append(result.extraArgs, args[i])
		}
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

func selectCredential(target string, credentials []credentialRef) (credentialRef, bool) {
	if len(credentials) == 1 {
		credential := credentials[0]
		if credential.Target == "" {
			credential.Target = target
		}
		return credential, true
	}
	return credentialRef{}, false
}

func clearBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
