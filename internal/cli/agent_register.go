package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"unicode"

	"github.com/jfardello/sshx/internal/agent"
	"github.com/jfardello/sshx/internal/credential"
	"github.com/jfardello/sshx/internal/fileupdate"
	"github.com/jfardello/sshx/internal/keystore"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

func newAgentRegisterCommand(deps dependencies) *cobra.Command {
	var backend, reference, collection, comment, knownHosts string
	var destinations []string
	var unrestricted, enable, confirm, replace bool
	var port int
	cmd := &cobra.Command{
		Use:   "register id --backend backend --reference reference [policy options]",
		Short: "Register a validated provider key and explicit signing policy",
		Long:  "Register an existing private key from an exact provider reference. Choose --unrestricted-local or repeated --destination user@host. Destination pins come only from the specified known-hosts file. No keys are fetched or installed remotely. Encrypted OpenSSH keys require a controlling terminal; unlock the provider separately.",
		Args:  cobra.ExactArgs(1),
	}
	cmd.Flags().StringVar(&backend, "backend", "", "explicit key backend: gopass or secret-service")
	cmd.Flags().StringVar(&reference, "reference", "", "exact gopass path or stable Secret Service sshx.id")
	cmd.Flags().StringVar(&collection, "collection", "", "Secret Service collection alias (required for secret-service)")
	cmd.Flags().StringVar(&comment, "comment", "", "public display label (maximum 128 bytes)")
	cmd.Flags().BoolVar(&unrestricted, "unrestricted-local", false, "explicitly allow local signing without destination restrictions")
	cmd.Flags().StringArrayVar(&destinations, "destination", nil, "exact user@host or user@[IPv6] (repeatable)")
	cmd.Flags().IntVar(&port, "port", 22, "known-hosts lookup port for all destinations (not an authorization constraint)")
	cmd.Flags().StringVar(&knownHosts, "known-hosts", "", "known-hosts file (default ~/.ssh/known_hosts)")
	cmd.Flags().BoolVar(&enable, "enable", false, "enable the registered key (default disabled)")
	cmd.Flags().BoolVar(&confirm, "confirm", false, "require per-request agent confirmation")
	cmd.Flags().BoolVar(&replace, "replace", false, "replace only this ID if its validated fields differ")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		for _, name := range []string{"verbose", "cache-ttl", "prompt-helper", "allow-forwarding", "allow-key-mutations", "state-file"} {
			if flag := cmd.Flag(name); flag != nil && flag.Changed {
				return fmt.Errorf("--%s does not apply to registration", name)
			}
		}
		record := agent.RegistryRecord{ID: args[0], Backend: credential.Backend(backend), Reference: reference, Collection: collection, Comment: comment, Enabled: enable, Confirm: confirm}
		if !cmd.Flags().Changed("backend") || !cmd.Flags().Changed("reference") || !credential.ValidRegistryID(record.ID) || len(comment) > 128 || strings.ContainsFunc(comment, unicode.IsControl) {
			return errors.New("registration requires a valid ID, explicit backend/reference, and bounded public comment")
		}
		switch record.Backend {
		case credential.BackendGopass:
			if !credential.ValidGopassReference(reference) || cmd.Flags().Changed("collection") {
				return errors.New("gopass registration requires an exact relative reference and no collection")
			}
		case credential.BackendSecretService:
			if !cmd.Flags().Changed("collection") || !credential.ValidRegistryID(reference) || !credential.ValidRegistryID(collection) {
				return errors.New("Secret Service registration requires a stable ID and explicit collection alias")
			}
		default:
			return errors.New("registration backend must be explicitly gopass or secret-service; auto is not supported")
		}
		if unrestricted == (len(destinations) != 0) {
			return errors.New("choose either --unrestricted-local or one or more --destination values")
		}
		if unrestricted && (cmd.Flags().Changed("known-hosts") || cmd.Flags().Changed("port")) {
			return errors.New("--known-hosts and --port require destination-constrained registration")
		}
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGTSTP)
		defer stop()
		if !unrestricted {
			if cmd.Flags().Changed("known-hosts") && knownHosts == "" {
				return errors.New("--known-hosts requires a nonempty file path")
			}
			if knownHosts == "" {
				home, err := os.UserHomeDir()
				if err != nil {
					return errors.New("cannot locate user known-hosts file")
				}
				knownHosts = filepath.Join(home, ".ssh", "known_hosts")
			}
			policy, err := agent.RegistrationDestinations(ctx, destinations, port, knownHosts)
			if err != nil {
				return err
			}
			record.Policy, record.Destinations = "destination-constrained", policy
		} else {
			record.Policy = "unrestricted-local"
		}
		name, err := agent.RegistryPath()
		if err != nil {
			return err
		}
		open := deps.openKeyStore
		if open == nil {
			open = keystore.Open
		}
		data, err := registrationKeyMaterial(ctx, open, credential.Ref{Backend: record.Backend, ID: reference, Collection: collection})
		defer clearBytes(data)
		if err != nil {
			return err
		}
		prompt := deps.registrationPassphrase
		if prompt == nil {
			prompt = readRegistrationPassphrase
		}
		var promptErr error
		public, err := agent.RegistrationPublicKey(ctx, data, func(ctx context.Context) ([]byte, error) {
			passphrase, err := prompt(ctx)
			promptErr = err
			return passphrase, err
		})
		// Private bytes are no longer needed, including while acquiring the registry
		// lock or syncing its public replacement. Keep the defer for earlier failures.
		clearBytes(data)
		if err != nil {
			if errors.Is(promptErr, errRegistrationTTY) {
				return errRegistrationTTY
			}
			if errors.Is(promptErr, errRegistrationPassphrase) {
				return errRegistrationPassphrase
			}
			return err
		}
		// The writer receives only validated public metadata, after provider cleanup
		// and any terminal interaction have finished.
		record.PublicKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public)))
		publication, err := agent.UpsertRegistryRecord(ctx, name, record, replace)
		if publication == fileupdate.DurabilityUncertain {
			return fmt.Errorf("registry was published, but durability is uncertain; do not retry automatically: %w", err)
		}
		if err != nil {
			return fmt.Errorf("registry was not published: %w", err)
		}
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "Fingerprint: %s\nEnabled: %t\n", ssh.FingerprintSHA256(public), enable)
		if err != nil {
			return errors.New("registration succeeded, but its result could not be written")
		}
		return nil
	}
	return cmd
}

func registrationKeyMaterial(ctx context.Context, open func(context.Context, credential.Backend) (credential.KeyStore, error), ref credential.Ref) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, credential.OperationTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	store, err := open(ctx, ref.Backend)
	if err != nil {
		if store != nil {
			_ = store.Close()
		}
		return nil, registrationProviderError(ctx, err)
	}
	if store == nil {
		return nil, credential.ErrRead
	}
	data, readErr := store.KeyMaterial(ctx, ref)
	closeErr := store.Close()
	if readErr != nil || closeErr != nil || ctx.Err() != nil {
		clearBytes(data)
		if readErr != nil {
			return nil, registrationProviderError(ctx, readErr)
		}
		if closeErr != nil {
			return nil, registrationProviderError(ctx, closeErr)
		}
		return nil, ctx.Err()
	}
	return data, nil
}

func registrationProviderError(ctx context.Context, err error) error {
	if errors.Is(err, credential.ErrLocked) && ctx.Err() == nil {
		return fmt.Errorf("credential provider is locked; unlock it separately and retry: %w", credential.ErrLocked)
	}
	return credential.SanitizeKeyReadError(ctx, err)
}
