package main

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode"

	"github.com/spf13/cobra"
)

func newCredentialsCommand(deps dependencies) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "credentials",
		Short:         "Discover stored credential metadata",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.AddCommand(newCredentialsListCommand(deps))
	return cmd
}

func newCredentialsListCommand(deps dependencies) *cobra.Command {
	var backendValue string
	var collection string
	var prefix string

	cmd := &cobra.Command{
		Use:   "list [query]",
		Short: "List credential metadata without reading secrets",
		Long: `List credentials using the same backend and matching rules as SSH and SCP.

Only backend, collection, label, and resolved target metadata are printed.
Secret values and complete attribute maps are never requested or displayed.`,
		Args:          cobra.MaximumNArgs(1),
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.Flags().StringVar(&backendValue, "credential-backend", "auto", "credential backend: auto, secret-service, or gopass")
	cmd.Flags().StringVar(&collection, "secret-collection", "", "limit Secret Service lookup to this collection label or alias")
	cmd.Flags().StringVar(&prefix, "gopass-prefix", "", "limit credential lookup to this gopass path")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		backend, err := parseCredentialBackend(backendValue)
		if err != nil {
			return err
		}
		if cmd.Flags().Changed("secret-collection") && collection == "" {
			return fmt.Errorf("secret collection cannot be empty")
		}
		if cmd.Flags().Changed("gopass-prefix") {
			prefix, err = normalizeGopassPrefix(prefix)
			if err != nil {
				return err
			}
		}

		options, err := finalizeCommandOptions(commandOptions{
			credentialBackend: backend,
			gopassPrefix:      prefix,
			secretCollection:  collection,
		})
		if err != nil {
			return err
		}
		query := ""
		if len(args) == 1 {
			query = args[0]
		}
		return executeCredentialList(query, options, deps)
	}
	return cmd
}

func executeCredentialList(query string, options commandOptions, deps dependencies) (returnErr error) {
	selection, err := selectCredentialStore(
		options.credentialBackend,
		dependencyGOOS(deps),
		deps.gopassStore,
		deps.secretServiceStore,
	)
	if err != nil {
		return fmt.Errorf("could not select credential backend: %w", err)
	}
	defer func() {
		if err := selection.store.Close(); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("close credential store: %w", err))
		}
	}()

	collection := options.gopassPrefix
	if selection.backend == credentialBackendSecretService {
		collection = options.secretCollection
	}
	credentials, err := selection.store.Search(credentialQuery{
		Collection: collection,
		Text:       query,
	})
	if err != nil {
		return fmt.Errorf("could not retrieve credentials: %w", err)
	}
	credentials = credentialsForListing(query, credentials)
	if err := writeCredentialList(deps.stdout, credentials); err != nil {
		return fmt.Errorf("write credential list: %w", err)
	}
	return nil
}

func writeCredentialList(output io.Writer, credentials []credentialRef) error {
	if output == nil {
		output = io.Discard
	}
	type row struct {
		backend    string
		collection string
		label      string
		target     string
	}
	rows := make([]row, 0, len(credentials))
	for _, credential := range credentials {
		rows = append(rows, row{
			backend:    safeCredentialField(string(credential.Backend)),
			collection: safeCredentialField(credential.Collection),
			label:      safeCredentialField(credential.Label),
			target:     safeCredentialField(credential.Target),
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		left := []string{rows[i].backend, rows[i].collection, rows[i].label, rows[i].target}
		right := []string{rows[j].backend, rows[j].collection, rows[j].label, rows[j].target}
		for index := range left {
			if left[index] != right[index] {
				return left[index] < right[index]
			}
		}
		return false
	})

	var formatted strings.Builder
	_, _ = fmt.Fprintln(&formatted, "BACKEND\tCOLLECTION\tLABEL\tTARGET")
	for _, row := range rows {
		_, _ = fmt.Fprintf(&formatted, "%s\t%s\t%s\t%s\n", row.backend, row.collection, row.label, row.target)
	}
	_, err := io.WriteString(output, formatted.String())
	return err
}

func safeCredentialField(value string) string {
	value = strings.Map(func(character rune) rune {
		if character == '\t' || character == '\n' || character == '\r' ||
			unicode.IsControl(character) || !unicode.IsGraphic(character) {
			return ' '
		}
		return character
	}, value)
	value = strings.Join(strings.Fields(value), " ")
	if value == "" {
		return "-"
	}
	return value
}
