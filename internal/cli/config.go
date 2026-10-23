package cli

import (
	"errors"
	"fmt"

	"github.com/jfardello/sshx/internal/config"
	"github.com/jfardello/sshx/internal/fileupdate"
	"github.com/spf13/cobra"
)

func newConfigCommand(deps dependencies) *cobra.Command {
	var effective bool
	root := &cobra.Command{
		Use:   "config [key [value]]",
		Short: "Inspect and edit nonsecret user configuration",
		Long:  "Inspect and edit user configuration. With no arguments, list stored settings; with a key, get it; with a key and value, set it. Use dotted agent/ssh keys and hyphens or underscores. Values are printed as quoted strings.",
		Args:  cobra.MaximumNArgs(2),
	}
	root.SetOut(deps.stdout)
	root.SetErr(deps.stderr)
	root.PersistentFlags().BoolVar(&effective, "effective", false, "include built-in defaults and file/default provenance (get/list only)")
	read := func(cmd *cobra.Command, key string) error {
		if key != "" {
			var err error
			key, err = config.NormalizeKey(key)
			if err != nil {
				return err
			}
		}
		name, err := config.UserPath()
		if err != nil {
			return err
		}
		settings, err := config.Settings(name, effective)
		if err != nil {
			return err
		}
		for _, setting := range settings {
			if key != "" && key != setting.Key {
				continue
			}
			if key == "" {
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s = %q", setting.Key, setting.Value)
			} else {
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "%q", setting.Value)
			}
			if err != nil {
				return err
			}
			if effective {
				if _, err = fmt.Fprintf(cmd.OutOrStdout(), "\t(%s)", setting.Source); err != nil {
					return err
				}
			}
			if _, err = fmt.Fprintln(cmd.OutOrStdout()); err != nil {
				return err
			}
			if key != "" {
				return nil
			}
		}
		if key != "" {
			return errors.New("configuration setting is not stored (use --effective for its default)")
		}
		return nil
	}
	write := func(cmd *cobra.Command, args []string, unset bool) error {
		if cmd.Flag("effective").Changed {
			return errors.New("--effective applies only to get and list")
		}
		name, err := config.UserPath()
		if err != nil {
			return err
		}
		var publication fileupdate.Publication
		if unset {
			publication, err = config.Unset(cmd.Context(), name, args[0])
		} else {
			publication, err = config.Set(cmd.Context(), name, args[0], args[1])
		}
		if publication == fileupdate.DurabilityUncertain {
			return fmt.Errorf("configuration was published, but durability is uncertain; do not retry automatically: %w", err)
		}
		if err != nil {
			return fmt.Errorf("configuration was not published: %w", err)
		}
		return nil
	}
	root.RunE = func(cmd *cobra.Command, args []string) error {
		switch len(args) {
		case 0:
			return read(cmd, "")
		case 1:
			return read(cmd, args[0])
		default:
			return write(cmd, args, false)
		}
	}
	root.AddCommand(
		&cobra.Command{Use: "get key", Short: "Show a stored value", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error { return read(cmd, args[0]) }},
		&cobra.Command{Use: "list", Short: "Show stored settings", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error { return read(cmd, "") }},
		&cobra.Command{Use: "set key value", Short: "Store a typed setting", Args: cobra.ExactArgs(2), RunE: func(cmd *cobra.Command, args []string) error { return write(cmd, args, false) }},
		&cobra.Command{Use: "unset key", Short: "Remove a stored override", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error { return write(cmd, args, true) }},
		&cobra.Command{Use: "path", Short: "Print the configuration path without reading it", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
			if cmd.Flag("effective").Changed {
				return errors.New("--effective applies only to get and list")
			}
			name, err := config.UserPath()
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), name)
			return err
		}},
	)
	return root
}
