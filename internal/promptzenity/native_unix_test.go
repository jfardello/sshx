//go:build !windows && !darwin

package promptzenity

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfardello/sshx/internal/promptprotocol"
)

// The subprocess gives the library a fresh executable lookup cache. A fake
// native backend verifies actual options without showing a desktop dialog.
func TestZenityNativeOptions(t *testing.T) {
	if os.Getenv("SSHX_ZENITY_ADAPTER_TEST") == "1" {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		switch os.Getenv("SSHX_ZENITY_ACTION") {
		case "confirm":
			approved, err := (Zenity{}).Confirm(ctx, "description")
			if err != nil || !approved {
				t.Fatal("approval failed")
			}
		case "password":
			password, err := (Zenity{}).Password(ctx, "description")
			if err != nil || string(password) != "secret" {
				t.Fatal("entry failed")
			}
		case "reject":
			approved, err := (Zenity{}).Confirm(ctx, "description")
			if err != nil || approved {
				t.Fatal("rejection failed")
			}
		case "empty":
			password, err := (Zenity{}).Password(ctx, "description")
			if err != nil || len(password) != 0 {
				t.Fatal("empty entry failed")
			}
		case "error":
			if _, err := (Zenity{}).Password(ctx, "description"); err != ErrFailed {
				t.Fatal("error not sanitized")
			}
		case "cancel":
			cancel()
			if _, err := (Zenity{}).Confirm(ctx, "description"); err != ErrFailed {
				t.Fatal("cancellation failed")
			}
		}
		return
	}
	for _, action := range []string{"confirm", "password", "reject", "empty", "error", "cancel"} {
		t.Run(action, func(t *testing.T) {
			dir := t.TempDir()
			marker := filepath.Join(dir, "args")
			script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > '" + marker + "'\n"
			switch action {
			case "password":
				script += "printf 'secret\\n'\n"
			case "reject":
				script += "exit 1\n"
			case "error":
				script += "echo sensitive-error >&2\nexit 2\n"
			}
			if err := os.WriteFile(filepath.Join(dir, "zenity"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestZenityNativeOptions$")
			cmd.Env = append(os.Environ(), "PATH="+dir, "SSHX_ZENITY_ADAPTER_TEST=1", "SSHX_ZENITY_ACTION="+action)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("adapter: %v %s", err, out)
			}
			if action == "cancel" {
				return
			}
			b, err := os.ReadFile(marker)
			if err != nil {
				t.Fatal(err)
			}
			args := "\n" + string(b)
			if action == "confirm" || action == "reject" {
				for _, opt := range []string{"--question", "--no-markup", "--default-cancel", "Allow once", "Reject"} {
					if !strings.Contains(args, "\n"+opt+"\n") {
						t.Fatalf("missing %s: %s", opt, args)
					}
				}
			} else {
				for _, opt := range []string{"--entry", "--hide-text", "Reject"} {
					if !strings.Contains(args, "\n"+opt+"\n") {
						t.Fatalf("missing %s: %s", opt, args)
					}
				}
			}
			if strings.Contains(args, "--entry-text") {
				t.Fatal("prepopulated passphrase")
			}
		})
	}
}

func TestZenityNativeSelection(t *testing.T) {
	if mode := os.Getenv("SSHX_SELECTION_ADAPTER_TEST"); mode != "" {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if mode == "context" {
			cancel()
		}
		d := promptprotocol.SelectionDisplay{Label: "same", Target: "alice@host", Backend: "gopass"}
		index, approved, err := (Zenity{}).Select(ctx, []promptprotocol.SelectionDisplay{d, d})
		switch mode {
		case "last":
			if err != nil || !approved || index != 1 {
				t.Fatal("duplicate display retargeted", index, err)
			}
		case "cancel", "empty":
			if err != nil || approved || index != -1 {
				t.Fatal("cancellation accepted", index, err)
			}
		default:
			if err != ErrFailed || approved || index != -1 {
				t.Fatal("failure escaped", index, err)
			}
		}
		return
	}
	for _, mode := range []string{"last", "cancel", "empty", "unknown", "error", "context"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			marker := filepath.Join(dir, "args")
			script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > '" + marker + "'\n"
			switch mode {
			case "last":
				script += "for item do last=$item; done\nprintf '%s\\n' \"$last\"\n"
			case "cancel":
				script += "exit 1\n"
			case "unknown":
				script += "printf '1. forged choice\\n'\n"
			case "error":
				script += "echo sensitive-error >&2\nexit 2\n"
			}
			if err := os.WriteFile(filepath.Join(dir, "zenity"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestZenityNativeSelection$")
			cmd.Env = append(os.Environ(), "PATH="+dir, "SSHX_SELECTION_ADAPTER_TEST="+mode)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("adapter %v %s", err, output)
			}
			if mode == "context" {
				return
			}
			data, err := os.ReadFile(marker)
			if err != nil {
				t.Fatal(err)
			}
			args := "\n" + string(data)
			for _, value := range []string{"--list", "Select once", "Cancel", "1. same | alice@host | gopass | ", "2. same | alice@host | gopass | "} {
				if !strings.Contains(args, "\n"+value+"\n") {
					t.Fatal("missing list option", value)
				}
			}
			if strings.Contains(args, "--multiple") {
				t.Fatal("multiple choice enabled")
			}
		})
	}
}
