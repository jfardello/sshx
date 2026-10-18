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
