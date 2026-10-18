package desktopselect

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jfardello/sshx/internal/promptprotocol"
)

func displays() []promptprotocol.SelectionDisplay {
	d := promptprotocol.SelectionDisplay{Label: "same", Target: "alice@host", Backend: "gopass"}
	return []promptprotocol.SelectionDisplay{d, d}
}

func TestSelectionHelperProcess(t *testing.T) {
	mode := os.Getenv("SSHX_SELECTION_TEST_MODE")
	if mode == "" {
		return
	}
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		os.Exit(2)
	}
	r, err := promptprotocol.DecodeSelectionRequest(input)
	if err != nil {
		os.Exit(3)
	}
	if mode == "wait" {
		time.Sleep(10 * time.Second)
		os.Exit(4)
	}
	if mode == "fail" {
		_, _ = os.Stderr.WriteString("sensitive provider failure")
		os.Exit(5)
	}
	if mode == "overflow" {
		_, _ = os.Stdout.WriteString(strings.Repeat("x", promptprotocol.MaxSelectionResponseBytes+1))
		os.Exit(0)
	}
	var response []byte
	switch mode {
	case "deny":
		response, err = promptprotocol.EncodeSelectionResponse(r, false, "")
	case "foreign-id":
		r.RequestID = strings.Repeat("f", 64)
		response, err = promptprotocol.EncodeSelectionResponse(r, true, r.Options[0].Token)
	case "foreign-token":
		response = []byte(`{"version":2,"request_id":"` + r.RequestID + `","approved":true,"token":"` + strings.Repeat("f", 64) + `"}`)
	case "version-one":
		response = []byte(`{"version":1,"request_id":"` + r.RequestID + `","approved":true}`)
	case "extra-field":
		response = []byte(`{"version":2,"request_id":"` + r.RequestID + `","approved":true,"token":"` + r.Options[0].Token + `","target":"attacker"}`)
	default:
		response, err = promptprotocol.EncodeSelectionResponse(r, true, r.Options[len(r.Options)-1].Token)
	}
	if err != nil {
		os.Exit(6)
	}
	_, _ = os.Stdout.Write(response)
	os.Exit(0)
}

func helper(t *testing.T, mode string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "helper")
	marker := filepath.Join(dir, "started")
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
	script := "#!/bin/sh\n: > " + quote(marker) + "\nexport SSHX_SELECTION_TEST_MODE=" + quote(mode) + "\nexec " + quote(os.Args[0]) + " '-test.run=^TestSelectionHelperProcess$'\n"
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	return path, marker
}

func TestSelectBoundIndex(t *testing.T) {
	path, _ := helper(t, "last")
	for _, choices := range [][]promptprotocol.SelectionDisplay{displays(), displays()[:1]} {
		index, err := Select(context.Background(), path, choices)
		if err != nil || index != len(choices)-1 {
			t.Fatal("wrong original index", index, err)
		}
	}
}

func TestSingleCandidateStillPrompts(t *testing.T) {
	path, marker := helper(t, "deny")
	if index, err := Select(context.Background(), path, displays()[:1]); index != -1 || err != ErrCanceled {
		t.Fatal("single candidate bypassed the dialog", index, err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("single-candidate helper was not invoked", err)
	}
}

func TestSelectFailures(t *testing.T) {
	for _, mode := range []string{"deny", "foreign-id", "foreign-token", "version-one", "extra-field", "overflow", "fail", "wait"} {
		t.Run(mode, func(t *testing.T) {
			path, _ := helper(t, mode)
			ctx := context.Background()
			var cancel context.CancelFunc
			if mode == "wait" {
				ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
				defer cancel()
			}
			index, err := Select(ctx, path, displays())
			expected := ErrFailed
			if mode == "deny" {
				expected = ErrCanceled
			}
			if mode == "wait" {
				expected = context.DeadlineExceeded
			}
			if index != -1 || !errors.Is(err, expected) {
				t.Fatalf("failure escaped: index=%d err=%v", index, err)
			}
		})
	}
}

func TestSelectRejectsBeforeLaunch(t *testing.T) {
	path, marker := helper(t, "last")
	oversized := displays()
	oversized[0].Label = strings.Repeat("x", 1025)
	for _, choices := range [][]promptprotocol.SelectionDisplay{oversized, make([]promptprotocol.SelectionDisplay, 257)} {
		if index, err := Select(context.Background(), path, choices); index != -1 || err != promptprotocol.ErrNarrow {
			t.Fatal("missing narrowing error", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Select(ctx, path, displays()); err != context.Canceled {
		t.Fatal("canceled request launched", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("helper launched before validation")
	}
	if _, err := Select(context.Background(), "/missing/helper", displays()); err != ErrUnavailable {
		t.Fatal("missing helper did not fail cleanly", err)
	}
}

func TestOldTkHelperFailsClosed(t *testing.T) {
	if _, err := os.Stat("/usr/bin/python3"); err != nil {
		t.Skip("legacy Tk helper requires /usr/bin/python3")
	}
	script, err := os.ReadFile("../../contrib/prompt/sshx-prompt")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "legacy-tk")
	if err := os.WriteFile(path, script, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	index, err := Select(ctx, path, displays())
	if index != -1 || err != ErrFailed {
		t.Fatal("legacy helper accepted selection", index, err)
	}
}
