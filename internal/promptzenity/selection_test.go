package promptzenity

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/jfardello/sshx/internal/promptprotocol"
)

type fakeSelection struct {
	fakeDialogs
	index    int
	approved bool
	seen     []promptprotocol.SelectionDisplay
}

func (f *fakeSelection) Select(_ context.Context, displays []promptprotocol.SelectionDisplay) (int, bool, error) {
	f.calls++
	f.seen = displays
	if f.cancel != nil {
		f.cancel()
	}
	// Even a buggy adapter modifying its display copy must not retarget the
	// original request's token; it never receives those tokens.
	displays[0].Label = "changed"
	return f.index, f.approved, f.err
}

func selectRequest(t *testing.T, count int) promptprotocol.SelectionRequest {
	t.Helper()
	displays := make([]promptprotocol.SelectionDisplay, count)
	for i := range displays {
		displays[i] = promptprotocol.SelectionDisplay{Label: "same <b>\u202e", Target: "alice@host", Backend: "secret-service", Collection: "Login"}
	}
	r, err := promptprotocol.NewSelectionRequest(displays)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestServeSelection(t *testing.T) {
	r := selectRequest(t, 2)
	input, _ := promptprotocol.EncodeSelectionRequest(r)
	for _, test := range []struct {
		index    int
		approved bool
	}{{0, true}, {1, true}, {-1, false}} {
		f := &fakeSelection{index: test.index, approved: test.approved}
		var out bytes.Buffer
		if err := Serve(context.Background(), bytes.NewReader(input), &out, f); err != nil {
			t.Fatal(err)
		}
		index, approved, err := promptprotocol.DecodeSelectionResponse(out.Bytes(), r)
		if err != nil || index != test.index || approved != test.approved || f.calls != 1 {
			t.Fatal("wrong bound choice", index, err)
		}
		if r.Options[0].Display.Label == "changed" {
			t.Fatal("dialog mutated request")
		}
		if strings.Contains(f.seen[1].Label, "<") || strings.Contains(f.seen[1].Label, "\u202e") {
			t.Fatal("unescaped display reached dialog")
		}
	}
	// This request exceeds v1's ceiling and is valid only for selection.
	r = selectRequest(t, 256)
	input, _ = promptprotocol.EncodeSelectionRequest(r)
	if len(input) <= promptprotocol.MaxBytes {
		t.Fatal("fixture too small")
	}
	var out bytes.Buffer
	if err := Serve(context.Background(), bytes.NewReader(input), &out, &fakeSelection{index: 255, approved: true}); err != nil {
		t.Fatal("valid larger v2 request rejected", err)
	}
	if index, _, err := promptprotocol.DecodeSelectionResponse(out.Bytes(), r); err != nil || index != 255 {
		t.Fatal("lost last choice", err)
	}
}

func TestSelectionDialogFailures(t *testing.T) {
	r := selectRequest(t, 2)
	input, _ := promptprotocol.EncodeSelectionRequest(r)
	for _, mode := range []string{"negative-index", "past-end", "denial-index", "error", "cancel", "no-picker", "short-write", "write-error", "oversized", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f := &fakeSelection{index: 0, approved: true}
			var dialogs Dialogs = f
			var output bytes.Buffer
			var out io.Writer = &output
			data := input
			switch mode {
			case "negative-index":
				f.index = -1
			case "past-end":
				f.index = 2
			case "denial-index":
				f.approved = false
			case "error":
				f.err = errors.New("sensitive error")
			case "cancel":
				f.cancel = cancel
			case "no-picker":
				dialogs = &fakeDialogs{}
			case "short-write":
				out = shortWriter{}
			case "write-error":
				out = failWriter{}
			case "oversized":
				data = append(bytes.Repeat([]byte(" "), promptprotocol.MaxSelectionRequestBytes), input...)
			case "malformed":
				data = []byte(`{"version":2,"operation":"confirm"}`)
			}
			if err := Serve(ctx, bytes.NewReader(data), out, dialogs); err != ErrFailed || output.Len() != 0 {
				t.Fatal("failure leaked output/error", err)
			}
		})
	}
}

func TestSelectionRowsCannotAlias(t *testing.T) {
	r := selectRequest(t, 2)
	rows := selectionRows([]promptprotocol.SelectionDisplay{r.Options[0].Display, r.Options[1].Display})
	if rows[0] == rows[1] || !strings.HasPrefix(rows[0], "1. ") || !strings.HasPrefix(rows[1], "2. ") {
		t.Fatal("duplicate display values alias")
	}
	for _, row := range rows {
		if strings.ContainsAny(row, "\n\x1b<>&\u202e") {
			t.Fatal("unsafe row")
		}
	}
}

func TestVersionOneBoundIsUnchanged(t *testing.T) {
	input := requestBytes("confirm")
	input = append(input, bytes.Repeat([]byte(" "), promptprotocol.MaxBytes-len(input)+1)...)
	f := &fakeDialogs{approved: true}
	var out bytes.Buffer
	if err := Serve(context.Background(), bytes.NewReader(input), &out, f); err != ErrFailed || f.calls != 0 || out.Len() != 0 {
		t.Fatal("v1 bounds widened", err)
	}
}
