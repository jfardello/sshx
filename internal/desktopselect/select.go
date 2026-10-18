// Package desktopselect invokes an explicitly configured trusted helper for one
// version-2 credential choice. It receives only display metadata, returns an
// original index, and never opens providers, retrieves secrets or launches SSH.
package desktopselect

import (
	"context"
	"errors"
	"time"

	"github.com/jfardello/sshx/internal/helperexec"
	"github.com/jfardello/sshx/internal/promptprotocol"
	"github.com/jfardello/sshx/internal/sensitive"
)

var (
	ErrCanceled    = errors.New("credential selection canceled")
	ErrFailed      = errors.New("credential selection failed")
	ErrUnavailable = helperexec.ErrUnavailable
)

// Select snapshots the ordered metadata, mints fresh per-request tokens and
// validates the helper's exact request ID and choice. The caller must retain
// its original references in the same order; returned display text is never
// used to search for a replacement. Even a single candidate requires a choice.
// The 30-second picker deadline ends when this function returns, before SSH.
func Select(ctx context.Context, helper string, displays []promptprotocol.SelectionDisplay) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if ctx.Err() != nil {
		return -1, ctx.Err()
	}
	r, err := promptprotocol.NewSelectionRequest(displays)
	if err != nil {
		return -1, err
	}
	input, err := promptprotocol.EncodeSelectionRequest(r)
	defer sensitive.Clear(input)
	if err != nil {
		return -1, err
	}
	output, err := helperexec.Run(ctx, helper, input, helperexec.Limits{
		RequestBytes: promptprotocol.MaxSelectionRequestBytes, ResponseBytes: promptprotocol.MaxSelectionResponseBytes,
	})
	defer sensitive.Clear(output)
	if ctx.Err() != nil {
		return -1, ctx.Err()
	}
	if errors.Is(err, helperexec.ErrUnavailable) {
		return -1, ErrUnavailable
	}
	if err != nil {
		return -1, ErrFailed
	}
	index, approved, err := promptprotocol.DecodeSelectionResponse(output, r)
	if err != nil {
		return -1, ErrFailed
	}
	if !approved {
		return -1, ErrCanceled
	}
	return index, nil
}
