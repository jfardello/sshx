package promptzenity

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/jfardello/sshx/internal/promptprotocol"
	"github.com/jfardello/sshx/internal/sensitive"
	"github.com/ncruces/zenity"
)

// SelectionDialogs is separate from version-1 signing dialogs. Implementations
// return the original displayed index; no display string is a credential ID.
type SelectionDialogs interface {
	Select(context.Context, []promptprotocol.SelectionDisplay) (int, bool, error)
}

func serveSelection(ctx context.Context, input []byte, out io.Writer, dialogs Dialogs) error {
	r, err := promptprotocol.DecodeSelectionRequest(input)
	if err != nil {
		return ErrFailed
	}
	picker, ok := dialogs.(SelectionDialogs)
	if !ok {
		return ErrFailed
	}
	displays := make([]promptprotocol.SelectionDisplay, len(r.Options))
	for i, option := range r.Options {
		displays[i] = option.Display
	}
	index, approved, err := picker.Select(ctx, displays)
	if err != nil || ctx.Err() != nil {
		return ErrFailed
	}
	var token string
	if approved {
		if index < 0 || index >= len(r.Options) {
			return ErrFailed
		}
		token = r.Options[index].Token
	} else if index != -1 {
		return ErrFailed
	}
	response, err := promptprotocol.EncodeSelectionResponse(r, approved, token)
	defer sensitive.Clear(response)
	if err != nil {
		return ErrFailed
	}
	n, err := out.Write(response)
	if err != nil || n != len(response) {
		return ErrFailed
	}
	return nil
}

// selectionRows uses unique ordinal prefixes, so even identical display fields
// cannot cause the native library's string result to select a different option.
// Fields have already been canonically escaped by the strict protocol decoder.
func selectionRows(displays []promptprotocol.SelectionDisplay) []string {
	rows := make([]string, len(displays))
	for i, d := range displays {
		rows[i] = fmt.Sprintf("%d. %s | %s | %s | %s", i+1, d.Label, d.Target, d.Backend, d.Collection)
	}
	return rows
}

func (Zenity) Select(ctx context.Context, displays []promptprotocol.SelectionDisplay) (int, bool, error) {
	rows := selectionRows(displays)
	chosen, err := zenity.List("Select one credential. No password is retrieved by this dialog.", rows,
		zenity.Title("sshx local credential selection"), zenity.OKLabel("Select once"), zenity.CancelLabel("Cancel"), zenity.Context(ctx))
	if errors.Is(err, zenity.ErrCanceled) {
		return -1, false, nil
	}
	if err != nil {
		return -1, false, ErrFailed
	}
	if chosen == "" {
		return -1, false, nil
	}
	for i, row := range rows {
		if chosen == row {
			return i, true, nil
		}
	}
	return -1, false, ErrFailed
}
