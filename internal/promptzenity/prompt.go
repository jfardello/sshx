// Package promptzenity separates prompt policy/rendering from the desktop adapter.
package promptzenity

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/jfardello/sshx/internal/promptprotocol"
	"github.com/jfardello/sshx/internal/sensitive"
	"github.com/ncruces/zenity"
)

var ErrFailed = errors.New("desktop prompt failed")

// Dialogs is injected for tests. Password returns an owned mutable UTF-8 buffer.
// An error, window close or cancellation always denies, without retry.
type Dialogs interface {
	Confirm(context.Context, string) (bool, error)
	Password(context.Context, string) ([]byte, error)
}

// PlainText retains every identity byte visibly, escaping Unicode, controls,
// markup delimiters and backslashes so display text cannot inject another field.
func PlainText(value string) string {
	return `"` + promptprotocol.DisplayText(value) + `"`
}

func Description(r promptprotocol.Request) string {
	description := "Key: " + PlainText(r.KeyFingerprint)
	if r.Destination.Status == "verified-session-and-policy" {
		description += "\nApproved host key: " + PlainText(r.Destination.HostFingerprint)
		description += "\nRequested SSH user: " + PlainText(r.Destination.Username)
	} else {
		description += "\nDestination: UNKNOWN (unrestricted signing)"
	}
	return description + "\nAlgorithm: " + PlainText(r.Algorithm) + "\nRequest: " + r.RequestID + "\nData SHA-256: " + r.DataDigest
}

// Serve handles exactly one request and produces no stdout until a complete
// decision is available. The process supervisor bounds blocking I/O and time.
func Serve(ctx context.Context, in io.Reader, out io.Writer, dialogs Dialogs) error {
	input, err := io.ReadAll(io.LimitReader(in, promptprotocol.MaxSelectionRequestBytes+1))
	defer sensitive.Clear(input)
	if err != nil || ctx.Err() != nil {
		return ErrFailed
	}
	// This only routes the bounded envelope. Each version's strict decoder
	// subsequently validates all fields, duplicates and its own size limit.
	var envelope struct {
		Version int `json:"version"`
	}
	if json.Unmarshal(input, &envelope) != nil {
		return ErrFailed
	}
	if envelope.Version == 2 {
		return serveSelection(ctx, input, out, dialogs)
	}
	r, err := promptprotocol.DecodeRequest(input)
	if err != nil {
		return ErrFailed
	}
	var approved bool
	var password []byte
	if r.Operation == "confirm" {
		approved, err = dialogs.Confirm(ctx, "Allow this ONE signing request?\n\n"+Description(r))
	} else {
		password, err = dialogs.Password(ctx, "Enter the OpenSSH private-key passphrase.\nThis decrypts the key; it is not approval for future signing.\n\n"+Description(r))
		approved = len(password) != 0
	}
	defer sensitive.Clear(password)
	if err != nil || ctx.Err() != nil {
		return ErrFailed
	}
	response, err := promptprotocol.EncodeResponse(r, approved, password)
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

// Zenity uses only question and hidden entry dialogs. No extra buttons, default
// password, caching, fallback, or error text from the library reaches the wire.
type Zenity struct{}

func (Zenity) Confirm(ctx context.Context, description string) (bool, error) {
	err := zenity.Question(description, zenity.Title("sshx local signing approval"), zenity.OKLabel("Allow once"), zenity.CancelLabel("Reject"), zenity.DefaultCancel(), zenity.Context(ctx))
	if errors.Is(err, zenity.ErrCanceled) {
		return false, nil
	}
	if err != nil {
		return false, ErrFailed
	}
	return true, nil
}

func (Zenity) Password(ctx context.Context, description string) ([]byte, error) {
	password, err := zenity.Entry(description, zenity.Title("sshx local key decryption"), zenity.OKLabel("Decrypt once"), zenity.CancelLabel("Reject"), zenity.HideText(), zenity.Context(ctx))
	if errors.Is(err, zenity.ErrCanceled) {
		return nil, nil
	}
	if err != nil {
		return nil, ErrFailed
	}
	// The library returns an immutable string; this copy is owned and cleared by
	// Serve. Library, Go-string and dialog-process copies cannot be erased here.
	return []byte(password), nil
}
