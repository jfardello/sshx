// Package fileupdate implements bounded, locked, atomic updates of trusted files.
// It does not decode documents or perform provider or interactive work.
package fileupdate

import (
	"context"
	"errors"
)

// Policy selects the input/output bound and whether group/other access is forbidden.
// MaxBytes must be positive. Replacements are always created with mode 0600.
type Policy struct {
	MaxBytes int
	Private  bool
}

// Publication describes whether this call replaced the destination.
type Publication int

const (
	Unchanged Publication = iota
	Published
	DurabilityUncertain
)

var (
	ErrBusy     = errors.New("file update busy")
	ErrConflict = errors.New("file update conflict")
	ErrInvalid  = errors.New("invalid or untrusted file update")
	ErrIO       = errors.New("file update I/O failure")
)

// Update edits a clean absolute path while holding its stable sibling .lock.
// edit must validate both documents, be bounded/local, and not retain current.
// changed=false leaves the target untouched (even when absent). The callback's
// input is a private copy, so editing it in place cannot corrupt the snapshot.
// Callback errors are sanitized to ErrInvalid, except the exported categories
// and context cancellation. Cancellation after rename does not undo publication.
// Cooperating writers serialize; portable rename is not compare-and-swap against
// noncooperating same-user writers racing the final check.
func Update(ctx context.Context, path string, policy Policy, edit func([]byte, bool) ([]byte, bool, error)) (Publication, error) {
	return update(ctx, path, policy, edit, hooks{})
}

func callbackError(err error) error {
	for _, category := range []error{context.Canceled, context.DeadlineExceeded, ErrBusy, ErrConflict, ErrInvalid, ErrIO} {
		if errors.Is(err, category) {
			return category
		}
	}
	return ErrInvalid
}
