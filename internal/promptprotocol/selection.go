package promptprotocol

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"unicode/utf8"
)

const (
	MaxSelectionRequestBytes  = 256 * 1024
	MaxSelectionResponseBytes = 16 * 1024
	MaxSelectionCandidates    = 256
	MaxSelectionFieldBytes    = 1024
)

var ErrNarrow = errors.New("credential selection exceeds limits; narrow the query")

// SelectionDisplay is an explicit allowlist of display-only metadata. It has no
// credential ID, provider path, attribute map or secret. NewSelectionRequest
// accepts raw text; wire requests contain canonical DisplayText representations.
type SelectionDisplay struct {
	Label      string `json:"label"`
	Target     string `json:"target"`
	Backend    string `json:"backend"`
	Collection string `json:"collection"`
}

type SelectionOption struct {
	Token   string           `json:"token"`
	Display SelectionDisplay `json:"display"`
}

type SelectionRequest struct {
	Version   int               `json:"version"`
	RequestID string            `json:"request_id"`
	Operation string            `json:"operation"`
	Options   []SelectionOption `json:"options"`
}

type selectionResponse struct {
	Version   int    `json:"version"`
	RequestID string `json:"request_id"`
	Approved  bool   `json:"approved"`
	Token     string `json:"token,omitempty"`
}

func randomToken() (string, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", ErrInvalid
	}
	return hex.EncodeToString(nonce[:]), nil
}

// NewSelectionRequest snapshots sanitized display metadata and mints a fresh
// random request ID and unique opaque tokens. Option order is retained so the
// parent can resolve a validated response to its original reference by index.
func NewSelectionRequest(displays []SelectionDisplay) (SelectionRequest, error) {
	if len(displays) > MaxSelectionCandidates {
		return SelectionRequest{}, ErrNarrow
	}
	r := SelectionRequest{Version: 2, Operation: "select-credential", Options: make([]SelectionOption, len(displays))}
	var err error
	r.RequestID, err = randomToken()
	if err != nil {
		return SelectionRequest{}, err
	}
	seen := map[string]bool{}
	for i, d := range displays {
		fields := []*string{&d.Label, &d.Target, &d.Backend, &d.Collection}
		for _, field := range fields {
			if !utf8.ValidString(*field) {
				return SelectionRequest{}, ErrInvalid
			}
			if len(*field) > MaxSelectionFieldBytes {
				return SelectionRequest{}, ErrNarrow
			}
			*field = DisplayText(*field)
		}
		var token string
		for token == "" || seen[token] {
			token, err = randomToken()
			if err != nil {
				return SelectionRequest{}, err
			}
		}
		seen[token] = true
		r.Options[i] = SelectionOption{token, d}
	}
	if _, err := EncodeSelectionRequest(r); err != nil {
		return SelectionRequest{}, err
	}
	return r, nil
}

func validateSelection(r SelectionRequest) error {
	if r.Version != 2 || r.Operation != "select-credential" || !hexDigest(r.RequestID) || len(r.Options) == 0 {
		return ErrInvalid
	}
	if len(r.Options) > MaxSelectionCandidates {
		return ErrNarrow
	}
	seen := map[string]bool{}
	for _, option := range r.Options {
		if !hexDigest(option.Token) || seen[option.Token] {
			return ErrInvalid
		}
		seen[option.Token] = true
		d := option.Display
		if d.Label == "" || d.Target == "" || (d.Backend != "gopass" && d.Backend != "secret-service") {
			return ErrInvalid
		}
		for _, field := range []string{d.Label, d.Target, d.Backend, d.Collection} {
			if len(field) > MaxSelectionFieldBytes {
				return ErrNarrow
			}
			if !canonicalDisplay(field) {
				return ErrInvalid
			}
		}
	}
	return nil
}

func EncodeSelectionRequest(r SelectionRequest) ([]byte, error) {
	if err := validateSelection(r); err != nil {
		return nil, err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return nil, ErrInvalid
	}
	if len(b) > MaxSelectionRequestBytes {
		return nil, ErrNarrow
	}
	return b, nil
}

// DecodeSelectionRequest rejects unknown/duplicate fields at every level,
// missing/null/wrongly typed values and trailing JSON before a dialog is shown.
func DecodeSelectionRequest(data []byte) (SelectionRequest, error) {
	var r SelectionRequest
	if len(data) > MaxSelectionRequestBytes {
		return r, ErrNarrow
	}
	if !utf8.Valid(data) || object(data, []string{"version", "request_id", "operation", "options"}, nil) != nil {
		return r, ErrInvalid
	}
	var raw struct {
		Options []json.RawMessage `json:"options"`
	}
	if json.Unmarshal(data, &raw) != nil {
		return r, ErrInvalid
	}
	if len(raw.Options) > MaxSelectionCandidates {
		return r, ErrNarrow
	}
	for _, option := range raw.Options {
		if object(option, []string{"token", "display"}, nil) != nil {
			return r, ErrInvalid
		}
		var display struct {
			Display json.RawMessage `json:"display"`
		}
		if json.Unmarshal(option, &display) != nil || object(display.Display, []string{"label", "target", "backend", "collection"}, nil) != nil {
			return r, ErrInvalid
		}
	}
	if json.Unmarshal(data, &r) != nil {
		return SelectionRequest{}, ErrInvalid
	}
	if err := validateSelection(r); err != nil {
		return SelectionRequest{}, err
	}
	return r, nil
}

func selectionIndex(r SelectionRequest, token string) int {
	for i, option := range r.Options {
		if option.Token == token {
			return i
		}
	}
	return -1
}

// EncodeSelectionResponse emits an envelope plus only the original chosen
// token. A denial must have no token; it never returns display text or a target.
func EncodeSelectionResponse(r SelectionRequest, approved bool, token string) ([]byte, error) {
	if err := validateSelection(r); err != nil {
		return nil, err
	}
	if (!approved && token != "") || (approved && selectionIndex(r, token) < 0) {
		return nil, ErrInvalid
	}
	b, err := json.Marshal(selectionResponse{2, r.RequestID, approved, token})
	if err != nil || len(b) > MaxSelectionResponseBytes {
		return nil, ErrInvalid
	}
	return b, nil
}

// DecodeSelectionResponse resolves only a token from this exact request to its
// original index. False approval returns (-1,false,nil); invalid replies fail.
func DecodeSelectionResponse(data []byte, r SelectionRequest) (int, bool, error) {
	if err := validateSelection(r); err != nil {
		return -1, false, err
	}
	if len(data) > MaxSelectionResponseBytes || !utf8.Valid(data) || object(data, []string{"version", "request_id", "approved"}, []string{"token"}) != nil {
		return -1, false, ErrInvalid
	}
	var response selectionResponse
	if json.Unmarshal(data, &response) != nil || response.Version != 2 || response.RequestID != r.RequestID {
		return -1, false, ErrInvalid
	}
	if !response.Approved {
		if object(data, []string{"version", "request_id", "approved"}, nil) != nil {
			return -1, false, ErrInvalid
		}
		return -1, false, nil
	}
	if object(data, []string{"version", "request_id", "approved", "token"}, nil) != nil {
		return -1, false, ErrInvalid
	}
	index := selectionIndex(r, response.Token)
	if index < 0 {
		return -1, false, ErrInvalid
	}
	return index, true, nil
}
