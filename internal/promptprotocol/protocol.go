// Package promptprotocol implements separate version-1 signing and version-2
// credential-selection wire formats. It neither authorizes signing nor retrieves
// credentials; callers retain all private material and exact provider references.
package promptprotocol

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/jfardello/sshx/internal/sensitive"
)

const MaxBytes = 16 * 1024
const MaxPassphraseBytes = 4096

var ErrInvalid = errors.New("invalid prompt protocol")

type Request struct {
	Version        int         `json:"version"`
	RequestID      string      `json:"request_id"`
	Operation      string      `json:"operation"`
	KeyFingerprint string      `json:"key_fingerprint"`
	DataDigest     string      `json:"data_digest"`
	Algorithm      string      `json:"algorithm"`
	Destination    Destination `json:"destination"`
}

type Destination struct {
	Status          string `json:"status"`
	HostFingerprint string `json:"host_fingerprint,omitempty"`
	Username        string `json:"username,omitempty"`
}

// object requires exactly the supplied fields; optional fields are admitted but
// cannot be null. Token inspection rejects duplicates and case-folded aliases.
func object(data []byte, required, optional []string) error {
	d := json.NewDecoder(bytes.NewReader(data))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return ErrInvalid
	}
	seen := map[string]bool{}
	allowed := map[string]bool{}
	for _, key := range append(append([]string{}, required...), optional...) {
		allowed[key] = true
	}
	for d.More() {
		token, err = d.Token()
		key, ok := token.(string)
		if err != nil || !ok || !allowed[key] || seen[key] {
			return ErrInvalid
		}
		seen[key] = true
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return ErrInvalid
		}
		null := bytes.Equal(bytes.TrimSpace(value), []byte("null"))
		sensitive.Clear(value)
		if null {
			return ErrInvalid
		}
	}
	if _, err = d.Token(); err != nil {
		return ErrInvalid
	}
	if _, err = d.Token(); err != io.EOF {
		return ErrInvalid
	}
	for _, key := range required {
		if !seen[key] {
			return ErrInvalid
		}
	}
	return nil
}

func hexDigest(value string) bool {
	b, err := hex.DecodeString(value)
	return err == nil && len(b) == 32 && value == strings.ToLower(value)
}

func fingerprint(value string) bool {
	encoded, ok := strings.CutPrefix(value, "SHA256:")
	b, err := base64.RawStdEncoding.DecodeString(encoded)
	return ok && err == nil && len(b) == 32 && base64.RawStdEncoding.EncodeToString(b) == encoded
}

func text(value string) bool { return value != "" && !strings.ContainsRune(value, utf8.RuneError) }

// DecodeRequest validates one complete bounded UTF-8 JSON request. Input remains
// owned by the caller. Unknown destinations cannot carry asserted host identity.
func DecodeRequest(data []byte) (Request, error) {
	var r Request
	if len(data) > MaxBytes || !utf8.Valid(data) || object(data, []string{"version", "request_id", "operation", "key_fingerprint", "data_digest", "algorithm", "destination"}, nil) != nil {
		return r, ErrInvalid
	}
	var raw struct {
		Destination json.RawMessage `json:"destination"`
	}
	if json.Unmarshal(data, &raw) != nil {
		return r, ErrInvalid
	}
	defer sensitive.Clear(raw.Destination)
	if object(raw.Destination, []string{"status"}, []string{"host_fingerprint", "username"}) != nil || json.Unmarshal(data, &r) != nil {
		return Request{}, ErrInvalid
	}
	if r.Version != 1 || !hexDigest(r.RequestID) || !hexDigest(r.DataDigest) || !fingerprint(r.KeyFingerprint) || !text(r.Algorithm) || len(r.Algorithm) > 256 || (r.Operation != "confirm" && r.Operation != "passphrase") {
		return Request{}, ErrInvalid
	}
	switch r.Destination.Status {
	case "unknown":
		if object(raw.Destination, []string{"status"}, nil) != nil {
			return Request{}, ErrInvalid
		}
	case "verified-session-and-policy":
		if object(raw.Destination, []string{"status", "host_fingerprint", "username"}, nil) != nil || !fingerprint(r.Destination.HostFingerprint) || !text(r.Destination.Username) {
			return Request{}, ErrInvalid
		}
	default:
		return Request{}, ErrInvalid
	}
	return r, nil
}

// EncodeResponse borrows passphrase. The returned JSON buffer belongs to the
// caller and must be cleared. encoding/json encodes []byte as standard base64.
func EncodeResponse(r Request, approved bool, passphrase []byte) ([]byte, error) {
	if !hexDigest(r.RequestID) || (r.Operation != "confirm" && r.Operation != "passphrase") || len(passphrase) > MaxPassphraseBytes || (!approved && len(passphrase) != 0) || (r.Operation == "confirm" && len(passphrase) != 0) || (approved && r.Operation == "passphrase" && (len(passphrase) == 0 || !utf8.Valid(passphrase))) {
		return nil, ErrInvalid
	}
	response := struct {
		Version    int    `json:"version"`
		RequestID  string `json:"request_id"`
		Approved   bool   `json:"approved"`
		Passphrase []byte `json:"passphrase,omitempty"`
	}{1, r.RequestID, approved, passphrase}
	b, err := json.Marshal(response)
	if err != nil || len(b) > MaxBytes {
		sensitive.Clear(b)
		return nil, ErrInvalid
	}
	return b, nil
}
