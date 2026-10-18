package promptzenity

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/jfardello/sshx/internal/promptprotocol"
)

type fakeDialogs struct {
	approved    bool
	password    []byte
	err         error
	calls       int
	description string
	cancel      context.CancelFunc
}

func (f *fakeDialogs) Confirm(_ context.Context, description string) (bool, error) {
	f.calls++
	f.description = description
	if f.cancel != nil {
		f.cancel()
	}
	return f.approved, f.err
}
func (f *fakeDialogs) Password(_ context.Context, description string) ([]byte, error) {
	f.calls++
	f.description = description
	if f.cancel != nil {
		f.cancel()
	}
	return f.password, f.err
}

func requestBytes(operation string) []byte {
	b, _ := json.Marshal(promptprotocol.Request{Version: 1, RequestID: strings.Repeat("a", 64), Operation: operation, KeyFingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32)), DataDigest: strings.Repeat("b", 64), Algorithm: "ssh-ed25519", Destination: promptprotocol.Destination{Status: "unknown"}})
	return b
}

func TestServeDecisionsAndClearing(t *testing.T) {
	for _, operation := range []string{"confirm", "passphrase"} {
		for _, approve := range []bool{false, true} {
			f := &fakeDialogs{approved: approve}
			if approve && operation == "passphrase" {
				f.password = []byte("pássphrase")
			}
			var out bytes.Buffer
			if err := Serve(context.Background(), bytes.NewReader(requestBytes(operation)), &out, f); err != nil {
				t.Fatal(err)
			}
			var response struct {
				Version    int
				RequestID  string `json:"request_id"`
				Approved   bool
				Passphrase []byte
			}
			if json.Unmarshal(out.Bytes(), &response) != nil || response.Version != 1 || response.RequestID != strings.Repeat("a", 64) || response.Approved != approve || f.calls != 1 {
				t.Fatalf("wrong response: %s", out.Bytes())
			}
			if approve && operation == "passphrase" && string(response.Passphrase) != "pássphrase" {
				t.Fatal("wrong base64 password")
			}
			if !bytes.Equal(f.password, make([]byte, len(f.password))) {
				t.Fatal("password not cleared")
			}
			if !strings.Contains(f.description, "Destination: UNKNOWN") || strings.Contains(f.description, "Approved host key:") {
				t.Fatal("unknown identity misrepresented")
			}
		}
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("sensitive writer error") }

type shortWriter struct{}

func (shortWriter) Write([]byte) (int, error) { return 0, nil }

type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, errors.New("sensitive reader error") }

func TestServeFailures(t *testing.T) {
	for _, operation := range []string{"confirm", "passphrase"} {
		for _, mode := range []string{"dialog-error", "cancel", "oversize", "bad-utf8", "writer-error", "short-write", "reader-error", "malformed", "request-limit", "already-canceled"} {
			t.Run(operation+"/"+mode, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				f := &fakeDialogs{approved: true}
				if operation == "passphrase" {
					f.password = []byte("secret")
				}
				var output bytes.Buffer
				var in io.Reader = bytes.NewReader(requestBytes(operation))
				var out io.Writer = &output
				switch mode {
				case "dialog-error":
					f.err = errors.New("sensitive dialog error")
				case "cancel":
					f.cancel = cancel
				case "oversize":
					if operation == "confirm" {
						t.Skip("passphrase only")
					}
					f.password = bytes.Repeat([]byte("x"), 4097)
				case "bad-utf8":
					if operation == "confirm" {
						t.Skip("passphrase only")
					}
					f.password = []byte{0xff}
				case "writer-error":
					out = failWriter{}
				case "short-write":
					out = shortWriter{}
				case "reader-error":
					in = failReader{}
				case "malformed":
					in = strings.NewReader(`{"version":1}`)
				case "request-limit":
					in = strings.NewReader(strings.Repeat(" ", promptprotocol.MaxBytes+1))
				case "already-canceled":
					cancel()
				}
				if err := Serve(ctx, in, out, f); err != ErrFailed {
					t.Fatalf("unsanitized error: %v", err)
				}
				if output.Len() != 0 {
					t.Fatal("partial output")
				}
				if f.calls > 0 && !bytes.Equal(f.password, make([]byte, len(f.password))) {
					t.Fatal("failed password not cleared")
				}
			})
		}
	}
}

func TestPlainTextIdentity(t *testing.T) {
	user := "alice\nApproved host: evil\x1b\x00\u202e\u2066<b>&_'\\\"é"
	r := promptprotocol.Request{KeyFingerprint: "SHA256:key", RequestID: strings.Repeat("a", 64), DataDigest: strings.Repeat("b", 64), Algorithm: "ssh-ed25519", Destination: promptprotocol.Destination{Status: "verified-session-and-policy", HostFingerprint: "SHA256:host", Username: user}}
	description := Description(r)
	if strings.Count(description, "\n") != 5 || !strings.Contains(description, "Approved host key: \"SHA256:host\"") {
		t.Fatalf("wrong fields: %s", description)
	}
	for _, dangerous := range []string{"\x1b", "\x00", "\u202e", "\u2066", "<", ">", "&", "é"} {
		if strings.Contains(description, dangerous) {
			t.Fatalf("unsafe rendering: %q", dangerous)
		}
	}
	for _, escaped := range []string{`\nApproved host: evil`, `\u202e`, `\u2066`, `\u003cb\u003e`, `\u0026`, `\u00e9`} {
		if !strings.Contains(description, escaped) {
			t.Fatalf("concealed identity %q", escaped)
		}
	}
	if PlainText(strings.Repeat("a", 8000)) != `"`+strings.Repeat("a", 8000)+`"` {
		t.Fatal("identity truncated")
	}
}
