package promptprotocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func selectionFixture(t testing.TB) SelectionRequest {
	t.Helper()
	r, err := NewSelectionRequest([]SelectionDisplay{{"same label", "alice@host", "gopass", ""}, {"same label", "alice@host", "gopass", ""}})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSelectionIdentityAndSanitization(t *testing.T) {
	displays := []SelectionDisplay{{"prod\n\x1b\u202e<b>&'\\\"é", "alice@host", "secret-service", "Login"}}
	r, err := NewSelectionRequest(displays)
	if err != nil {
		t.Fatal(err)
	}
	if !hexDigest(r.RequestID) || !hexDigest(r.Options[0].Token) {
		t.Fatal("invalid random identity")
	}
	for _, field := range []string{r.Options[0].Display.Label, r.Options[0].Display.Target, r.Options[0].Display.Collection} {
		if !canonicalDisplay(field) || strings.ContainsAny(field, "\n\x1b<>&'é\u202e") {
			t.Fatal("unsafe display")
		}
	}
	if !strings.Contains(r.Options[0].Display.Label, `\u202e`) || !strings.Contains(r.Options[0].Display.Label, `\u003c`) || !strings.Contains(r.Options[0].Display.Label, `\u00e9`) {
		t.Fatal("identity lost")
	}
	if displays[0].Label == r.Options[0].Display.Label {
		t.Fatal("caller data changed or display not escaped")
	}
	displays[0].Label = "changed"
	if r.Options[0].Display.Label == "changed" {
		t.Fatal("request aliases input")
	}
	other := selectionFixture(t)
	seen := map[string]bool{r.RequestID: true, r.Options[0].Token: true}
	for _, v := range []string{other.RequestID, other.Options[0].Token, other.Options[1].Token} {
		if seen[v] {
			t.Fatal("reused identity")
		}
		seen[v] = true
	}
	b, err := EncodeSelectionRequest(r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeSelectionRequest(b)
	if err != nil || !reflect.DeepEqual(got, r) {
		t.Fatal("roundtrip", err)
	}
	for _, forbidden := range []string{`"id":`, `"reference":`, `"attributes":`, `"password":`, `"secret":`} {
		if bytes.Contains(b, []byte(forbidden)) {
			t.Fatal("disallowed field on wire")
		}
	}
}

func TestSelectionBounds(t *testing.T) {
	r := selectionFixture(t)
	for _, count := range []int{1, MaxSelectionCandidates} {
		displays := make([]SelectionDisplay, count)
		for i := range displays {
			displays[i] = SelectionDisplay{strings.Repeat("x", MaxSelectionFieldBytes), "host", "gopass", ""}
		}
		request, err := NewSelectionRequest(displays)
		if count == 1 {
			if err != nil || len(request.Options[0].Display.Label) != MaxSelectionFieldBytes {
				t.Fatal("exact field bound rejected", err)
			}
		} else if !errors.Is(err, ErrNarrow) {
			t.Fatal("envelope size did not require narrowing", err)
		}
		for i := range displays {
			displays[i].Label = "short"
		}
		request, err = NewSelectionRequest(displays)
		if err != nil || len(request.Options) != count {
			t.Fatal("candidate count rejected", err)
		}
	}
	if _, err := NewSelectionRequest(make([]SelectionDisplay, MaxSelectionCandidates+1)); err != ErrNarrow {
		t.Fatal("candidate limit")
	}
	for _, value := range []string{strings.Repeat("x", 1025), strings.Repeat("é", 512)} {
		if _, err := NewSelectionRequest([]SelectionDisplay{{value, "host", "gopass", ""}}); err != ErrNarrow {
			t.Fatal("raw/escaped field bound", err)
		}
	}
	if _, err := NewSelectionRequest([]SelectionDisplay{{string([]byte{0xff}), "host", "gopass", ""}}); err != ErrInvalid {
		t.Fatal("invalid UTF-8 accepted")
	}
	b, _ := EncodeSelectionRequest(r)
	b = append(b, bytes.Repeat([]byte(" "), MaxSelectionRequestBytes-len(b))...)
	if _, err := DecodeSelectionRequest(b); err != nil {
		t.Fatal("exact envelope bound rejected", err)
	}
	if _, err := DecodeSelectionRequest(append(b, ' ')); err != ErrNarrow {
		t.Fatal("oversized envelope accepted")
	}
}

func TestSelectionRequestStrictness(t *testing.T) {
	r := selectionFixture(t)
	valid, _ := EncodeSelectionRequest(r)
	var tree map[string]any
	if json.Unmarshal(valid, &tree) != nil {
		t.Fatal("fixture")
	}
	// Required fields/types are checked at all three object levels.
	for _, level := range []string{"request", "option", "display"} {
		var keys []string
		switch level {
		case "request":
			keys = []string{"version", "request_id", "operation", "options"}
		case "option":
			keys = []string{"token", "display"}
		case "display":
			keys = []string{"label", "target", "backend", "collection"}
		}
		for _, key := range keys {
			for _, replacement := range []any{nil, true, 42, []any{}, map[string]any{}, "missing"} {
				var candidate map[string]any
				_ = json.Unmarshal(valid, &candidate)
				object := candidate
				if level != "request" {
					object = candidate["options"].([]any)[0].(map[string]any)
				}
				if level == "display" {
					object = object["display"].(map[string]any)
				}
				if replacement == "missing" {
					delete(object, key)
				} else {
					object[key] = replacement
				}
				b, _ := json.Marshal(candidate)
				if _, err := DecodeSelectionRequest(b); err == nil {
					t.Fatalf("accepted %s.%s = %#v", level, key, replacement)
				}
			}
		}
	}
	for _, bad := range [][]byte{
		[]byte(`null`), []byte(`[]`), []byte(`{`), append(bytes.Clone(valid), []byte(` {}`)...),
		bytes.Replace(valid, []byte(`"version":2`), []byte(`"version":2,"version":2`), 1),
		bytes.Replace(valid, []byte(`"version":2`), []byte(`"Version":2`), 1),
		bytes.Replace(valid, []byte(`"version":2`), []byte(`"version":2,"password":"secret"`), 1),
		bytes.Replace(valid, []byte(`"token":`), []byte(`"reference":"provider/path","token":`), 1),
		bytes.Replace(valid, []byte(`"label":"same label"`), []byte(`"label":"same label","label":"same label"`), 1),
		bytes.Replace(valid, []byte(`"display":{`), []byte(`"display":{"attributes":{},`), 1),
		bytes.Replace(valid, []byte(`"same label"`), []byte(`"<b>unsafe</b>"`), 1),
		bytes.Replace(valid, []byte(`"same label"`), []byte(`"line\nspoof"`), 1),
		bytes.Replace(valid, []byte(`"same label"`), []byte(`"\ud800"`), 1),
		bytes.Replace(valid, []byte(`same label`), []byte{0xff}, 1),
	} {
		if _, err := DecodeSelectionRequest(bad); err == nil {
			t.Fatalf("accepted malformed request: %q", bad)
		}
	}
	for _, mutate := range []func(*SelectionRequest){
		func(r *SelectionRequest) { r.Version = 1 }, func(r *SelectionRequest) { r.Version = 3 },
		func(r *SelectionRequest) { r.Operation = "confirm" }, func(r *SelectionRequest) { r.Operation = "passphrase" },
		func(r *SelectionRequest) { r.RequestID = strings.Repeat("A", 64) },
		func(r *SelectionRequest) { r.Options[1].Token = r.Options[0].Token },
		func(r *SelectionRequest) { r.Options[0].Token = "foreign" },
		func(r *SelectionRequest) { r.Options = nil },
		func(r *SelectionRequest) { r.Options[0].Display.Backend = "auto" },
		func(r *SelectionRequest) { r.Options[0].Display.Label = "" },
		func(r *SelectionRequest) { r.Options[0].Display.Target = "" },
	} {
		candidate := r
		candidate.Options = append([]SelectionOption{}, r.Options...)
		mutate(&candidate)
		if _, err := EncodeSelectionRequest(candidate); err == nil {
			t.Fatal("invalid outbound request")
		}
		b, _ := json.Marshal(candidate)
		if _, err := DecodeSelectionRequest(b); err == nil {
			t.Fatal("invalid inbound request")
		}
	}
}

func TestSelectionResponseBinding(t *testing.T) {
	r := selectionFixture(t)
	for i, option := range r.Options {
		b, err := EncodeSelectionResponse(r, true, option.Token)
		if err != nil {
			t.Fatal(err)
		}
		index, approved, err := DecodeSelectionResponse(b, r)
		if err != nil || !approved || index != i {
			t.Fatal("duplicate labels retargeted choice", index, err)
		}
		if bytes.Contains(b, []byte("same label")) || bytes.Contains(b, []byte("alice@host")) {
			t.Fatal("response contains display data")
		}
		if _, _, err := DecodeSelectionResponse(b, selectionFixture(t)); err == nil {
			t.Fatal("cross-request response accepted")
		}
	}
	b, err := EncodeSelectionResponse(r, false, "")
	if err != nil {
		t.Fatal(err)
	}
	index, approved, err := DecodeSelectionResponse(b, r)
	if err != nil || approved || index != -1 || bytes.Contains(b, []byte(`"token"`)) {
		t.Fatal("invalid denial")
	}
	for _, pair := range []struct {
		approved bool
		token    string
	}{{true, ""}, {true, strings.Repeat("c", 64)}, {false, r.Options[0].Token}} {
		if _, err := EncodeSelectionResponse(r, pair.approved, pair.token); err == nil {
			t.Fatal("invalid outbound response")
		}
	}
	good, _ := EncodeSelectionResponse(r, true, r.Options[0].Token)
	for _, bad := range [][]byte{
		[]byte(`null`), []byte(`{}`), append(bytes.Clone(good), []byte(` {}`)...),
		bytes.Replace(good, []byte(`"version":2`), []byte(`"version":1`), 1),
		bytes.Replace(good, []byte(`"version":2`), []byte(`"version":3`), 1),
		bytes.Replace(good, []byte(`"version":2`), []byte(`"version":2,"version":2`), 1),
		bytes.Replace(good, []byte(`"version":2`), []byte(`"version":null`), 1),
		bytes.Replace(good, []byte(`"approved":true`), []byte(`"approved":false`), 1),
		bytes.Replace(good, []byte(`"approved":true`), []byte(`"approved":null`), 1),
		bytes.Replace(good, []byte(`"approved":true`), []byte(`"approved":"true"`), 1),
		bytes.Replace(good, []byte(`"token":`), []byte(`"Token":`), 1),
		bytes.Replace(good, []byte(`"token":`), []byte(`"operation":"select-credential","token":`), 1),
		bytes.Replace(good, []byte(`"token":`), []byte(`"target":"evil","token":`), 1),
		bytes.Replace(good, []byte(r.Options[0].Token), []byte(strings.Repeat("f", 64)), 1),
		bytes.Replace(good, []byte(r.RequestID), []byte(strings.Repeat("f", 64)), 1),
		[]byte(`{"version":2,"request_id":"` + r.RequestID + `","approved":false,"token":""}`),
		[]byte(`{"version":2,"request_id":"` + r.RequestID + `","approved":true}`),
		append(bytes.Repeat([]byte(" "), MaxSelectionResponseBytes), good...),
	} {
		if _, _, err := DecodeSelectionResponse(bad, r); err == nil {
			t.Fatalf("accepted invalid reply %q", bad)
		}
	}
	good = append(good, bytes.Repeat([]byte(" "), MaxSelectionResponseBytes-len(good))...)
	if _, _, err := DecodeSelectionResponse(good, r); err != nil {
		t.Fatal("exact response limit rejected")
	}
}

func FuzzSelectionRequest(f *testing.F) {
	r := selectionFixture(f)
	b, _ := EncodeSelectionRequest(r)
	f.Add(b)
	f.Add([]byte(`{"version":2}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := DecodeSelectionRequest(data)
		if err == nil {
			b, err := EncodeSelectionRequest(r)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = DecodeSelectionRequest(b); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func FuzzSelectionResponse(f *testing.F) {
	r := selectionFixture(f)
	r.RequestID = strings.Repeat("a", 64)
	r.Options[0].Token = strings.Repeat("b", 64)
	r.Options[1].Token = strings.Repeat("c", 64)
	b, _ := EncodeSelectionResponse(r, true, r.Options[0].Token)
	f.Add(b)
	f.Fuzz(func(t *testing.T, data []byte) {
		index, approved, err := DecodeSelectionResponse(data, r)
		if err == nil && approved && (index < 0 || index >= len(r.Options)) {
			t.Fatal("unbound choice")
		}
	})
}
