package promptprotocol

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func validRequest() Request {
	return Request{1, strings.Repeat("a", 64), "confirm", "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32)), strings.Repeat("b", 64), "ssh-ed25519", Destination{Status: "unknown"}}
}

func TestRequestStrictness(t *testing.T) {
	r := validRequest()
	valid, _ := json.Marshal(r)
	if got, err := DecodeRequest(valid); err != nil || got != r {
		t.Fatalf("roundtrip: %v", err)
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(valid, &fields)
	for key := range fields {
		for _, replacement := range []string{"null", "true", "[]", "{}"} {
			copyFields := map[string]json.RawMessage{}
			for k, v := range fields {
				copyFields[k] = v
			}
			copyFields[key] = json.RawMessage(replacement)
			b, _ := json.Marshal(copyFields)
			t.Run(key+replacement, func(t *testing.T) {
				if _, err := DecodeRequest(b); err == nil {
					t.Fatal("accepted wrong field type/null")
				}
			})
		}
		copyFields := map[string]json.RawMessage{}
		for k, v := range fields {
			if k != key {
				copyFields[k] = v
			}
		}
		b, _ := json.Marshal(copyFields)
		if _, err := DecodeRequest(b); err == nil {
			t.Fatalf("accepted missing %s", key)
		}
	}
	for _, bad := range [][]byte{
		[]byte(`[]`), []byte(`null`), []byte(`{`), append(append([]byte{}, valid...), []byte(` {}`)...),
		bytes.Replace(valid, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1),
		bytes.Replace(valid, []byte(`"version":1`), []byte(`"Version":1`), 1),
		bytes.Replace(valid, []byte(`"version":1`), []byte(`"version":2`), 1),
		bytes.Replace(valid, []byte(`"version":1`), []byte(`"version":1.0`), 1),
		bytes.Replace(valid, []byte(`"confirm"`), []byte(`"select-credential"`), 1),
		bytes.Replace(valid, []byte(`"status":"unknown"`), []byte(`"status":"unknown","status":"unknown"`), 1),
		bytes.Replace(valid, []byte(`"status":"unknown"`), []byte(`"status":"unknown","username":"claimed"`), 1),
		bytes.Replace(valid, []byte(`"status":"unknown"`), []byte(`"status":"unknown","extra":true`), 1),
		bytes.Replace(valid, []byte(`"status":"unknown"`), []byte(`"status":"verified-session-and-policy"`), 1),
		bytes.Replace(valid, []byte(`ssh-ed25519`), []byte{0xff}, 1),
		bytes.Replace(valid, []byte(`ssh-ed25519`), []byte(`\ud800`), 1),
		append(bytes.Repeat([]byte(" "), MaxBytes), valid...),
	} {
		if _, err := DecodeRequest(bad); err == nil {
			t.Fatalf("accepted invalid request %q", bad)
		}
	}
	for _, mutate := range []func(*Request){
		func(r *Request) { r.RequestID = strings.Repeat("A", 64) },
		func(r *Request) { r.RequestID = "a" },
		func(r *Request) { r.DataDigest = "wrong" },
		func(r *Request) { r.KeyFingerprint = "SHA256:invalid" },
		func(r *Request) { r.Algorithm = "" },
		func(r *Request) { r.Algorithm = strings.Repeat("a", 257) },
		func(r *Request) { r.Destination.Status = "claimed" },
	} {
		candidate := r
		mutate(&candidate)
		b, _ := json.Marshal(candidate)
		if _, err := DecodeRequest(b); err == nil {
			t.Fatal("accepted invalid value")
		}
	}
	r.Destination = Destination{"verified-session-and-policy", r.KeyFingerprint, "alice"}
	b, _ := json.Marshal(r)
	if _, err := DecodeRequest(b); err != nil {
		t.Fatal(err)
	}
	for _, username := range []string{"", "\ufffd"} {
		r.Destination.Username = username
		b, _ = json.Marshal(r)
		if _, err := DecodeRequest(b); err == nil {
			t.Fatal("accepted invalid user")
		}
	}
	// Boundary is the whole envelope, including whitespace.
	b, _ = json.Marshal(validRequest())
	b = append(b, bytes.Repeat([]byte(" "), MaxBytes-len(b))...)
	if _, err := DecodeRequest(b); err != nil {
		t.Fatal("rejected exact limit")
	}
	if _, err := DecodeRequest(append(b, ' ')); err == nil {
		t.Fatal("accepted oversize")
	}
}

func TestResponseCompatibility(t *testing.T) {
	r := validRequest()
	for _, operation := range []string{"confirm", "passphrase"} {
		r.Operation = operation
		for _, approved := range []bool{false, true} {
			var password []byte
			if operation == "passphrase" && approved {
				password = []byte("páss\nword")
			}
			b, err := EncodeResponse(r, approved, password)
			if err != nil {
				t.Fatal(err)
			}
			var response struct {
				Version    int
				RequestID  string `json:"request_id"`
				Approved   bool
				Passphrase []byte
			}
			if json.Unmarshal(b, &response) != nil || response.Version != 1 || response.RequestID != r.RequestID || response.Approved != approved || !bytes.Equal(response.Passphrase, password) {
				t.Fatalf("wire mismatch: %s", b)
			}
			if len(password) > 0 && bytes.Contains(b, password) {
				t.Fatal("plaintext passphrase on wire")
			}
		}
	}
	r.Operation = "passphrase"
	if _, err := EncodeResponse(r, true, bytes.Repeat([]byte("a"), MaxPassphraseBytes)); err != nil {
		t.Fatal(err)
	}
	for _, password := range [][]byte{nil, bytes.Repeat([]byte("a"), MaxPassphraseBytes+1), {0xff}} {
		if _, err := EncodeResponse(r, true, password); err == nil {
			t.Fatal("accepted invalid password")
		}
	}
	if _, err := EncodeResponse(r, false, []byte("secret")); err == nil {
		t.Fatal("denial included secret")
	}
	r.Operation = "confirm"
	if _, err := EncodeResponse(r, true, []byte("secret")); err == nil {
		t.Fatal("confirmation included secret")
	}
	r.RequestID = "bad"
	if _, err := EncodeResponse(r, false, nil); err == nil {
		t.Fatal("accepted bad ID")
	}
}

func FuzzDecodeRequest(f *testing.F) {
	b, _ := json.Marshal(validRequest())
	f.Add(b)
	f.Add([]byte(`{"version":null}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := DecodeRequest(b)
		if err == nil {
			encoded, e := json.Marshal(r)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = DecodeRequest(encoded); e != nil {
				t.Fatal(e)
			}
		}
	})
}
