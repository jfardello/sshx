package credential

import (
	"strings"
	"testing"
)

func TestCredentialTargetMapping(t *testing.T) {
	tests := []struct {
		name       string
		credential credentialRef
		query      string
		want       string
		wantError  string
	}{
		{
			name: "portable target takes priority",
			credential: secretServiceCredential("Login", "ignored", map[string]string{
				"sshx.target": "alice@portable.example",
				"URL":         "ssh://bob@url.example",
			}),
			want: "alice@portable.example",
		},
		{
			name: "KeePassXC URL user",
			credential: secretServiceCredential("Login", "ignored", map[string]string{
				"URL":      "ssh://url-user@example.com:2222/home",
				"UserName": "attribute-user",
			}),
			want: "url-user@example.com",
		},
		{
			name: "KeePassXC username attribute",
			credential: secretServiceCredential("Login", "ignored", map[string]string{
				"URL":      "ssh://example.com",
				"UserName": "attribute-user",
			}),
			want: "attribute-user@example.com",
		},
		{
			name: "KeePassXC IPv6 URL",
			credential: secretServiceCredential("Login", "ignored", map[string]string{
				"URL":      "ssh://[2001:db8::1]",
				"UserName": "alice",
			}),
			want: "alice@[2001:db8::1]",
		},
		{
			name:       "label fallback",
			credential: secretServiceCredential("Login", "host.example", nil),
			want:       "host.example",
		},
		{
			name: "non SSH URL falls back to label",
			credential: secretServiceCredential("Login", "host.example", map[string]string{
				"URL": "https://example.com",
			}),
			want: "host.example",
		},
		{
			name: "invalid portable target",
			credential: secretServiceCredential("Login", "host.example", map[string]string{
				"sshx.target": "alice@host example",
			}),
			wantError: "must not contain whitespace",
		},
		{
			name: "SSH URL without host",
			credential: secretServiceCredential("Login", "host.example", map[string]string{
				"URL": "ssh://",
			}),
			wantError: "host is empty",
		},
		{
			name:       "unsafe label",
			credential: secretServiceCredential("Login", "-oProxyCommand=bad", nil),
			wantError:  "cannot begin",
		},
		{
			name: "legacy gopass target",
			credential: credentialRef{
				Backend: credentialBackendGopass,
				ID:      "servers/alice@example.com",
			},
			query: "alice@example.com",
			want:  "alice@example.com",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := credentialTarget(test.credential, test.query)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("credentialTarget() error = %v, want %q", err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("credentialTarget() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestMatchCredentialsUsesDocumentedPriority(t *testing.T) {
	portable := secretServiceCredential("Login", "not-the-query", map[string]string{"sshx.target": "alice@example.com"})
	label := secretServiceCredential("Login", "alice@example.com", map[string]string{"sshx.target": "other@example.com"})
	identity := secretServiceCredential("Team", "server", map[string]string{"sshx.target": "third@example.com"})
	partial := secretServiceCredential("Other", "Alice Workstation", map[string]string{"sshx.target": "fourth@example.com"})

	tests := []struct {
		name        string
		query       string
		credentials []credentialRef
		wantID      string
	}{
		{name: "exact portable target", query: "alice@example.com", credentials: []credentialRef{label, portable}, wantID: portable.ID},
		{name: "exact label", query: "alice@example.com", credentials: []credentialRef{label, identity}, wantID: label.ID},
		{name: "exact collection identity", query: "Team/server", credentials: []credentialRef{identity, partial}, wantID: identity.ID},
		{name: "case insensitive partial", query: "workSTATION", credentials: []credentialRef{identity, partial}, wantID: partial.ID},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matches, err := matchCredentials(test.query, test.credentials)
			if err != nil {
				t.Fatal(err)
			}
			if len(matches) != 1 || matches[0].ID != test.wantID {
				t.Fatalf("matches = %#v, want ID %q", matches, test.wantID)
			}
			if matches[0].Target == "" {
				t.Fatal("resolved target is empty")
			}
		})
	}
}

func secretServiceCredential(collection, label string, attributes map[string]string) credentialRef {
	return credentialRef{
		Backend:    credentialBackendSecretService,
		ID:         collection + "/" + label,
		Collection: collection,
		Label:      label,
		Attributes: attributes,
	}
}
