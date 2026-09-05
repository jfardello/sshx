package main

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
)

type secretServicePropertyKey struct {
	path     dbus.ObjectPath
	property string
}

type secretServiceCallKey struct {
	path   dbus.ObjectPath
	method string
}

type recordedSecretServiceCall struct {
	path   dbus.ObjectPath
	method string
	args   []any
}

type fakeSecretServiceTransport struct {
	activateErr error
	properties  map[secretServicePropertyKey][]propertyResult
	calls       map[secretServiceCallKey][]*dbus.Call
	prompt      dbus.Variant
	dismissed   bool
	promptErr   error
	promptCalls []dbus.ObjectPath
	callLog     []recordedSecretServiceCall
	propertyLog []secretServicePropertyKey
	closeErr    error
	closeCalls  int
}

type propertyResult struct {
	value dbus.Variant
	err   error
}

func newFakeSecretServiceTransport() *fakeSecretServiceTransport {
	return &fakeSecretServiceTransport{
		properties: make(map[secretServicePropertyKey][]propertyResult),
		calls:      make(map[secretServiceCallKey][]*dbus.Call),
	}
}

func (f *fakeSecretServiceTransport) Activate() error { return f.activateErr }

func (f *fakeSecretServiceTransport) Call(
	objectPath dbus.ObjectPath,
	method string,
	args ...any,
) *dbus.Call {
	f.callLog = append(f.callLog, recordedSecretServiceCall{
		path: objectPath, method: method, args: append([]any(nil), args...),
	})
	key := secretServiceCallKey{path: objectPath, method: method}
	results := f.calls[key]
	if len(results) == 0 {
		return &dbus.Call{Err: errors.New("unexpected D-Bus call: " + method)}
	}
	result := results[0]
	f.calls[key] = results[1:]
	return result
}

func (f *fakeSecretServiceTransport) GetProperty(
	objectPath dbus.ObjectPath,
	property string,
) (dbus.Variant, error) {
	key := secretServicePropertyKey{path: objectPath, property: property}
	f.propertyLog = append(f.propertyLog, key)
	results := f.properties[key]
	if len(results) == 0 {
		return dbus.Variant{}, errors.New("unexpected D-Bus property: " + property)
	}
	result := results[0]
	if len(results) > 1 {
		f.properties[key] = results[1:]
	}
	return result.value, result.err
}

func (f *fakeSecretServiceTransport) Prompt(
	objectPath dbus.ObjectPath,
	_ string,
) (dbus.Variant, bool, error) {
	f.promptCalls = append(f.promptCalls, objectPath)
	return f.prompt, f.dismissed, f.promptErr
}

func (f *fakeSecretServiceTransport) Close() error {
	f.closeCalls++
	return f.closeErr
}

func (f *fakeSecretServiceTransport) setProperty(
	objectPath dbus.ObjectPath,
	property string,
	values ...any,
) {
	key := secretServicePropertyKey{path: objectPath, property: property}
	for _, value := range values {
		f.properties[key] = append(f.properties[key], propertyResult{value: dbus.MakeVariant(value)})
	}
}

func (f *fakeSecretServiceTransport) setPropertyError(
	objectPath dbus.ObjectPath,
	property string,
	err error,
) {
	key := secretServicePropertyKey{path: objectPath, property: property}
	f.properties[key] = []propertyResult{{err: err}}
}

func (f *fakeSecretServiceTransport) addCall(
	objectPath dbus.ObjectPath,
	method string,
	call *dbus.Call,
) {
	key := secretServiceCallKey{path: objectPath, method: method}
	f.calls[key] = append(f.calls[key], call)
}

func successfulSecretServiceCall(body ...any) *dbus.Call {
	return &dbus.Call{Body: body}
}

func TestSecretServiceSearchReturnsMetadataWithoutReadingSecrets(t *testing.T) {
	transport := newFakeSecretServiceTransport()
	collectionPath := dbus.ObjectPath("/org/freedesktop/secrets/collection/login")
	itemPath := dbus.ObjectPath("/org/freedesktop/secrets/collection/login/1")
	transport.setProperty(secretServicePath, secretServiceInterface+".Collections", []dbus.ObjectPath{collectionPath})
	transport.addCall(secretServicePath, secretServiceInterface+".ReadAlias", successfulSecretServiceCall(secretServiceNoPromptPath))
	transport.setProperty(collectionPath, secretServiceCollectionInterface+".Label", "Login")
	transport.setProperty(collectionPath, secretServiceCollectionInterface+".Locked", false)
	transport.setProperty(collectionPath, secretServiceCollectionInterface+".Items", []dbus.ObjectPath{itemPath})
	transport.setProperty(itemPath, secretServiceItemInterface+".Label", "host.example")
	transport.setProperty(itemPath, secretServiceItemInterface+".Attributes", map[string]string{
		"sshx.target": "alice@host.example",
		"application": "sshx",
	})
	transport.setProperty(itemPath, secretServiceItemInterface+".Locked", true)

	store := &secretServiceStore{transport: transport}
	credentials, err := store.Search(credentialQuery{Collection: "Login", Text: "host"})
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}
	want := []credentialRef{{
		Backend:    credentialBackendSecretService,
		ID:         string(itemPath),
		Collection: "Login",
		Label:      "host.example",
		Attributes: map[string]string{"sshx.target": "alice@host.example", "application": "sshx"},
		Locked:     true,
	}}
	if !reflect.DeepEqual(credentials, want) {
		t.Fatalf("Search() = %#v, want %#v", credentials, want)
	}
	if len(transport.callLog) != 1 || transport.callLog[0].method != secretServiceInterface+".ReadAlias" {
		t.Fatalf("Search() calls = %#v, want metadata-only ReadAlias", transport.callLog)
	}

	credentials[0].Attributes["application"] = "changed"
	if got := transport.properties[secretServicePropertyKey{itemPath, secretServiceItemInterface + ".Attributes"}][0].value.Value().(map[string]string)["application"]; got != "sshx" {
		t.Fatalf("Search() returned provider-owned attributes map; provider value = %q", got)
	}
}

func TestSecretServiceSearchScopesCollectionByPathName(t *testing.T) {
	transport := newFakeSecretServiceTransport()
	collectionPath := dbus.ObjectPath("/org/freedesktop/secrets/collection/login")
	transport.setProperty(secretServicePath, secretServiceInterface+".Collections", []dbus.ObjectPath{collectionPath})
	transport.addCall(secretServicePath, secretServiceInterface+".ReadAlias", successfulSecretServiceCall(secretServiceNoPromptPath))
	transport.setProperty(collectionPath, secretServiceCollectionInterface+".Label", "Default Keyring")
	transport.setProperty(collectionPath, secretServiceCollectionInterface+".Locked", false)
	transport.setProperty(collectionPath, secretServiceCollectionInterface+".Items", []dbus.ObjectPath{})

	store := &secretServiceStore{transport: transport}
	credentials, err := store.Search(credentialQuery{Collection: "login"})
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}
	if len(credentials) != 0 {
		t.Fatalf("Search() = %#v, want no credentials", credentials)
	}
}

func TestSecretServiceSearchScopesCollectionByAlias(t *testing.T) {
	transport := newFakeSecretServiceTransport()
	collectionPath := dbus.ObjectPath("/org/freedesktop/secrets/collection/generated_id")
	transport.setProperty(secretServicePath, secretServiceInterface+".Collections", []dbus.ObjectPath{collectionPath})
	transport.addCall(secretServicePath, secretServiceInterface+".ReadAlias", successfulSecretServiceCall(collectionPath))
	transport.setProperty(collectionPath, secretServiceCollectionInterface+".Label", "Default Keyring")
	transport.setProperty(collectionPath, secretServiceCollectionInterface+".Locked", false)
	transport.setProperty(collectionPath, secretServiceCollectionInterface+".Items", []dbus.ObjectPath{})

	store := &secretServiceStore{transport: transport}
	credentials, err := store.Search(credentialQuery{Collection: "default"})
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}
	if len(credentials) != 0 {
		t.Fatalf("Search() = %#v, want no credentials", credentials)
	}
}

func TestSecretServiceSearchRejectsDuplicateCollectionSelector(t *testing.T) {
	transport := newFakeSecretServiceTransport()
	firstPath := dbus.ObjectPath("/org/freedesktop/secrets/collection/first")
	secondPath := dbus.ObjectPath("/org/freedesktop/secrets/collection/second")
	transport.setProperty(
		secretServicePath,
		secretServiceInterface+".Collections",
		[]dbus.ObjectPath{firstPath, secondPath},
	)
	transport.addCall(secretServicePath, secretServiceInterface+".ReadAlias", successfulSecretServiceCall(secretServiceNoPromptPath))
	transport.setProperty(firstPath, secretServiceCollectionInterface+".Label", "Work")
	transport.setProperty(secondPath, secretServiceCollectionInterface+".Label", "Work")

	store := &secretServiceStore{transport: transport}
	_, err := store.Search(credentialQuery{Collection: "Work"})
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("Search() error = %v, want ambiguous collection error", err)
	}
	if len(transport.callLog) != 1 || transport.callLog[0].method != secretServiceInterface+".ReadAlias" {
		t.Fatalf("Search() calls = %#v, want only ReadAlias", transport.callLog)
	}
	for _, property := range transport.propertyLog {
		if strings.HasSuffix(property.property, ".Locked") || strings.HasSuffix(property.property, ".Items") {
			t.Fatalf("Search() accessed %q before rejecting duplicate collections", property.property)
		}
	}
}

func TestSecretServiceSearchUnlocksCollection(t *testing.T) {
	transport := newFakeSecretServiceTransport()
	collectionPath := dbus.ObjectPath("/org/freedesktop/secrets/collection/login")
	transport.setProperty(secretServicePath, secretServiceInterface+".Collections", []dbus.ObjectPath{collectionPath})
	transport.setProperty(collectionPath, secretServiceCollectionInterface+".Label", "Login")
	transport.setProperty(collectionPath, secretServiceCollectionInterface+".Locked", true, false)
	transport.setProperty(collectionPath, secretServiceCollectionInterface+".Items", []dbus.ObjectPath{})
	transport.addCall(secretServicePath, secretServiceInterface+".Unlock", successfulSecretServiceCall(
		[]dbus.ObjectPath{collectionPath}, secretServiceNoPromptPath,
	))

	store := &secretServiceStore{transport: transport}
	if _, err := store.Search(credentialQuery{}); err != nil {
		t.Fatalf("Search() error = %v", err)
	}
	if len(transport.callLog) != 1 || transport.callLog[0].method != secretServiceInterface+".Unlock" {
		t.Fatalf("Search() calls = %#v, want one Unlock call", transport.callLog)
	}
	if len(transport.promptCalls) != 0 {
		t.Fatalf("Search() prompt calls = %#v, want none", transport.promptCalls)
	}
}

func TestSecretServiceSecretRetrievesOnlySelectedUnlockedItem(t *testing.T) {
	transport := newFakeSecretServiceTransport()
	itemPath := dbus.ObjectPath("/org/freedesktop/secrets/collection/login/1")
	sessionPath := dbus.ObjectPath("/org/freedesktop/secrets/session/1")
	responseValue := []byte("hunter2")
	transport.setProperty(itemPath, secretServiceItemInterface+".Locked", false)
	transport.addCall(secretServicePath, secretServiceInterface+".OpenSession", successfulSecretServiceCall(
		dbus.MakeVariant([]byte{}), sessionPath,
	))
	transport.addCall(itemPath, secretServiceItemInterface+".GetSecret", successfulSecretServiceCall(
		[]any{sessionPath, []byte{}, responseValue, "text/plain"},
	))
	transport.addCall(sessionPath, secretServiceSessionInterface+".Close", successfulSecretServiceCall())

	store := &secretServiceStore{transport: transport}
	secret, err := store.Secret(credentialRef{Backend: credentialBackendSecretService, ID: string(itemPath)})
	if err != nil {
		t.Fatalf("Secret() error = %v", err)
	}
	if got := string(secret); got != "hunter2" {
		t.Fatalf("Secret() = %q, want hunter2", got)
	}
	if got := string(responseValue); got != strings.Repeat("\x00", len(responseValue)) {
		t.Fatalf("provider response was not cleared: %q", got)
	}
	wantMethods := []string{
		secretServiceInterface + ".OpenSession",
		secretServiceItemInterface + ".GetSecret",
		secretServiceSessionInterface + ".Close",
	}
	for index, method := range wantMethods {
		if transport.callLog[index].method != method {
			t.Fatalf("call %d = %q, want %q", index, transport.callLog[index].method, method)
		}
	}
	if got := transport.callLog[1].path; got != itemPath {
		t.Fatalf("GetSecret path = %q, want %q", got, itemPath)
	}
}

func TestSecretServiceSecretCompletesUnlockPrompt(t *testing.T) {
	transport := newFakeSecretServiceTransport()
	itemPath := dbus.ObjectPath("/org/freedesktop/secrets/collection/login/1")
	promptPath := dbus.ObjectPath("/org/freedesktop/secrets/prompt/1")
	sessionPath := dbus.ObjectPath("/org/freedesktop/secrets/session/1")
	transport.setProperty(itemPath, secretServiceItemInterface+".Locked", true, false)
	transport.addCall(secretServicePath, secretServiceInterface+".Unlock", successfulSecretServiceCall(
		[]dbus.ObjectPath{}, promptPath,
	))
	transport.prompt = dbus.MakeVariant([]dbus.ObjectPath{itemPath})
	transport.addCall(secretServicePath, secretServiceInterface+".OpenSession", successfulSecretServiceCall(
		dbus.MakeVariant(""), sessionPath,
	))
	transport.addCall(itemPath, secretServiceItemInterface+".GetSecret", successfulSecretServiceCall(
		[]any{sessionPath, []byte{}, []byte("password"), "text/plain"},
	))
	transport.addCall(sessionPath, secretServiceSessionInterface+".Close", successfulSecretServiceCall())

	store := &secretServiceStore{transport: transport}
	secret, err := store.Secret(credentialRef{Backend: credentialBackendSecretService, ID: string(itemPath)})
	if err != nil {
		t.Fatalf("Secret() error = %v", err)
	}
	clearBytes(secret)
	if !reflect.DeepEqual(transport.promptCalls, []dbus.ObjectPath{promptPath}) {
		t.Fatalf("Prompt calls = %#v, want %q", transport.promptCalls, promptPath)
	}
}

func TestSecretServicePromptDismissalIsVisible(t *testing.T) {
	transport := newFakeSecretServiceTransport()
	itemPath := dbus.ObjectPath("/org/freedesktop/secrets/collection/login/1")
	promptPath := dbus.ObjectPath("/org/freedesktop/secrets/prompt/1")
	transport.setProperty(itemPath, secretServiceItemInterface+".Locked", true)
	transport.addCall(secretServicePath, secretServiceInterface+".Unlock", successfulSecretServiceCall(
		[]dbus.ObjectPath{}, promptPath,
	))
	transport.dismissed = true

	store := &secretServiceStore{transport: transport}
	_, err := store.Secret(credentialRef{Backend: credentialBackendSecretService, ID: string(itemPath)})
	var dismissed *secretServicePromptDismissedError
	if !errors.As(err, &dismissed) {
		t.Fatalf("Secret() error = %v, want prompt dismissal error", err)
	}
	if isCredentialBackendUnavailable(err) {
		t.Fatalf("prompt dismissal was incorrectly classified as unavailable: %v", err)
	}
}

func TestSecretServiceAccessDenialIsNotUnavailable(t *testing.T) {
	transport := newFakeSecretServiceTransport()
	itemPath := dbus.ObjectPath("/org/freedesktop/secrets/collection/login/1")
	denied := dbus.NewError("org.freedesktop.DBus.Error.AccessDenied", []any{"denied"})
	transport.setPropertyError(itemPath, secretServiceItemInterface+".Locked", denied)

	store := &secretServiceStore{transport: transport}
	_, err := store.Secret(credentialRef{Backend: credentialBackendSecretService, ID: string(itemPath)})
	if !errors.Is(err, denied) {
		t.Fatalf("Secret() error = %v, want access denial", err)
	}
	if isCredentialBackendUnavailable(err) {
		t.Fatalf("access denial was incorrectly classified as unavailable: %v", err)
	}
}

func TestSecretServiceRejectsMalformedResponses(t *testing.T) {
	t.Run("collections property", func(t *testing.T) {
		transport := newFakeSecretServiceTransport()
		transport.setProperty(secretServicePath, secretServiceInterface+".Collections", "not paths")
		store := &secretServiceStore{transport: transport}
		if _, err := store.Search(credentialQuery{}); err == nil || !strings.Contains(err.Error(), "expected object paths") {
			t.Fatalf("Search() error = %v, want malformed property error", err)
		}
	})

	t.Run("object path", func(t *testing.T) {
		transport := newFakeSecretServiceTransport()
		transport.setProperty(secretServicePath, secretServiceInterface+".Collections", []dbus.ObjectPath{"/"})
		store := &secretServiceStore{transport: transport}
		if _, err := store.Search(credentialQuery{}); err == nil || !strings.Contains(err.Error(), "collection path") {
			t.Fatalf("Search() error = %v, want malformed object path error", err)
		}
	})

	t.Run("plain session", func(t *testing.T) {
		transport := newFakeSecretServiceTransport()
		itemPath := dbus.ObjectPath("/org/freedesktop/secrets/collection/login/1")
		transport.setProperty(itemPath, secretServiceItemInterface+".Locked", false)
		transport.addCall(secretServicePath, secretServiceInterface+".OpenSession", successfulSecretServiceCall(
			dbus.MakeVariant("unexpected"), dbus.ObjectPath("/org/freedesktop/secrets/session/1"),
		))
		transport.addCall(
			dbus.ObjectPath("/org/freedesktop/secrets/session/1"),
			secretServiceSessionInterface+".Close",
			successfulSecretServiceCall(),
		)
		store := &secretServiceStore{transport: transport}
		if _, err := store.Secret(credentialRef{Backend: credentialBackendSecretService, ID: string(itemPath)}); err == nil || !strings.Contains(err.Error(), "plain session output") {
			t.Fatalf("Secret() error = %v, want malformed session error", err)
		}
		if got := transport.callLog[len(transport.callLog)-1].method; got != secretServiceSessionInterface+".Close" {
			t.Fatalf("last call = %q, want session Close", got)
		}
	})

	t.Run("non-empty byte-array plain session", func(t *testing.T) {
		transport := newFakeSecretServiceTransport()
		itemPath := dbus.ObjectPath("/org/freedesktop/secrets/collection/login/1")
		sessionPath := dbus.ObjectPath("/org/freedesktop/secrets/session/1")
		output := []byte("unexpected")
		transport.setProperty(itemPath, secretServiceItemInterface+".Locked", false)
		transport.addCall(secretServicePath, secretServiceInterface+".OpenSession", successfulSecretServiceCall(
			dbus.MakeVariant(output), sessionPath,
		))
		transport.addCall(sessionPath, secretServiceSessionInterface+".Close", successfulSecretServiceCall())
		store := &secretServiceStore{transport: transport}
		if _, err := store.Secret(credentialRef{Backend: credentialBackendSecretService, ID: string(itemPath)}); err == nil || !strings.Contains(err.Error(), "plain session output") {
			t.Fatalf("Secret() error = %v, want malformed session error", err)
		}
		if got := string(output); got != strings.Repeat("\x00", len(output)) {
			t.Fatalf("plain session output was not cleared: %q", got)
		}
		if got := transport.callLog[len(transport.callLog)-1].method; got != secretServiceSessionInterface+".Close" {
			t.Fatalf("last call = %q, want session Close", got)
		}
	})

	t.Run("secret session", func(t *testing.T) {
		transport := newFakeSecretServiceTransport()
		itemPath := dbus.ObjectPath("/org/freedesktop/secrets/collection/login/1")
		sessionPath := dbus.ObjectPath("/org/freedesktop/secrets/session/1")
		transport.setProperty(itemPath, secretServiceItemInterface+".Locked", false)
		transport.addCall(secretServicePath, secretServiceInterface+".OpenSession", successfulSecretServiceCall(
			dbus.MakeVariant(""), sessionPath,
		))
		transport.addCall(itemPath, secretServiceItemInterface+".GetSecret", successfulSecretServiceCall(
			[]any{dbus.ObjectPath("/org/freedesktop/secrets/session/other"), []byte{}, []byte("password"), "text/plain"},
		))
		transport.addCall(sessionPath, secretServiceSessionInterface+".Close", successfulSecretServiceCall())
		store := &secretServiceStore{transport: transport}
		if _, err := store.Secret(credentialRef{Backend: credentialBackendSecretService, ID: string(itemPath)}); err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("Secret() error = %v, want malformed secret error", err)
		}
	})

	t.Run("secret parameters", func(t *testing.T) {
		transport := newFakeSecretServiceTransport()
		itemPath := dbus.ObjectPath("/org/freedesktop/secrets/collection/login/1")
		sessionPath := dbus.ObjectPath("/org/freedesktop/secrets/session/1")
		transport.setProperty(itemPath, secretServiceItemInterface+".Locked", false)
		transport.addCall(secretServicePath, secretServiceInterface+".OpenSession", successfulSecretServiceCall(
			dbus.MakeVariant(""), sessionPath,
		))
		transport.addCall(itemPath, secretServiceItemInterface+".GetSecret", successfulSecretServiceCall(
			[]any{sessionPath, []byte{1}, []byte("password"), "text/plain"},
		))
		transport.addCall(sessionPath, secretServiceSessionInterface+".Close", successfulSecretServiceCall())
		store := &secretServiceStore{transport: transport}
		if _, err := store.Secret(credentialRef{Backend: credentialBackendSecretService, ID: string(itemPath)}); err == nil || !strings.Contains(err.Error(), "returned parameters") {
			t.Fatalf("Secret() error = %v, want malformed parameters error", err)
		}
	})

	t.Run("prompt result", func(t *testing.T) {
		transport := newFakeSecretServiceTransport()
		itemPath := dbus.ObjectPath("/org/freedesktop/secrets/collection/login/1")
		promptPath := dbus.ObjectPath("/org/freedesktop/secrets/prompt/1")
		transport.setProperty(itemPath, secretServiceItemInterface+".Locked", true)
		transport.addCall(secretServicePath, secretServiceInterface+".Unlock", successfulSecretServiceCall(
			[]dbus.ObjectPath{}, promptPath,
		))
		transport.prompt = dbus.MakeVariant("not paths")
		store := &secretServiceStore{transport: transport}
		if _, err := store.Secret(credentialRef{Backend: credentialBackendSecretService, ID: string(itemPath)}); err == nil || !strings.Contains(err.Error(), "prompt result") {
			t.Fatalf("Secret() error = %v, want malformed prompt error", err)
		}
	})
}

func TestSecretServiceRejectsMalformedItemProperties(t *testing.T) {
	tests := []struct {
		name       string
		property   string
		value      any
		wantPhrase string
	}{
		{name: "label", property: secretServiceItemInterface + ".Label", value: false, wantPhrase: "expected string"},
		{name: "attributes", property: secretServiceItemInterface + ".Attributes", value: []string{"invalid"}, wantPhrase: "expected string map"},
		{name: "locked", property: secretServiceItemInterface + ".Locked", value: "false", wantPhrase: "expected boolean"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transport := newFakeSecretServiceTransport()
			itemPath := dbus.ObjectPath("/org/freedesktop/secrets/collection/login/1")
			transport.setProperty(itemPath, secretServiceItemInterface+".Label", "host")
			transport.setProperty(itemPath, secretServiceItemInterface+".Attributes", map[string]string{})
			transport.setProperty(itemPath, secretServiceItemInterface+".Locked", false)
			transport.setProperty(itemPath, test.property, test.value)

			// Put the malformed value first when the property was pre-populated above.
			key := secretServicePropertyKey{path: itemPath, property: test.property}
			values := transport.properties[key]
			transport.properties[key] = append(values[len(values)-1:], values[:len(values)-1]...)

			store := &secretServiceStore{transport: transport}
			if _, err := store.itemMetadata("Login", itemPath); err == nil || !strings.Contains(err.Error(), test.wantPhrase) {
				t.Fatalf("itemMetadata() error = %v, want %q", err, test.wantPhrase)
			}
		})
	}
}

func TestSecretServiceRejectsNilProviderCalls(t *testing.T) {
	t.Run("open session", func(t *testing.T) {
		transport := newFakeSecretServiceTransport()
		itemPath := dbus.ObjectPath("/org/freedesktop/secrets/collection/login/1")
		transport.setProperty(itemPath, secretServiceItemInterface+".Locked", false)
		transport.calls[secretServiceCallKey{secretServicePath, secretServiceInterface + ".OpenSession"}] = []*dbus.Call{nil}
		store := &secretServiceStore{transport: transport}
		if _, err := store.Secret(credentialRef{Backend: credentialBackendSecretService, ID: string(itemPath)}); err == nil || !strings.Contains(err.Error(), "nil OpenSession") {
			t.Fatalf("Secret() error = %v, want nil call error", err)
		}
	})

	t.Run("get secret", func(t *testing.T) {
		transport := newFakeSecretServiceTransport()
		itemPath := dbus.ObjectPath("/org/freedesktop/secrets/collection/login/1")
		sessionPath := dbus.ObjectPath("/org/freedesktop/secrets/session/1")
		transport.setProperty(itemPath, secretServiceItemInterface+".Locked", false)
		transport.addCall(secretServicePath, secretServiceInterface+".OpenSession", successfulSecretServiceCall(dbus.MakeVariant(""), sessionPath))
		transport.calls[secretServiceCallKey{itemPath, secretServiceItemInterface + ".GetSecret"}] = []*dbus.Call{nil}
		transport.addCall(sessionPath, secretServiceSessionInterface+".Close", successfulSecretServiceCall())
		store := &secretServiceStore{transport: transport}
		if _, err := store.Secret(credentialRef{Backend: credentialBackendSecretService, ID: string(itemPath)}); err == nil || !strings.Contains(err.Error(), "nil GetSecret") {
			t.Fatalf("Secret() error = %v, want nil call error", err)
		}
	})

	t.Run("unlock", func(t *testing.T) {
		transport := newFakeSecretServiceTransport()
		itemPath := dbus.ObjectPath("/org/freedesktop/secrets/collection/login/1")
		transport.setProperty(itemPath, secretServiceItemInterface+".Locked", true)
		transport.calls[secretServiceCallKey{secretServicePath, secretServiceInterface + ".Unlock"}] = []*dbus.Call{nil}
		store := &secretServiceStore{transport: transport}
		if _, err := store.Secret(credentialRef{Backend: credentialBackendSecretService, ID: string(itemPath)}); err == nil || !strings.Contains(err.Error(), "nil Unlock") {
			t.Fatalf("Secret() error = %v, want nil call error", err)
		}
	})
}

func TestSecretServiceRejectsInvalidCredentialReferences(t *testing.T) {
	store := &secretServiceStore{transport: newFakeSecretServiceTransport()}
	if _, err := store.Secret(credentialRef{Backend: credentialBackendGopass, ID: "entry"}); err == nil || !strings.Contains(err.Error(), "backend") {
		t.Fatalf("Secret() error = %v, want backend mismatch", err)
	}
	if _, err := store.Secret(credentialRef{Backend: credentialBackendSecretService, ID: "/"}); err == nil || !strings.Contains(err.Error(), "item path") {
		t.Fatalf("Secret() error = %v, want invalid item path", err)
	}
}

func TestClearSecretServiceCallBodyClearsEverySecretRepresentation(t *testing.T) {
	direct := []byte("direct")
	nested := []byte("nested")
	structValue := []byte("struct")
	pointerValue := []byte("pointer")
	values := []any{
		direct,
		[]any{nested},
		secretServiceSecret{Value: structValue},
		&secretServiceSecret{Value: pointerValue},
		(*secretServiceSecret)(nil),
	}

	clearSecretServiceCallBody(values)
	for name, value := range map[string][]byte{
		"direct": direct, "nested": nested, "struct": structValue, "pointer": pointerValue,
	} {
		if strings.Trim(string(value), "\x00") != "" {
			t.Fatalf("%s secret was not cleared: %q", name, value)
		}
	}
}

func TestSecretServiceUnlockFailuresRemainVisible(t *testing.T) {
	itemPath := dbus.ObjectPath("/org/freedesktop/secrets/collection/login/1")
	promptPath := dbus.ObjectPath("/org/freedesktop/secrets/prompt/1")

	t.Run("prompt provider failure", func(t *testing.T) {
		transport := newFakeSecretServiceTransport()
		providerErr := errors.New("prompt provider failed")
		transport.setProperty(itemPath, secretServiceItemInterface+".Locked", true)
		transport.addCall(secretServicePath, secretServiceInterface+".Unlock", successfulSecretServiceCall([]dbus.ObjectPath{}, promptPath))
		transport.promptErr = providerErr
		store := &secretServiceStore{transport: transport}
		_, err := store.Secret(credentialRef{Backend: credentialBackendSecretService, ID: string(itemPath)})
		if !errors.Is(err, providerErr) || isCredentialBackendUnavailable(err) {
			t.Fatalf("Secret() error = %v, want provider error", err)
		}
	})

	t.Run("object remains locked", func(t *testing.T) {
		transport := newFakeSecretServiceTransport()
		transport.setProperty(itemPath, secretServiceItemInterface+".Locked", true, true)
		transport.addCall(secretServicePath, secretServiceInterface+".Unlock", successfulSecretServiceCall([]dbus.ObjectPath{itemPath}, secretServiceNoPromptPath))
		store := &secretServiceStore{transport: transport}
		_, err := store.Secret(credentialRef{Backend: credentialBackendSecretService, ID: string(itemPath)})
		if err == nil || !strings.Contains(err.Error(), "remains locked") {
			t.Fatalf("Secret() error = %v, want remains-locked error", err)
		}
	})

	t.Run("malformed unlocked path", func(t *testing.T) {
		transport := newFakeSecretServiceTransport()
		transport.setProperty(itemPath, secretServiceItemInterface+".Locked", true)
		transport.addCall(secretServicePath, secretServiceInterface+".Unlock", successfulSecretServiceCall([]dbus.ObjectPath{"invalid"}, secretServiceNoPromptPath))
		store := &secretServiceStore{transport: transport}
		_, err := store.Secret(credentialRef{Backend: credentialBackendSecretService, ID: string(itemPath)})
		if err == nil || !strings.Contains(err.Error(), "unlock path") {
			t.Fatalf("Secret() error = %v, want malformed unlock path error", err)
		}
	})
}

func TestNewSecretServiceStoreClassifiesAvailability(t *testing.T) {
	t.Run("unsupported platform", func(t *testing.T) {
		connected := false
		_, err := newSecretServiceStoreForOS("darwin", func() (secretServiceTransport, error) {
			connected = true
			return nil, nil
		})
		if !isCredentialBackendUnavailable(err) || connected {
			t.Fatalf("new store error = %v, connected = %v", err, connected)
		}
	})

	t.Run("missing session bus", func(t *testing.T) {
		_, err := newSecretServiceStoreForOS("linux", func() (secretServiceTransport, error) {
			return nil, errors.New("no session bus")
		})
		if !isCredentialBackendUnavailable(err) {
			t.Fatalf("new store error = %v, want unavailable", err)
		}
	})

	t.Run("connector returns no transport", func(t *testing.T) {
		_, err := newSecretServiceStoreForOS("linux", func() (secretServiceTransport, error) {
			return nil, nil
		})
		if !isCredentialBackendUnavailable(err) {
			t.Fatalf("new store error = %v, want unavailable", err)
		}
	})

	t.Run("session bus permission denied", func(t *testing.T) {
		_, err := newSecretServiceStoreForOS("linux", func() (secretServiceTransport, error) {
			return nil, os.ErrPermission
		})
		if !errors.Is(err, os.ErrPermission) || isCredentialBackendUnavailable(err) {
			t.Fatalf("new store error = %v, want non-unavailable permission error", err)
		}
	})

	t.Run("missing service", func(t *testing.T) {
		transport := newFakeSecretServiceTransport()
		transport.activateErr = dbus.NewError("org.freedesktop.DBus.Error.ServiceUnknown", nil)
		_, err := newSecretServiceStoreForOS("linux", func() (secretServiceTransport, error) {
			return transport, nil
		})
		if !isCredentialBackendUnavailable(err) || transport.closeCalls != 1 {
			t.Fatalf("new store error = %v, close calls = %d", err, transport.closeCalls)
		}
	})

	t.Run("service cannot be activated", func(t *testing.T) {
		transport := newFakeSecretServiceTransport()
		transport.activateErr = dbus.NewError("org.freedesktop.DBus.Error.Spawn.ChildExited", nil)
		_, err := newSecretServiceStoreForOS("linux", func() (secretServiceTransport, error) {
			return transport, nil
		})
		if !isCredentialBackendUnavailable(err) || transport.closeCalls != 1 {
			t.Fatalf("new store error = %v, close calls = %d", err, transport.closeCalls)
		}
	})

	t.Run("activation denied", func(t *testing.T) {
		transport := newFakeSecretServiceTransport()
		denied := dbus.NewError("org.freedesktop.DBus.Error.AccessDenied", nil)
		transport.activateErr = denied
		_, err := newSecretServiceStoreForOS("linux", func() (secretServiceTransport, error) {
			return transport, nil
		})
		if !errors.Is(err, denied) || isCredentialBackendUnavailable(err) || transport.closeCalls != 1 {
			t.Fatalf("new store error = %v, close calls = %d", err, transport.closeCalls)
		}
	})

	t.Run("activation and connection cleanup errors", func(t *testing.T) {
		transport := newFakeSecretServiceTransport()
		activationErr := errors.New("provider activation failed")
		cleanupErr := errors.New("connection cleanup failed")
		transport.activateErr = activationErr
		transport.closeErr = cleanupErr
		_, err := newSecretServiceStoreForOS("linux", func() (secretServiceTransport, error) {
			return transport, nil
		})
		if !errors.Is(err, activationErr) || !errors.Is(err, cleanupErr) {
			t.Fatalf("new store error = %v, want activation and cleanup errors", err)
		}
		if isCredentialBackendUnavailable(err) {
			t.Fatalf("provider failure was incorrectly classified as unavailable: %v", err)
		}
	})

	t.Run("close is idempotent", func(t *testing.T) {
		transport := newFakeSecretServiceTransport()
		closeErr := errors.New("close failed")
		transport.closeErr = closeErr
		store, err := newSecretServiceStoreForOS("linux", func() (secretServiceTransport, error) {
			return transport, nil
		})
		if err != nil {
			t.Fatalf("new store error = %v", err)
		}
		if err := store.Close(); !errors.Is(err, closeErr) {
			t.Fatalf("Close() error = %v, want %v", err, closeErr)
		}
		if err := store.Close(); !errors.Is(err, closeErr) {
			t.Fatalf("second Close() error = %v, want %v", err, closeErr)
		}
		if transport.closeCalls != 1 {
			t.Fatalf("transport close calls = %d, want 1", transport.closeCalls)
		}
	})
}

func TestSecretServiceSecretPreservesOperationAndCleanupErrors(t *testing.T) {
	transport := newFakeSecretServiceTransport()
	itemPath := dbus.ObjectPath("/org/freedesktop/secrets/collection/login/1")
	sessionPath := dbus.ObjectPath("/org/freedesktop/secrets/session/1")
	operationErr := errors.New("provider failed")
	cleanupErr := errors.New("session cleanup failed")
	transport.setProperty(itemPath, secretServiceItemInterface+".Locked", false)
	transport.addCall(secretServicePath, secretServiceInterface+".OpenSession", successfulSecretServiceCall(
		dbus.MakeVariant(""), sessionPath,
	))
	transport.addCall(itemPath, secretServiceItemInterface+".GetSecret", &dbus.Call{Err: operationErr})
	transport.addCall(sessionPath, secretServiceSessionInterface+".Close", &dbus.Call{Err: cleanupErr})

	store := &secretServiceStore{transport: transport}
	_, err := store.Secret(credentialRef{Backend: credentialBackendSecretService, ID: string(itemPath)})
	if !errors.Is(err, operationErr) || !errors.Is(err, cleanupErr) {
		t.Fatalf("Secret() error = %v, want operation and cleanup errors", err)
	}
}

func TestSecretServiceSecretClearsResultWhenSessionCleanupFails(t *testing.T) {
	transport := newFakeSecretServiceTransport()
	itemPath := dbus.ObjectPath("/org/freedesktop/secrets/collection/login/1")
	sessionPath := dbus.ObjectPath("/org/freedesktop/secrets/session/1")
	cleanupErr := errors.New("session cleanup failed")
	transport.setProperty(itemPath, secretServiceItemInterface+".Locked", false)
	transport.addCall(secretServicePath, secretServiceInterface+".OpenSession", successfulSecretServiceCall(
		dbus.MakeVariant(""), sessionPath,
	))
	transport.addCall(itemPath, secretServiceItemInterface+".GetSecret", successfulSecretServiceCall(
		[]any{sessionPath, []byte{}, []byte("password"), "text/plain"},
	))
	transport.addCall(sessionPath, secretServiceSessionInterface+".Close", &dbus.Call{Err: cleanupErr})

	store := &secretServiceStore{transport: transport}
	secret, err := store.Secret(credentialRef{Backend: credentialBackendSecretService, ID: string(itemPath)})
	if !errors.Is(err, cleanupErr) {
		t.Fatalf("Secret() error = %v, want cleanup error", err)
	}
	if secret != nil {
		t.Fatalf("Secret() returned bytes with a cleanup error: %q", secret)
	}
}
