package secretservice

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"runtime"
	"strings"
	"sync"

	"github.com/godbus/dbus/v5"
)

const (
	secretServiceBusName             = "org.freedesktop.secrets"
	secretServicePath                = dbus.ObjectPath("/org/freedesktop/secrets")
	secretServiceInterface           = "org.freedesktop.Secret.Service"
	secretServiceCollectionInterface = "org.freedesktop.Secret.Collection"
	secretServiceItemInterface       = "org.freedesktop.Secret.Item"
	secretServiceSessionInterface    = "org.freedesktop.Secret.Session"
	secretServicePromptInterface     = "org.freedesktop.Secret.Prompt"
	secretServiceNoPromptPath        = dbus.ObjectPath("/")
)

type secretServiceSecret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

type secretServiceTransport interface {
	Activate() error
	Call(objectPath dbus.ObjectPath, method string, args ...any) *dbus.Call
	GetProperty(objectPath dbus.ObjectPath, property string) (dbus.Variant, error)
	Prompt(objectPath dbus.ObjectPath, windowID string) (dbus.Variant, bool, error)
	Close() error
	WithContext(context.Context) secretServiceTransport
	Owner(context.Context) (string, error)
	WithOwner(string) secretServiceTransport
}

type dbusSecretServiceTransport struct {
	conn             *dbus.Conn
	ctx              context.Context
	destination      string
	cancelConnection context.CancelFunc
}

// The connection outlives the operation context after successful setup. During
// setup, cancellation closes an authenticated or still-authenticating connection.
func connectSecretServiceTransport(ctx context.Context, options ...dbus.ConnOption) (secretServiceTransport, error) {
	ctx, timeout := context.WithTimeout(ctx, credentialOperationTimeout)
	defer timeout()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	connectionContext, cancelConnection := context.WithCancel(context.Background())
	stop := context.AfterFunc(ctx, cancelConnection)
	type result struct {
		conn *dbus.Conn
		err  error
	}
	results := make(chan result)
	go func() {
		conn, err := dbus.ConnectSessionBus(append(options, dbus.WithContext(connectionContext))...)
		select {
		case results <- result{conn, err}:
		case <-ctx.Done():
			if conn != nil {
				_ = conn.Close()
			}
		}
	}()
	select {
	case <-ctx.Done():
		stop()
		cancelConnection()
		return nil, ctx.Err()
	case result := <-results:
		if !stop() || ctx.Err() != nil {
			cancelConnection()
			if result.conn != nil {
				_ = result.conn.Close()
			}
			return nil, ctx.Err()
		}
		if result.err != nil {
			cancelConnection()
			return nil, result.err
		}
		return &dbusSecretServiceTransport{conn: result.conn, cancelConnection: cancelConnection}, nil
	}
}

func (t *dbusSecretServiceTransport) Activate() error {
	var result uint32
	err := t.conn.BusObject().CallWithContext(t.context(),
		"org.freedesktop.DBus.StartServiceByName",
		0,
		secretServiceBusName,
		uint32(0),
	).Store(&result)
	if err != nil {
		return err
	}
	if result != 1 && result != 2 {
		return fmt.Errorf("unexpected StartServiceByName result %d", result)
	}
	return nil
}

func (t *dbusSecretServiceTransport) Call(
	objectPath dbus.ObjectPath,
	method string,
	args ...any,
) *dbus.Call {
	return t.conn.Object(t.busName(), objectPath).CallWithContext(t.context(), method, 0, args...)
}

func (t *dbusSecretServiceTransport) GetProperty(
	objectPath dbus.ObjectPath,
	property string,
) (dbus.Variant, error) {
	i := strings.LastIndex(property, ".")
	var result dbus.Variant
	err := t.Call(objectPath, "org.freedesktop.DBus.Properties.Get", property[:i], property[i+1:]).Store(&result)
	return result, err
}

func (t *dbusSecretServiceTransport) Prompt(
	objectPath dbus.ObjectPath,
	windowID string,
) (result dbus.Variant, dismissed bool, returnErr error) {
	owner, err := t.Owner(t.context())
	if err != nil {
		return dbus.Variant{}, false, err
	}
	pinned := t.WithOwner(owner)
	options := []dbus.MatchOption{
		dbus.WithMatchObjectPath(objectPath),
		dbus.WithMatchInterface(secretServicePromptInterface),
		dbus.WithMatchMember("Completed"),
		dbus.WithMatchSender(owner),
	}
	signals := make(chan *dbus.Signal, 1)
	t.conn.Signal(signals)
	defer t.conn.RemoveSignal(signals)

	if err := t.conn.AddMatchSignalContext(t.context(), options...); err != nil {
		return dbus.Variant{}, false, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), credentialCleanupTimeout)
		defer cancel()
		if t.context().Err() != nil {
			_ = pinned.WithContext(cleanup).Call(objectPath, secretServicePromptInterface+".Dismiss").Store()
		}
		if err := t.conn.RemoveMatchSignalContext(cleanup, options...); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("remove prompt signal match: %w", err))
		}
	}()

	if call := pinned.Call(
		objectPath,
		secretServicePromptInterface+".Prompt",
		windowID,
	); call == nil {
		return dbus.Variant{}, false, errors.New("Secret Service returned a nil prompt call")
	} else if err := call.Store(); err != nil {
		return dbus.Variant{}, false, err
	}

	for {
		var signal *dbus.Signal
		select {
		case <-t.context().Done():
			return dbus.Variant{}, false, t.context().Err()
		case <-t.conn.Context().Done():
			return dbus.Variant{}, false, errCredentialProviderChanged
		case signal = <-signals:
		}
		if signal == nil || signal.Sender != owner || signal.Path != objectPath ||
			signal.Name != secretServicePromptInterface+".Completed" {
			continue
		}
		if err := dbus.Store(signal.Body, &dismissed, &result); err != nil {
			return dbus.Variant{}, false, fmt.Errorf("malformed prompt result: %w", err)
		}
		return result, dismissed, nil
	}

}

func (t *dbusSecretServiceTransport) Close() error {
	if t.cancelConnection != nil {
		defer t.cancelConnection()
	}
	return t.conn.Close()
}

type secretServiceStore struct {
	transport secretServiceTransport
	closeOnce sync.Once
	closeErr  error
}

func newSecretServiceStore(ctx context.Context) (credentialStore, error) {
	return newSecretServiceStoreForOS(runtime.GOOS, func() (secretServiceTransport, error) { return connectSecretServiceTransport(ctx) }, ctx)
}

func newSecretServiceStoreForOS(
	goos string,
	connect func() (secretServiceTransport, error),
	contexts ...context.Context,
) (credentialStore, error) {
	ctx := context.Background()
	if len(contexts) > 0 {
		ctx = contexts[0]
	}
	ctx, cancel := context.WithTimeout(ctx, credentialOperationTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !secretServiceSupportedOS(goos) {
		return nil, newCredentialBackendUnavailableError(
			credentialBackendSecretService,
			fmt.Errorf("unsupported operating system %q", goos),
		)
	}

	transport, err := connect()
	if err != nil {
		return nil, classifySecretServiceConnectionError(err)
	}
	if transport == nil {
		return nil, newCredentialBackendUnavailableError(
			credentialBackendSecretService,
			errors.New("D-Bus connector returned no transport"),
		)
	}

	if err := transport.WithContext(ctx).Activate(); err != nil {
		activationErr := classifySecretServiceActivationError(err)
		if closeErr := transport.Close(); closeErr != nil {
			activationErr = errors.Join(activationErr, fmt.Errorf("close D-Bus connection: %w", closeErr))
		}
		return nil, activationErr
	}

	return &secretServiceStore{transport: transport}, nil
}

func classifySecretServiceConnectionError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	wrapped := fmt.Errorf("connect to D-Bus session bus: %w", err)
	name, isDBusError := secretServiceDBusErrorName(err)
	if errors.Is(err, os.ErrPermission) ||
		(isDBusError && (name == "org.freedesktop.DBus.Error.AccessDenied" ||
			name == "org.freedesktop.DBus.Error.AuthFailed")) ||
		strings.Contains(strings.ToLower(err.Error()), "authentication failed") {
		return wrapped
	}
	return newCredentialBackendUnavailableError(credentialBackendSecretService, wrapped)
}

func secretServiceSupportedOS(goos string) bool {
	switch goos {
	case "linux", "freebsd", "openbsd", "netbsd", "dragonfly":
		return true
	default:
		return false
	}
}

func classifySecretServiceActivationError(err error) error {
	name, ok := secretServiceDBusErrorName(err)
	if !ok {
		return err
	}

	switch name {
	case "org.freedesktop.DBus.Error.ServiceUnknown",
		"org.freedesktop.DBus.Error.NameHasNoOwner":
		return newCredentialBackendUnavailableError(credentialBackendSecretService, err)
	default:
		if strings.HasPrefix(name, "org.freedesktop.DBus.Error.Spawn.") {
			return newCredentialBackendUnavailableError(credentialBackendSecretService, err)
		}
		return err
	}
}

func secretServiceDBusErrorName(err error) (string, bool) {
	var dbusErr dbus.Error
	if errors.As(err, &dbusErr) {
		return dbusErr.Name, true
	}

	var dbusErrPointer *dbus.Error
	if errors.As(err, &dbusErrPointer) && dbusErrPointer != nil {
		return dbusErrPointer.Name, true
	}
	return "", false
}

func (s *secretServiceStore) search(query credentialQuery) ([]credentialRef, error) {
	collectionPaths, err := s.objectPathsProperty(
		secretServicePath,
		secretServiceInterface+".Collections",
	)
	if err != nil {
		return nil, fmt.Errorf("list Secret Service collections: %w", err)
	}
	aliasPath := secretServiceNoPromptPath
	if query.Collection != "" {
		aliasPath, err = s.readCollectionAlias(query.Collection)
		if err != nil {
			return nil, err
		}
	}

	type collectionRef struct {
		path  dbus.ObjectPath
		label string
	}
	collections := make([]collectionRef, 0, len(collectionPaths))
	selectedPaths := make(map[dbus.ObjectPath]struct{})
	for _, collectionPath := range collectionPaths {
		if err := requireSecretServiceObjectPath(collectionPath, "collection"); err != nil {
			return nil, err
		}

		collectionLabel, err := s.stringProperty(
			collectionPath,
			secretServiceCollectionInterface+".Label",
		)
		if err != nil {
			return nil, fmt.Errorf("read Secret Service collection label: %w", err)
		}
		if query.Collection != "" && query.Collection != collectionLabel &&
			query.Collection != path.Base(string(collectionPath)) &&
			collectionPath != aliasPath {
			continue
		}
		if _, exists := selectedPaths[collectionPath]; exists {
			continue
		}
		selectedPaths[collectionPath] = struct{}{}
		collections = append(collections, collectionRef{path: collectionPath, label: collectionLabel})
	}
	if query.Collection != "" && len(collections) > 1 {
		return nil, fmt.Errorf(
			"Secret Service collection selector %q is ambiguous (%d collections matched)",
			query.Collection,
			len(collections),
		)
	}

	credentials := make([]credentialRef, 0)
	for _, collection := range collections {
		locked, err := s.boolProperty(
			collection.path,
			secretServiceCollectionInterface+".Locked",
		)
		if err != nil {
			return nil, fmt.Errorf("read Secret Service collection lock state: %w", err)
		}
		if locked && query.AllowInteraction {
			if err := s.unlockObject(collection.path, secretServiceCollectionInterface); err != nil {
				return nil, fmt.Errorf("unlock Secret Service collection %q: %w", collection.label, err)
			}
		}

		items, err := s.objectPathsProperty(
			collection.path,
			secretServiceCollectionInterface+".Items",
		)
		if err != nil {
			return nil, fmt.Errorf("list Secret Service items in collection %q: %w", collection.label, err)
		}

		for _, itemPath := range items {
			credential, err := s.itemMetadata(collection.label, itemPath)
			if err != nil {
				return nil, err
			}
			if attributesMatch(credential.Attributes, query.Attributes) {
				credential.Locked = credential.Locked || locked
				credentials = append(credentials, credential)
			}
		}
	}

	return credentials, nil
}

func (s *secretServiceStore) readCollectionAlias(alias string) (dbus.ObjectPath, error) {
	call := s.transport.Call(
		secretServicePath,
		secretServiceInterface+".ReadAlias",
		alias,
	)
	if call == nil {
		return "", errors.New("Secret Service returned a nil ReadAlias call")
	}

	var collectionPath dbus.ObjectPath
	if err := call.Store(&collectionPath); err != nil {
		return "", fmt.Errorf("read Secret Service collection alias %q: %w", alias, err)
	}
	if collectionPath == secretServiceNoPromptPath {
		return collectionPath, nil
	}
	if err := requireSecretServiceObjectPath(collectionPath, "collection alias"); err != nil {
		return "", err
	}
	return collectionPath, nil
}

func (s *secretServiceStore) itemMetadata(
	collectionLabel string,
	itemPath dbus.ObjectPath,
) (credentialRef, error) {
	if err := requireSecretServiceObjectPath(itemPath, "item"); err != nil {
		return credentialRef{}, err
	}

	label, err := s.stringProperty(itemPath, secretServiceItemInterface+".Label")
	if err != nil {
		return credentialRef{}, fmt.Errorf("read Secret Service item label: %w", err)
	}
	attributes, err := s.attributesProperty(itemPath, secretServiceItemInterface+".Attributes")
	if err != nil {
		return credentialRef{}, fmt.Errorf("read Secret Service item attributes: %w", err)
	}
	locked, err := s.boolProperty(itemPath, secretServiceItemInterface+".Locked")
	if err != nil {
		return credentialRef{}, fmt.Errorf("read Secret Service item lock state: %w", err)
	}

	return credentialRef{
		Backend:    credentialBackendSecretService,
		ID:         string(itemPath),
		Collection: collectionLabel,
		Label:      label,
		Attributes: attributes,
		Locked:     locked,
	}, nil
}

func (s *secretServiceStore) secret(credential credentialRef, allowInteraction bool) (secret []byte, returnErr error) {
	if credential.Backend != credentialBackendSecretService {
		return nil, fmt.Errorf("Secret Service cannot retrieve credential from backend %q", credential.Backend)
	}

	itemPath := dbus.ObjectPath(credential.ID)
	if err := requireSecretServiceObjectPath(itemPath, "item"); err != nil {
		return nil, err
	}

	locked, err := s.boolProperty(itemPath, secretServiceItemInterface+".Locked")
	if err != nil {
		return nil, fmt.Errorf("read Secret Service item lock state: %w", err)
	}
	if locked {
		if !allowInteraction {
			return nil, errCredentialLocked
		}
		if err := s.unlockObject(itemPath, secretServiceItemInterface); err != nil {
			return nil, fmt.Errorf("unlock Secret Service item: %w", err)
		}
	}

	sessionPath, err := s.openSession()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := s.closeSession(sessionPath); err != nil {
			returnErr = errors.Join(returnErr, err)
			clearBytes(secret)
			secret = nil
		}
	}()

	call := s.transport.Call(
		itemPath,
		secretServiceItemInterface+".GetSecret",
		sessionPath,
	)
	if call == nil {
		return nil, errors.New("Secret Service returned a nil GetSecret call")
	}
	defer clearSecretServiceCallBody(call.Body)

	var response secretServiceSecret
	if err := call.Store(&response); err != nil {
		return nil, fmt.Errorf("get Secret Service secret: %w", err)
	}
	defer clearBytes(response.Value)

	if response.Session != sessionPath {
		return nil, fmt.Errorf(
			"malformed Secret Service secret: session %q does not match %q",
			response.Session,
			sessionPath,
		)
	}
	if len(response.Parameters) != 0 {
		return nil, errors.New("malformed Secret Service secret: plain session returned parameters")
	}

	if len(response.Value) > maxCredentialOutputBytes {
		return nil, errCredentialTooLarge
	}
	return append([]byte(nil), response.Value...), nil
}

func clearSecretServiceCallBody(values []any) {
	for _, value := range values {
		switch typed := value.(type) {
		case []byte:
			clearBytes(typed)
		case []any:
			clearSecretServiceCallBody(typed)
		case secretServiceSecret:
			clearBytes(typed.Parameters)
			clearBytes(typed.Value)
		case *secretServiceSecret:
			if typed != nil {
				clearBytes(typed.Parameters)
				clearBytes(typed.Value)
			}
		}
	}
}

func (s *secretServiceStore) openSession() (dbus.ObjectPath, error) {
	call := s.transport.Call(
		secretServicePath,
		secretServiceInterface+".OpenSession",
		"plain",
		dbus.MakeVariant(""),
	)
	if call == nil {
		return "", errors.New("Secret Service returned a nil OpenSession call")
	}

	var output dbus.Variant
	var sessionPath dbus.ObjectPath
	if err := call.Store(&output, &sessionPath); err != nil {
		return "", fmt.Errorf("open Secret Service session: %w", err)
	}
	if err := requireSecretServiceObjectPath(sessionPath, "session"); err != nil {
		return "", err
	}
	if !isValidPlainSessionOutput(output) {
		responseErr := errors.New("malformed Secret Service plain session output")
		if closeErr := s.closeSession(sessionPath); closeErr != nil {
			responseErr = errors.Join(responseErr, closeErr)
		}
		return "", responseErr
	}
	return sessionPath, nil
}

func isValidPlainSessionOutput(output dbus.Variant) bool {
	switch value := output.Value().(type) {
	case string:
		return value == ""
	case []byte:
		// gopass-secret-service currently returns an empty byte array for a
		// plain session even though the specification calls for an empty
		// string. Accept only the empty form to preserve strict validation.
		valid := len(value) == 0
		clearBytes(value)
		return valid
	default:
		return false
	}
}

func (s *secretServiceStore) closeSession(sessionPath dbus.ObjectPath) error {
	ctx, cancel := context.WithTimeout(context.Background(), credentialCleanupTimeout)
	defer cancel()
	call := s.transport.WithContext(ctx).Call(sessionPath, secretServiceSessionInterface+".Close")
	if call == nil {
		return errors.New("close Secret Service session: nil D-Bus call")
	}
	if err := call.Store(); err != nil {
		return fmt.Errorf("close Secret Service session: %w", err)
	}
	return nil
}

func (s *secretServiceStore) unlockObject(
	objectPath dbus.ObjectPath,
	lockableInterface string,
) error {
	call := s.transport.Call(
		secretServicePath,
		secretServiceInterface+".Unlock",
		[]dbus.ObjectPath{objectPath},
	)
	if call == nil {
		return errors.New("Secret Service returned a nil Unlock call")
	}

	var unlocked []dbus.ObjectPath
	var promptPath dbus.ObjectPath
	if err := call.Store(&unlocked, &promptPath); err != nil {
		return fmt.Errorf("request Secret Service unlock: %w", err)
	}
	for _, unlockedPath := range unlocked {
		if !unlockedPath.IsValid() {
			return fmt.Errorf("malformed Secret Service unlock path %q", unlockedPath)
		}
	}

	if promptPath != secretServiceNoPromptPath {
		if err := requireSecretServiceObjectPath(promptPath, "prompt"); err != nil {
			return err
		}
		result, dismissed, err := s.transport.Prompt(promptPath, "")
		if err != nil {
			return fmt.Errorf("complete Secret Service unlock prompt: %w", err)
		}
		if dismissed {
			return &secretServicePromptDismissedError{promptPath: promptPath}
		}
		promptedPaths, ok := result.Value().([]dbus.ObjectPath)
		if !ok {
			return errors.New("malformed Secret Service unlock prompt result")
		}
		for _, promptedPath := range promptedPaths {
			if !promptedPath.IsValid() {
				return fmt.Errorf("malformed Secret Service prompt path %q", promptedPath)
			}
		}
	}

	locked, err := s.boolProperty(objectPath, lockableInterface+".Locked")
	if err != nil {
		return fmt.Errorf("confirm Secret Service unlock: %w", err)
	}
	if locked {
		return errors.New("Secret Service object remains locked after unlock")
	}
	return nil
}

type secretServicePromptDismissedError struct {
	promptPath dbus.ObjectPath
}

func (e *secretServicePromptDismissedError) Error() string {
	return fmt.Sprintf("Secret Service prompt %q was dismissed", e.promptPath)
}

func (s *secretServiceStore) objectPathsProperty(
	objectPath dbus.ObjectPath,
	property string,
) ([]dbus.ObjectPath, error) {
	variant, err := s.transport.GetProperty(objectPath, property)
	if err != nil {
		return nil, err
	}
	value, ok := variant.Value().([]dbus.ObjectPath)
	if !ok {
		return nil, fmt.Errorf("malformed Secret Service property %q: expected object paths", property)
	}
	return append([]dbus.ObjectPath(nil), value...), nil
}

func (s *secretServiceStore) stringProperty(
	objectPath dbus.ObjectPath,
	property string,
) (string, error) {
	variant, err := s.transport.GetProperty(objectPath, property)
	if err != nil {
		return "", err
	}
	value, ok := variant.Value().(string)
	if !ok {
		return "", fmt.Errorf("malformed Secret Service property %q: expected string", property)
	}
	return value, nil
}

func (s *secretServiceStore) boolProperty(
	objectPath dbus.ObjectPath,
	property string,
) (bool, error) {
	variant, err := s.transport.GetProperty(objectPath, property)
	if err != nil {
		return false, err
	}
	value, ok := variant.Value().(bool)
	if !ok {
		return false, fmt.Errorf("malformed Secret Service property %q: expected boolean", property)
	}
	return value, nil
}

func (s *secretServiceStore) attributesProperty(
	objectPath dbus.ObjectPath,
	property string,
) (map[string]string, error) {
	variant, err := s.transport.GetProperty(objectPath, property)
	if err != nil {
		return nil, err
	}
	value, ok := variant.Value().(map[string]string)
	if !ok {
		return nil, fmt.Errorf("malformed Secret Service property %q: expected string map", property)
	}
	attributes := make(map[string]string, len(value))
	for name, attribute := range value {
		attributes[name] = attribute
	}
	return attributes, nil
}

func requireSecretServiceObjectPath(objectPath dbus.ObjectPath, kind string) error {
	if !objectPath.IsValid() || objectPath == secretServiceNoPromptPath {
		return fmt.Errorf("malformed Secret Service %s path %q", kind, objectPath)
	}
	return nil
}

func (s *secretServiceStore) Close() error {
	s.closeOnce.Do(func() {
		s.closeErr = s.transport.Close()
	})
	return s.closeErr
}

func (t *dbusSecretServiceTransport) context() context.Context {
	if t.ctx != nil {
		return t.ctx
	}
	return context.Background()
}
func (t *dbusSecretServiceTransport) busName() string {
	if t.destination != "" {
		return t.destination
	}
	return secretServiceBusName
}
func (t *dbusSecretServiceTransport) WithContext(ctx context.Context) secretServiceTransport {
	return &dbusSecretServiceTransport{conn: t.conn, ctx: ctx, destination: t.destination, cancelConnection: t.cancelConnection}
}
func (s *secretServiceStore) Search(ctx context.Context, query credentialQuery) ([]credentialRef, error) {
	ctx, cancel := context.WithTimeout(ctx, credentialOperationTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	scoped := &secretServiceStore{transport: s.transport.WithContext(ctx)}
	refs, err := scoped.search(query)
	if err != nil && !query.AllowInteraction {
		return nil, sanitizeKeyReadError(ctx, keyProviderError(err))
	}
	return refs, err
}
func (s *secretServiceStore) Secret(ctx context.Context, ref credentialRef, options credentialReadOptions) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, credentialOperationTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	scoped := &secretServiceStore{transport: s.transport.WithContext(ctx)}
	interactive := options.AllowInteraction
	return scoped.secret(ref, interactive)
}
func attributesMatch(actual, required map[string]string) bool {
	for k, v := range required {
		value, exists := actual[k]
		if !exists || value != v {
			return false
		}
	}
	return true
}
