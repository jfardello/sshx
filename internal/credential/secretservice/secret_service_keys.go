package secretservice

import (
	"context"
	"errors"

	"github.com/godbus/dbus/v5"
)

// Resolve a stable item ID for every operation, then address only that unique
// provider owner. Recycled object paths after service replacement are never used.
func (t *dbusSecretServiceTransport) Owner(ctx context.Context) (string, error) {
	var owner string
	err := t.conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", 0, secretServiceBusName).Store(&owner)
	if err != nil || owner == "" {
		return "", errCredentialProviderChanged
	}
	return owner, nil
}
func (t *dbusSecretServiceTransport) WithOwner(owner string) secretServiceTransport {
	return &dbusSecretServiceTransport{conn: t.conn, ctx: t.ctx, destination: owner, cancelConnection: t.cancelConnection}
}

func (s *secretServiceStore) KeyMaterial(ctx context.Context, ref credentialRef) (data []byte, returnErr error) {
	ctx, cancel := context.WithTimeout(ctx, credentialOperationTimeout)
	defer cancel()
	defer func() {
		if returnErr != nil {
			clearBytes(data)
			data = nil
			returnErr = sanitizeKeyReadError(ctx, keyProviderError(returnErr))
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if ref.Backend != credentialBackendSecretService || !validRegistryID(ref.ID) || !validRegistryID(ref.Collection) {
		return nil, errCredentialReference
	}
	owner, err := s.transport.Owner(ctx)
	if err != nil {
		return nil, err
	}
	scoped := &secretServiceStore{transport: s.transport.WithContext(ctx).WithOwner(owner)}
	collection, match, err := scoped.keyLocation(ref)
	if err != nil {
		return nil, err
	}
	required := map[string]string{"service": "sshx", "sshx.type": "ssh-key", "sshx.schema": "1", "sshx.id": ref.ID}
	data, err = scoped.secret(credentialRef{Backend: credentialBackendSecretService, ID: string(match)}, false)
	if err != nil {
		return nil, err
	}
	if len(data) > maxKeyMaterialBytes {
		return data, errCredentialTooLarge
	}
	// Check mutable metadata and lock state again before releasing any bytes.
	attrs, err := scoped.attributesProperty(match, secretServiceItemInterface+".Attributes")
	if err != nil {
		return data, err
	}
	if !attributesMatch(attrs, required) {
		return data, errCredentialReference
	}
	for _, object := range []struct {
		path  dbus.ObjectPath
		iface string
	}{{collection, secretServiceCollectionInterface}, {match, secretServiceItemInterface}} {
		locked, err := scoped.boolProperty(object.path, object.iface+".Locked")
		if err != nil {
			return data, err
		}
		if locked {
			return data, errCredentialLocked
		}
	}
	current, err := s.transport.Owner(ctx)
	if err != nil || current != owner {
		return data, errCredentialProviderChanged
	}
	if err := ctx.Err(); err != nil {
		return data, err
	}
	return data, nil
}

var _ keyMaterialStore = (*secretServiceStore)(nil)

// Preserve only known error kinds across the key-material boundary.
func keyProviderError(err error) error {
	if errors.Is(err, dbus.ErrClosed) {
		return errCredentialProviderChanged
	}
	name, ok := secretServiceDBusErrorName(err)
	if ok {
		switch name {
		case "org.freedesktop.DBus.Error.NameHasNoOwner", "org.freedesktop.DBus.Error.ServiceUnknown", "org.freedesktop.DBus.Error.NoReply", "org.freedesktop.DBus.Error.Disconnected":
			return errCredentialProviderChanged
		case "org.freedesktop.Secret.Error.IsLocked":
			return errCredentialLocked
		}
	}
	return err
}

// keyLocation resolves exact public metadata and verifies collection readiness.
func (s *secretServiceStore) keyLocation(ref credentialRef) (dbus.ObjectPath, dbus.ObjectPath, error) {
	collection, err := s.readCollectionAlias(ref.Collection)
	if err != nil {
		return "", "", err
	}
	if collection == secretServiceNoPromptPath {
		return "", "", errCredentialReference
	}
	locked, err := s.boolProperty(collection, secretServiceCollectionInterface+".Locked")
	if err != nil {
		return "", "", err
	}
	if locked {
		return "", "", errCredentialLocked
	}
	items, err := s.objectPathsProperty(collection, secretServiceCollectionInterface+".Items")
	if err != nil {
		return "", "", err
	}
	if len(items) > 16384 {
		return "", "", errCredentialTooLarge
	}
	var match dbus.ObjectPath
	required := map[string]string{"service": "sshx", "sshx.type": "ssh-key", "sshx.schema": "1", "sshx.id": ref.ID}
	for _, item := range items {
		if requireSecretServiceObjectPath(item, "item") != nil {
			return "", "", errCredentialReference
		}
		attrs, err := s.attributesProperty(item, secretServiceItemInterface+".Attributes")
		if err != nil {
			return "", "", err
		}
		if attrs["sshx.id"] != ref.ID {
			continue
		}
		if !attributesMatch(attrs, required) || match != "" {
			return "", "", errCredentialReference
		}
		match = item
	}
	if match == "" {
		return "", "", errCredentialReference
	}
	return collection, match, nil
}
