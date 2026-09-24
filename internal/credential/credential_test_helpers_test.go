package credential

import "context"

type recordingStore struct{}

func (*recordingStore) Search(context.Context, credentialQuery) ([]credentialRef, error) {
	return nil, nil
}
func (*recordingStore) Secret(context.Context, credentialRef, credentialReadOptions) ([]byte, error) {
	return nil, nil
}
func (*recordingStore) Close() error { return nil }
