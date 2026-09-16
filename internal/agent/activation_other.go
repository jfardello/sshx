//go:build !linux

package agent

import "errors"

func NewActivatedServer(_ string, _ *Registry, _ StoreOpener) (*Server, error) {
	return nil, errors.New("systemd socket activation is supported only on Linux")
}
