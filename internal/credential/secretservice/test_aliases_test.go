package secretservice

import (
	"github.com/jfardello/sshx/internal/credential"
)

const credentialBackendGopass = credential.BackendGopass

var (
	isCredentialBackendUnavailable = credential.IsBackendUnavailable
)
