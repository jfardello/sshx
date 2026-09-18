package agent

import (
	"context"
	"errors"
	"io"
	"log"
)

// SetDiagnostics enables fixed, secret-safe events on an explicit writer.
// A nil writer disables diagnostics. It never enables upstream protocol logging.
func (s *agentServer) SetDiagnostics(w io.Writer) {
	if w == nil {
		s.keys.diagnostics.Store(nil)
		return
	}
	s.keys.diagnostics.Store(log.New(w, "sshx agent: ", 0))
	s.keys.debug("diagnostics enabled; registry loaded")
}

// Callers supply only constant events, never wire data or provider error text.
func (s *agentKeyService) debug(event string) {
	if s == nil {
		return
	}
	if logger := s.diagnostics.Load(); logger != nil {
		logger.Print(event)
	}
}

func diagnosticKeyError(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "sign denied: credential operation timed out"
	case errors.Is(err, context.Canceled):
		return "sign denied: credential operation canceled"
	case errors.Is(err, errCredentialLocked):
		return "sign denied: credential backend locked"
	case errors.Is(err, errCredentialProviderChanged):
		return "sign denied: credential provider changed"
	case errors.Is(err, errKeyMismatch):
		return "sign denied: private key does not match registered public key"
	case errors.Is(err, errKeyUnsupported):
		return "sign denied: unsupported or encrypted private key"
	case errors.Is(err, errCredentialTooLarge):
		return "sign denied: credential exceeds size limit"
	case errors.Is(err, errCredentialReference):
		return "sign denied: credential reference unavailable"
	default:
		return "sign denied: credential read or cryptographic operation failed"
	}
}
