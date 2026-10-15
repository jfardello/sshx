package cli

import (
	"context"
	"errors"
	"runtime"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

var (
	errRegistrationTTY        = errors.New("encrypted SSH key requires a controlling terminal; run registration from a terminal")
	errRegistrationPassphrase = errors.New("could not read SSH key passphrase from controlling terminal")
)

// Matches the agent's key-passphrase bound (maxAgentPassphraseBytes).
const maxRegistrationPassphraseBytes = 4096
const registrationPassphrasePrompt = "SSH key passphrase: "

// readRegistrationPassphrase returns an owned buffer which the caller must clear.
// The caller must install its signal-aware context (including external SIGQUIT
// and SIGTSTP) before invoking this function. Typed interrupt, quit and suspend
// controls cancel here instead of signaling or suspending the process.
func readRegistrationPassphrase(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fd, err := unix.Open("/dev/tty", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if errors.Is(err, unix.ENXIO) || errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTTY) {
			return nil, errRegistrationTTY
		}
		return nil, errRegistrationPassphrase
	}
	defer unix.Close(fd)
	return readRegistrationPassphraseFD(ctx, fd)
}

// The descriptor must be a dedicated, nonblocking terminal descriptor. Keeping
// this seam local lets tests use a PTY without replacing process-global stdin.
func readRegistrationPassphraseFD(ctx context.Context, fd int) (passphrase []byte, returnErr error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	get, set, flush := registrationTermiosRequests()
	if get == 0 {
		return nil, errRegistrationPassphrase
	}
	state, err := term.GetState(fd)
	if err != nil {
		return nil, errRegistrationPassphrase
	}
	settings, err := unix.IoctlGetTermios(fd, get)
	if err != nil {
		return nil, errRegistrationPassphrase
	}
	defer func() {

		// Cosmetic output must never delay restoration behind a full output queue.
		newlineCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		_ = registrationTTYWrite(newlineCtx, fd, []byte("\n"))
		cancel()
		// Discard unfinished or pasted-ahead input on every exit before echo
		// and terminal signal processing are restored.
		for {
			if runtime.GOOS == "darwin" {
				err = unix.IoctlSetInt(fd, flush, 1) // Darwin FREAD
			} else {
				_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(flush), uintptr(unix.TCIFLUSH))
				err = nil
				if errno != 0 {
					err = errno
				}
			}
			if !errors.Is(err, unix.EINTR) {
				break
			}
		}
		if err != nil {
			returnErr = errors.Join(returnErr, errRegistrationPassphrase)
		}
		for {
			err = term.Restore(fd, state)
			if !errors.Is(err, unix.EINTR) {
				break
			}
		}
		if err != nil {
			returnErr = errors.Join(returnErr, errRegistrationPassphrase)
		}
		if ctx.Err() != nil {
			returnErr = ctx.Err()
		}
		if returnErr != nil {
			clear(passphrase)
			passphrase = nil
		}
	}()
	// Canonical queues can be smaller than the backend's passphrase limit.
	// Read and edit bytes ourselves; ISIG must be off so Ctrl-\\ and Ctrl-Z
	// cannot terminate or suspend the process with echo still disabled.
	settings.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG
	settings.Cc[unix.VMIN] = 1
	settings.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(fd, set, settings); err != nil {
		return nil, errRegistrationPassphrase
	}
	if err := registrationTTYWrite(ctx, fd, []byte(registrationPassphrasePrompt)); err != nil {
		return nil, err
	}

	// Fixed capacity prevents append from leaving secret-bearing old allocations.
	buffer := make([]byte, 0, maxRegistrationPassphraseBytes)
	defer func() { clear(buffer[:cap(buffer)]) }()
	var chunk [maxRegistrationPassphraseBytes + 1]byte
	defer clear(chunk[:])
	for {
		if err := registrationTTYPoll(ctx, fd, unix.POLLIN); err != nil {
			return nil, err
		}
		n, err := unix.Read(fd, chunk[:])
		if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
			continue
		}
		if err != nil || n == 0 {
			return nil, errRegistrationPassphrase
		}
		for _, b := range chunk[:n] {
			if registrationControlByte(b, settings.Cc[unix.VINTR]) ||
				registrationControlByte(b, settings.Cc[unix.VQUIT]) ||
				registrationControlByte(b, settings.Cc[unix.VSUSP]) {
				return nil, context.Canceled
			}
			if registrationControlByte(b, settings.Cc[unix.VERASE]) || b == '\b' || b == 0x7f {
				buffer = registrationEraseRune(buffer)
				continue
			}
			if registrationControlByte(b, settings.Cc[unix.VKILL]) {
				clear(buffer)
				buffer = buffer[:0]
				continue
			}
			if b == '\n' || b == '\r' || registrationControlByte(b, settings.Cc[unix.VEOF]) {
				if len(buffer) == 0 {
					return nil, errRegistrationPassphrase
				}
				return append([]byte(nil), buffer...), nil
			}
			if len(buffer) == maxRegistrationPassphraseBytes {
				return nil, errRegistrationPassphrase
			}
			buffer = append(buffer, b)
		}
		clear(chunk[:])
	}
}

func registrationEraseRune(buffer []byte) []byte {
	if len(buffer) == 0 {
		return buffer
	}
	// DecodeLastRune consumes one byte for invalid or incomplete UTF-8,
	// preserving the rest of arbitrary byte input without normalization.
	_, size := utf8.DecodeLastRune(buffer)
	end := len(buffer) - size
	clear(buffer[end:])
	return buffer[:end]
}

func registrationControlByte(b, control byte) bool {
	// _POSIX_VDISABLE is 0 on Linux and 0xff on Darwin. Disabled terminal
	// controls must not accidentally turn ordinary input into an action.
	return b == control && control != 0 && (runtime.GOOS != "darwin" || control != 0xff)
}

func registrationTTYPoll(ctx context.Context, fd int, events int16) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		wait := 50 * time.Millisecond
		if deadline, ok := ctx.Deadline(); ok {
			if remaining := time.Until(deadline); remaining < wait {
				wait = max(remaining, 0)
			}
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: events}}
		_, err := unix.Poll(poll, int((wait+time.Millisecond-1)/time.Millisecond))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return errRegistrationPassphrase
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if poll[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return errRegistrationPassphrase
		}
		if poll[0].Revents&events != 0 {
			return nil
		}
	}
}

func registrationTTYWrite(ctx context.Context, fd int, data []byte) error {
	for len(data) != 0 {
		if err := registrationTTYPoll(ctx, fd, unix.POLLOUT); err != nil {
			return err
		}
		n, err := unix.Write(fd, data)
		if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
			continue
		}
		if err != nil || n == 0 {
			return errRegistrationPassphrase
		}
		data = data[n:]
	}
	return nil
}

// ioctl request names differ between Linux and Darwin. The ABI values are kept
// here so this small implementation can live in one file on both platforms.
func registrationTermiosRequests() (get, set, flush uint) {
	switch runtime.GOOS {
	case "linux":
		return 0x5401, 0x5402, 0x540b // TCGETS, TCSETS, TCFLSH
	case "darwin":
		return 0x40487413, 0x80487414, 0x80047410 // TIOCGETA, TIOCSETA, TIOCFLUSH
	default:
		return 0, 0, 0
	}
}
