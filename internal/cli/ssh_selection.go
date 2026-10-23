package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/jfardello/sshx/internal/promptprotocol"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

var errSelectionTTY = errors.New("credential selection requires a controlling terminal")
var errSelectionInput = errors.New("invalid or unavailable terminal credential selection")

type sshSelectionCanceled struct{}

func (*sshSelectionCanceled) Error() string { return "credential selection canceled" }
func (*sshSelectionCanceled) Code() int     { return 130 }

func chooseSSHCredential(opts commandOptions, candidates []credentialRef, deps dependencies) (int, error) {
	if opts.ui == "desktop" {
		return -1, errors.New("desktop selection is not integrated with SSH yet; use --ui shell")
	}
	pick := deps.selectShell
	if pick == nil {
		pick = selectTerminalCredential
	}
	index, err := pick(dependencyContext(deps), candidates)
	if errors.Is(err, context.Canceled) {
		return -1, &sshSelectionCanceled{}
	}
	if err != nil {
		return -1, err
	}
	if index < 0 || index >= len(candidates) {
		return -1, errSelectionInput
	}
	return index, nil
}

func selectionMenu(candidates []credentialRef) (string, error) {
	if len(candidates) == 0 {
		return "", errSelectionInput
	}
	if len(candidates) > promptprotocol.MaxSelectionCandidates {
		return "", promptprotocol.ErrNarrow
	}
	var menu strings.Builder
	menu.WriteString("Select a credential:\n")
	for i, candidate := range candidates {
		label := candidate.Label
		if label == "" {
			label = path.Base(candidate.ID)
		}
		collection := candidate.Collection
		if candidate.Backend == credentialBackendGopass {
			label = path.Base(label)
			collection = ""
		}
		fields := []string{label, candidate.Target, string(candidate.Backend), collection}
		for j, field := range fields {
			if !utf8.ValidString(field) {
				return "", errSelectionInput
			}
			if len(field) > promptprotocol.MaxSelectionFieldBytes {
				return "", promptprotocol.ErrNarrow
			}
			fields[j] = promptprotocol.DisplayText(field)
			if len(fields[j]) > promptprotocol.MaxSelectionFieldBytes {
				return "", promptprotocol.ErrNarrow
			}
		}
		fmt.Fprintf(&menu, "%d. %s | %s | %s | %s\n", i+1, fields[0], fields[1], fields[2], fields[3])
	}
	menu.WriteString("0. Cancel\n")
	if menu.Len() > promptprotocol.MaxSelectionRequestBytes {
		return "", promptprotocol.ErrNarrow
	}
	return menu.String(), nil
}

func selectTerminalCredential(ctx context.Context, candidates []credentialRef) (int, error) {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGTSTP)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if ctx.Err() != nil {
		return -1, ctx.Err()
	}
	fd, err := unix.Open("/dev/tty", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return -1, errSelectionTTY
	}
	defer unix.Close(fd)
	if !term.IsTerminal(fd) {
		return -1, errSelectionTTY
	}
	return selectTerminalCredentialFD(ctx, fd, candidates)
}

func selectTerminalCredentialFD(ctx context.Context, fd int, candidates []credentialRef) (int, error) {
	menu, err := selectionMenu(candidates)
	if err != nil {
		return -1, err
	}
	input, err := readTerminalLineFD(ctx, fd, menu+"Choice (0 cancels): ", 4, true)
	defer clearBytes(input)
	if err != nil {
		if ctx.Err() != nil {
			return -1, ctx.Err()
		}
		if errors.Is(err, context.Canceled) {
			return -1, context.Canceled
		}
		return -1, errSelectionInput
	}
	number, err := strconv.Atoi(string(input))
	if err != nil || number < 0 || number > len(candidates) {
		return -1, errSelectionInput
	}
	if number == 0 {
		return -1, context.Canceled
	}
	return number - 1, nil
}
