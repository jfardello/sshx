package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/jfardello/sshx/internal/cli"
	"github.com/jfardello/sshx/internal/pty"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := cli.NewRootCommand().ExecuteContext(ctx); err != nil {
		var exitErr *pty.ExitCodeError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.Code())
		}

		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
