package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/jfardello/sshx/internal/cli"
)

func main() {
	ctx := context.Background()
	// Agent commands own signal handling so run can forward the actual signal
	// and preserve the child's status. Password commands retain cancellation.
	if len(os.Args) < 2 || os.Args[1] != "agent" {
		var stop context.CancelFunc
		ctx, stop = signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer stop()
	}
	if err := cli.NewRootCommand().ExecuteContext(ctx); err != nil {
		var exitErr interface{ Code() int }
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.Code())
		}

		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
