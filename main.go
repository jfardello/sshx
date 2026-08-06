package main

import (
	"errors"
	"fmt"
	"os"
)

func main() {
	if err := newRootCommand().Execute(); err != nil {
		var exitErr *exitCodeError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.code)
		}

		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
