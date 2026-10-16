// Entry point for the codemeld CLI binary; delegates argument parsing and dispatch to internal/cli.
package main

import (
	"context"
	"os"

	"codemeld.dev/codemeld/internal/cli"
)

func main() {
	os.Exit(cli.Run(context.Background(), os.Args, os.Stdout, os.Stderr))
}
