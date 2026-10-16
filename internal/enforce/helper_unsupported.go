//go:build !linux

package enforce

import (
	"fmt"
	"os"
	"runtime"
)

func RunHelper([]string) int {
	fmt.Fprintf(os.Stderr, "codemeld confinement: unsupported on %s\n", runtime.GOOS)
	return SetupFailureExitCode
}
