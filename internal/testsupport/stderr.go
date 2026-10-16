// Package testsupport holds small helpers shared across package test suites.
package testsupport

import (
	"io"
	"os"
	"testing"
)

// CaptureStderr runs fn with os.Stderr redirected through a pipe and returns
// everything written to stderr during the call. It restores os.Stderr before
// returning.
//
// CaptureStderr redirects process-wide os.Stderr, so it must not be used from
// tests (or call sites) running under t.Parallel(): concurrent captures would
// race on the shared os.Stderr.
func CaptureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	defer func() { os.Stderr = orig }()

	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()

	fn()
	_ = w.Close()
	return <-done
}
