//go:build !linux

package filetools

import "golang.org/x/sys/unix"

const dirSearchOnly = unix.O_SEARCH
