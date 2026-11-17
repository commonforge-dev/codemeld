package filetools

import "golang.org/x/sys/unix"

// dirSearchOnly opens a folder needing only search permission, as resolving a path through it does.
const dirSearchOnly = unix.O_PATH
