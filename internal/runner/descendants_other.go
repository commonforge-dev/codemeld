//go:build !linux

package runner

import "os"

type rootIdentity struct {
	pid int
}

const observesRootExit = false

func awaitRootExit(int) bool { return false }

func registerRoot(pid int) rootIdentity { return rootIdentity{pid: pid} }

func unregisterRoot(rootIdentity) {}

func commandEnv(env []string, _ string) []string { return env }

func killEscaped(root rootIdentity, _ string, group bool) error {
	if !group {
		return os.ErrProcessDone
	}
	return killGroup(root.pid)
}
