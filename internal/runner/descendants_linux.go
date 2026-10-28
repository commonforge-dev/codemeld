//go:build linux

package runner

import (
	"bytes"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// RunMarkerEnv carries a command's invocation id into its environment. It correlates processes
// that left the command's process tree; it is not proof of ancestry and not a secret.
const RunMarkerEnv = "CODEMELD_RUN_ID"

const rescanPasses = 4

const observesRootExit = true

type procID struct {
	pid   int
	start uint64
}

type rootIdentity struct {
	procID
	known bool
}

type procStat struct {
	ppid  int
	start uint64
	state byte
}

var liveRoots = struct {
	sync.Mutex
	ids map[procID]struct{}
}{ids: map[procID]struct{}{}}

func registerRoot(pid int) rootIdentity {
	root := rootIdentity{procID: procID{pid: pid}}
	if st, ok := readProcStat(pid); ok {
		root.start, root.known = st.start, true
	}
	if root.known {
		liveRoots.Lock()
		liveRoots.ids[root.procID] = struct{}{}
		liveRoots.Unlock()
	}
	return root
}

func unregisterRoot(root rootIdentity) {
	liveRoots.Lock()
	delete(liveRoots.ids, root.procID)
	liveRoots.Unlock()
}

func otherLiveRoots(root rootIdentity) map[procID]bool {
	liveRoots.Lock()
	defer liveRoots.Unlock()
	others := make(map[procID]bool, len(liveRoots.ids))
	for id := range liveRoots.ids {
		if id != root.procID {
			others[id] = true
		}
	}
	return others
}

func commandEnv(env []string, invocationID string) []string {
	if env == nil {
		env = os.Environ()
	}
	marked := make([]string, 0, len(env)+1)
	for _, entry := range env {
		if !strings.HasPrefix(entry, RunMarkerEnv+"=") {
			marked = append(marked, entry)
		}
	}
	return append(marked, RunMarkerEnv+"="+invocationID)
}

// killEscaped records the root's descendants before the group kill, because killing the group
// first would reparent escaped children and lose the parent chain that identifies them.
func killEscaped(root rootIdentity, invocationID string, group bool) error {
	signaled := map[procID]bool{root.procID: true}
	var first []procID
	live := !root.known
	if root.known {
		procs := readProcs()
		if st, ok := procs[root.pid]; ok && st.start == root.start {
			live = true
			first = escapedTargets(procs, root, signaled, "")
		}
	}
	err := os.ErrProcessDone
	if group && live {
		err = killGroup(root.pid)
	}
	if !root.known {
		return err
	}
	signal(first, signaled)
	marker := RunMarkerEnv + "=" + invocationID
	for range rescanPasses {
		found := escapedTargets(readProcs(), root, signaled, marker)
		if len(found) == 0 {
			break
		}
		signal(found, signaled)
	}
	return err
}

func awaitRootExit(pid int) bool {
	var info unix.Siginfo
	for {
		if err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOWAIT, nil); err != unix.EINTR {
			return true
		}
	}
}

func escapedTargets(procs map[int]procStat, root rootIdentity, signaled map[procID]bool, marker string) []procID {
	others := otherLiveRoots(root)
	self := os.Getpid()
	eligible := func(pid int, st procStat) bool {
		id := procID{pid: pid, start: st.start}
		return pid != self && st.start >= root.start && st.state != 'Z' && st.state != 'X' &&
			!signaled[id] && !others[id] && sameUser(pid)
	}
	children := map[int][]int{}
	for pid, st := range procs {
		children[st.ppid] = append(children[st.ppid], pid)
	}
	var queue []int
	for id := range signaled {
		if st, ok := procs[id.pid]; ok && st.start == id.start {
			queue = append(queue, id.pid)
		}
	}
	seen := map[int]bool{}
	var found []procID
	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]
		for _, pid := range children[parent] {
			st := procs[pid]
			if seen[pid] || !eligible(pid, st) {
				continue
			}
			seen[pid] = true
			found = append(found, procID{pid: pid, start: st.start})
			queue = append(queue, pid)
		}
	}
	if marker == "" {
		return found
	}
	for pid, st := range procs {
		if !seen[pid] && eligible(pid, st) && carriesMarker(pid, marker) {
			found = append(found, procID{pid: pid, start: st.start})
		}
	}
	return found
}

func signal(targets []procID, signaled map[procID]bool) {
	for _, id := range targets {
		signaled[id] = true
		if st, ok := readProcStat(id.pid); ok && st.start == id.start {
			_ = syscall.Kill(id.pid, syscall.SIGKILL)
		}
	}
}

func readProcs() map[int]procStat {
	entries, _ := os.ReadDir("/proc")
	procs := make(map[int]procStat, len(entries))
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if st, ok := readProcStat(pid); ok {
			procs[pid] = st
		}
	}
	return procs
}

func readProcStat(pid int) (procStat, bool) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return procStat{}, false
	}
	i := bytes.LastIndexByte(data, ')')
	if i < 0 {
		return procStat{}, false
	}
	fields := strings.Fields(string(data[i+1:]))
	if len(fields) < 20 || fields[0] == "" {
		return procStat{}, false
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return procStat{}, false
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return procStat{}, false
	}
	return procStat{ppid: ppid, start: start, state: fields[0][0]}, true
}

func sameUser(pid int) bool {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return false
	}
	uid := strconv.Itoa(os.Getuid())
	for line := range strings.Lines(string(data)) {
		if rest, ok := strings.CutPrefix(line, "Uid:"); ok {
			ids := strings.Fields(rest)
			return len(ids) >= 2 && ids[0] == uid && ids[1] == uid
		}
	}
	return false
}

func carriesMarker(pid int, marker string) bool {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/environ")
	if err != nil {
		return false
	}
	for entry := range bytes.SplitSeq(data, []byte{0}) {
		if string(entry) == marker {
			return true
		}
	}
	return false
}
