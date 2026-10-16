// Package procowner records which process instance created a durable artifact and reports whether
// that exact process is still running.
package procowner

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
)

const SchemaVersion = 1

type Classification string

const (
	Owned    Classification = "owned"
	Orphaned Classification = "orphaned"
)

type Owner struct {
	SchemaVersion int    `json:"schema_version"`
	OS            string `json:"os"`
	PID           int    `json:"pid"`
	StartTime     string `json:"start_time"`
}

var errProcessAbsent = errors.New("procowner: process does not exist")

var errProbeUnsupported = errors.New("procowner: process start time is unavailable on this platform")

var probeStartTime = probeStartTimeSyscall

func Capture() (Owner, error) {
	pid := os.Getpid()
	start, err := probeStartTime(pid)
	if err != nil {
		return Owner{}, fmt.Errorf("procowner: read start time of pid %d: %w", pid, err)
	}
	return Owner{
		SchemaVersion: SchemaVersion,
		OS:            runtime.GOOS,
		PID:           pid,
		StartTime:     start,
	}, nil
}

// Classify answers Orphaned only when the recorded process is affirmatively gone. Everything else —
// a reused PID whose start time differs, a denied or unreadable probe, a record this build cannot
// interpret — is Owned, so an artifact is retained rather than replayed against a live process.
func Classify(rec Owner) Classification {
	if rec.SchemaVersion != SchemaVersion || rec.OS != runtime.GOOS || rec.PID <= 0 || rec.StartTime == "" {
		return Owned
	}
	if _, err := probeStartTime(rec.PID); errors.Is(err, errProcessAbsent) {
		return Orphaned
	}
	return Owned
}

// Offset and size of ki_start (a timeval) within the FreeBSD kern.proc.pid record, confirmed
// against sys/user.h on FreeBSD 15.1-RELEASE-p3 amd64. x/sys defines no FreeBSD kinfo_proc type, so
// the leading ki_structsize field guards the offset against a layout this build does not know.
const (
	freebsdStartTimeOffset = 336
	freebsdTimevalSize     = 16
)

func decodeFreeBSDStartTime(raw []byte) (string, error) {
	if len(raw) < 4 {
		return "", fmt.Errorf("procowner: kern.proc.pid record of %d bytes has no ki_structsize", len(raw))
	}
	structSize := int32(binary.NativeEndian.Uint32(raw[:4]))
	if int(structSize) != len(raw) {
		return "", fmt.Errorf("procowner: kern.proc.pid ki_structsize %d does not match the %d-byte record", structSize, len(raw))
	}
	if len(raw) < freebsdStartTimeOffset+freebsdTimevalSize {
		return "", fmt.Errorf("procowner: kern.proc.pid record of %d bytes is too short for ki_start", len(raw))
	}
	sec := int64(binary.NativeEndian.Uint64(raw[freebsdStartTimeOffset:]))
	usec := int64(binary.NativeEndian.Uint64(raw[freebsdStartTimeOffset+8:]))
	return formatTimeval(sec, usec), nil
}

func formatTimeval(sec, usec int64) string {
	return fmt.Sprintf("%d.%06d", sec, usec)
}
