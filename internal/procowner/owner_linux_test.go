//go:build linux

package procowner

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
)

// The kernel exposes one more than the highest allocatable PID, so pid_max itself never names a
// running process.
func absentPID(t *testing.T) int {
	t.Helper()
	data, err := os.ReadFile("/proc/sys/kernel/pid_max")
	if err != nil {
		t.Fatalf("read pid_max: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("parse pid_max %q: %v", data, err)
	}
	return pid
}

func TestCapture_CurrentLinuxProcessIsOwned(t *testing.T) {
	rec, err := Capture()
	if err != nil {
		t.Fatalf("Capture() error: %v", err)
	}
	if rec.SchemaVersion != SchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", rec.SchemaVersion, SchemaVersion)
	}
	if rec.OS != "linux" {
		t.Errorf("OS = %q, want %q", rec.OS, "linux")
	}
	if rec.PID != os.Getpid() {
		t.Errorf("PID = %d, want %d", rec.PID, os.Getpid())
	}
	if _, err := strconv.ParseUint(rec.StartTime, 10, 64); err != nil {
		t.Errorf("StartTime = %q, want a number: %v", rec.StartTime, err)
	}
	if got := Classify(rec); got != Owned {
		t.Fatalf("Classify(captured) = %q, want %q", got, Owned)
	}
}

func TestClassify_AbsentLinuxProcessIsOrphaned(t *testing.T) {
	rec := Owner{SchemaVersion: SchemaVersion, OS: "linux", PID: absentPID(t), StartTime: "900"}

	if got := Classify(rec); got != Orphaned {
		t.Fatalf("Classify() = %q, want %q", got, Orphaned)
	}
}

func TestProbeStartTimeSyscall_ReadsProcStat(t *testing.T) {
	start, err := probeStartTimeSyscall(os.Getpid())
	if err != nil {
		t.Fatalf("probeStartTimeSyscall() error: %v", err)
	}
	if _, err := strconv.ParseUint(start, 10, 64); err != nil {
		t.Fatalf("probeStartTimeSyscall() = %q, want a number: %v", start, err)
	}

	if _, err := probeStartTimeSyscall(absentPID(t)); !errors.Is(err, errProcessAbsent) {
		t.Fatalf("probeStartTimeSyscall(absent) error = %v, want errProcessAbsent", err)
	}
}

func statRecord(comm, startTime string) string {
	fields := make([]string, 50)
	for i := range fields {
		fields[i] = strconv.Itoa(i)
	}
	fields[0] = "S"
	fields[linuxStartTimeField-3] = startTime
	return "1234 (" + comm + ") " + strings.Join(fields, " ") + "\n"
}

func TestStartTimeFromStat_ReadsFieldTwentyTwo(t *testing.T) {
	tests := []struct {
		name string
		comm string
	}{
		{name: "plain command", comm: "codemeld"},
		{name: "command containing spaces", comm: "my weird agent"},
		{name: "command containing a close paren", comm: "weird ) name"},
		{name: "command containing spaces and parens", comm: "(a) b) c"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := startTimeFromStat(statRecord(tc.comm, "8675309"))
			if err != nil {
				t.Fatalf("startTimeFromStat() error: %v", err)
			}
			if want := "8675309"; got != want {
				t.Fatalf("startTimeFromStat() = %q, want %q", got, want)
			}
		})
	}
}

func TestStartTimeFromStat_UnreadableRecordsFail(t *testing.T) {
	tests := []struct {
		name string
		stat string
	}{
		{name: "no command field", stat: "1234 codemeld S 1 2 3\n"},
		{name: "truncated after the command", stat: "1234 (codemeld) S 1 2 3\n"},
		{name: "non-numeric start time", stat: statRecord("codemeld", "not-a-number")},
		{name: "empty record", stat: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := startTimeFromStat(tc.stat)
			if err == nil {
				t.Fatalf("startTimeFromStat() = %q, want an error", got)
			}
			if errors.Is(err, errProcessAbsent) {
				t.Fatal("an unreadable record reported process absence, which would orphan a live record")
			}
		})
	}
}
