package procowner

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"runtime"
	"testing"
)

const freebsdRecordSize = 1088

func withProbe(t *testing.T, fn func(int) (string, error)) {
	t.Helper()
	orig := probeStartTime
	probeStartTime = fn
	t.Cleanup(func() { probeStartTime = orig })
}

func liveRecord(startTime string) Owner {
	return Owner{SchemaVersion: SchemaVersion, OS: runtime.GOOS, PID: 4242, StartTime: startTime}
}

func TestClassify_AbsentPIDIsOrphaned(t *testing.T) {
	withProbe(t, func(int) (string, error) { return "", errProcessAbsent })

	if got := Classify(liveRecord("900")); got != Orphaned {
		t.Fatalf("Classify() = %q, want %q", got, Orphaned)
	}
}

func TestClassify_UncertainProbeResultsRetainOwnership(t *testing.T) {
	tests := []struct {
		name  string
		start string
		probe func(int) (string, error)
	}{
		{
			name:  "live process with a matching start time",
			start: "900",
			probe: func(int) (string, error) { return "900", nil },
		},
		{
			name:  "reused PID with a different start time",
			start: "900",
			probe: func(int) (string, error) { return "13371337", nil },
		},
		{
			name:  "permission denied",
			start: "900",
			probe: func(int) (string, error) { return "", fs.ErrPermission },
		},
		{
			name:  "zombie awaiting reaping",
			start: "900",
			probe: func(int) (string, error) { return "900", nil },
		},
		{
			name:  "unavailable process metadata",
			start: "900",
			probe: func(int) (string, error) { return "", errors.New("procowner: stat record has no command field") },
		},
		{
			name:  "unexpected probe error",
			start: "900",
			probe: func(int) (string, error) { return "", errors.New("kernel table read failed") },
		},
		{
			name:  "platform without a start-time probe",
			start: "900",
			probe: func(int) (string, error) { return "", errProbeUnsupported },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withProbe(t, tc.probe)

			if got := Classify(liveRecord(tc.start)); got != Owned {
				t.Fatalf("Classify() = %q, want %q", got, Owned)
			}
		})
	}
}

func TestErrProbeUnsupported_IsNotProcessAbsence(t *testing.T) {
	if errors.Is(errProbeUnsupported, errProcessAbsent) {
		t.Fatal("errProbeUnsupported reports process absence, so an unsupported build could orphan a live record")
	}
}

func TestClassify_UnusableRecordsRetainOwnershipWithoutProbing(t *testing.T) {
	otherOS := "plan9"
	if runtime.GOOS == otherOS {
		otherOS = "linux"
	}

	tests := []struct {
		name   string
		record Owner
	}{
		{name: "zero value", record: Owner{}},
		{name: "unwritten schema version", record: Owner{OS: runtime.GOOS, PID: 4242, StartTime: "900"}},
		{name: "future schema version", record: Owner{SchemaVersion: SchemaVersion + 1, OS: runtime.GOOS, PID: 4242, StartTime: "900"}},
		{name: "another operating system", record: Owner{SchemaVersion: SchemaVersion, OS: otherOS, PID: 4242, StartTime: "900"}},
		{name: "missing PID", record: Owner{SchemaVersion: SchemaVersion, OS: runtime.GOOS, StartTime: "900"}},
		{name: "negative PID", record: Owner{SchemaVersion: SchemaVersion, OS: runtime.GOOS, PID: -1, StartTime: "900"}},
		{name: "missing start time", record: Owner{SchemaVersion: SchemaVersion, OS: runtime.GOOS, PID: 4242}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			probed := false
			withProbe(t, func(int) (string, error) {
				probed = true
				return "", errProcessAbsent
			})

			if got := Classify(tc.record); got != Owned {
				t.Fatalf("Classify() = %q, want %q", got, Owned)
			}
			if probed {
				t.Fatal("Classify probed the platform for a record it cannot interpret")
			}
		})
	}
}

func TestCapture_RecordsTheCurrentProcess(t *testing.T) {
	withProbe(t, func(pid int) (string, error) {
		if pid != os.Getpid() {
			t.Errorf("probed pid %d, want %d", pid, os.Getpid())
		}
		return "900", nil
	})

	rec, err := Capture()
	if err != nil {
		t.Fatalf("Capture() error: %v", err)
	}
	want := Owner{SchemaVersion: SchemaVersion, OS: runtime.GOOS, PID: os.Getpid(), StartTime: "900"}
	if rec != want {
		t.Fatalf("Capture() = %+v, want %+v", rec, want)
	}
	if got := Classify(rec); got != Owned {
		t.Fatalf("Classify(captured) = %q, want %q", got, Owned)
	}
}

func TestCapture_FailsWhenTheProbeCannotSupplyAStartTime(t *testing.T) {
	probeErr := errors.New("kernel table read failed")
	withProbe(t, func(int) (string, error) { return "", probeErr })

	rec, err := Capture()
	if err == nil {
		t.Fatalf("Capture() = %+v, want an error", rec)
	}
	if !errors.Is(err, probeErr) {
		t.Fatalf("Capture() error does not wrap the probe failure: %v", err)
	}
	if rec != (Owner{}) {
		t.Fatalf("Capture() = %+v, want the zero record on failure", rec)
	}
}

func TestOwner_RoundTripsThroughJSON(t *testing.T) {
	want := Owner{SchemaVersion: SchemaVersion, OS: "freebsd", PID: 4242, StartTime: "1712345678.000042"}

	encoded, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("json.Marshal() error: %v", err)
	}
	const wantJSON = `{"schema_version":1,"os":"freebsd","pid":4242,"start_time":"1712345678.000042"}`
	if string(encoded) != wantJSON {
		t.Fatalf("json.Marshal() = %s, want %s", encoded, wantJSON)
	}

	var got Owner
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}
	if got != want {
		t.Fatalf("round trip = %+v, want %+v", got, want)
	}
}

func freebsdRecord(size int, structSize int32, sec, usec int64) []byte {
	raw := make([]byte, size)
	if size >= 4 {
		binary.NativeEndian.PutUint32(raw[:4], uint32(structSize))
	}
	if size >= freebsdStartTimeOffset+freebsdTimevalSize {
		binary.NativeEndian.PutUint64(raw[freebsdStartTimeOffset:], uint64(sec))
		binary.NativeEndian.PutUint64(raw[freebsdStartTimeOffset+8:], uint64(usec))
	}
	return raw
}

func TestDecodeFreeBSDStartTime_ReadsKiStart(t *testing.T) {
	raw := freebsdRecord(freebsdRecordSize, freebsdRecordSize, 1712345678, 42)

	got, err := decodeFreeBSDStartTime(raw)
	if err != nil {
		t.Fatalf("decodeFreeBSDStartTime() error: %v", err)
	}
	if want := "1712345678.000042"; got != want {
		t.Fatalf("decodeFreeBSDStartTime() = %q, want %q", got, want)
	}
}

func TestDecodeFreeBSDStartTime_MismatchedLayoutIsAProbeError(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "record shorter than ki_structsize claims", raw: freebsdRecord(100, freebsdRecordSize, 1, 1)},
		{name: "record longer than ki_structsize claims", raw: freebsdRecord(1200, freebsdRecordSize, 1, 1)},
		{name: "self-consistent record that cannot hold ki_start", raw: freebsdRecord(340, 340, 1, 1)},
		{name: "record too short for ki_structsize", raw: freebsdRecord(2, 0, 1, 1)},
		{name: "empty record", raw: nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeFreeBSDStartTime(tc.raw)
			if err == nil {
				t.Fatalf("decodeFreeBSDStartTime() = %q, want an error", got)
			}
			if errors.Is(err, errProcessAbsent) {
				t.Fatal("a layout mismatch reported process absence, which would orphan a live record")
			}

			withProbe(t, func(int) (string, error) { return decodeFreeBSDStartTime(tc.raw) })
			if class := Classify(liveRecord("1.000001")); class != Owned {
				t.Fatalf("Classify() = %q, want %q", class, Owned)
			}
		})
	}
}
