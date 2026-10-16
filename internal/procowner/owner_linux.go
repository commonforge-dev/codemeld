//go:build linux

package procowner

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
)

const linuxStartTimeField = 22

func probeStartTimeSyscall(pid int) (string, error) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", errProcessAbsent
		}
		return "", err
	}
	return startTimeFromStat(string(data))
}

// The command name in field 2 is parenthesized and may itself contain spaces or ')', so the
// remaining fields are taken after its last ')' rather than by splitting the whole record.
func startTimeFromStat(stat string) (string, error) {
	end := strings.LastIndexByte(stat, ')')
	if end < 0 {
		return "", fmt.Errorf("procowner: /proc stat record has no command field: %q", stat)
	}
	fields := strings.Fields(stat[end+1:])
	const index = linuxStartTimeField - 3
	if len(fields) <= index {
		return "", fmt.Errorf("procowner: /proc stat record has %d fields after the command, want more than %d", len(fields), index)
	}
	start := fields[index]
	if _, err := strconv.ParseUint(start, 10, 64); err != nil {
		return "", fmt.Errorf("procowner: /proc stat start time %q is not a number: %w", start, err)
	}
	return start, nil
}
