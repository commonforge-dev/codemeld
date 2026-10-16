//go:build !linux && !darwin && !freebsd

package procowner

// A target with no start-time probe must never report absence: it cannot tell a gone process from
// one it simply has no way to look up, and a wrong absence would orphan a live record.
func probeStartTimeSyscall(_ int) (string, error) {
	return "", errProbeUnsupported
}
