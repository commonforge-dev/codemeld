//go:build !linux

package enforce

func runSliceSelfTest(string, string) (passed bool, reason string) {
	return false, "slice self-test: " + ErrBrokerUnsupported.Error()
}
