//go:build !linux

package bootstrap

import (
	"codemeld.dev/codemeld/internal/enforce"
	"codemeld.dev/codemeld/internal/runner"
)

type sessionDenyList struct{}

func newSessionDenyList() *sessionDenyList { return nil }

func (*sessionDenyList) Close() {}

func (c *confinement) attachBroker(*runner.RunSpec, enforce.Policy) error {
	return enforce.ErrBrokerUnsupported
}
