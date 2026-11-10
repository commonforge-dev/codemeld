//go:build !linux

package bootstrap

import (
	"codemeld.dev/codemeld/internal/enforce"
	"codemeld.dev/codemeld/internal/runner"
)

func (c *confinement) attachBroker(*runner.RunSpec, string) error {
	return enforce.ErrBrokerUnsupported
}
