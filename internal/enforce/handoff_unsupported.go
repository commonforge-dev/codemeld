//go:build !linux

package enforce

import (
	"errors"
	"os"
	"time"
)

const HelperChannelFD = 3

var ErrBrokerUnsupported = errors.New("enforce: broker mode is not supported on this platform")

func ReceiveListener(*os.File, time.Duration) (*os.File, error) {
	return nil, ErrBrokerUnsupported
}

func ReleaseHelper(*os.File) error {
	return ErrBrokerUnsupported
}
