//go:build linux

package tunnel

import (
	"errors"
	"net"
	"syscall"
)

// shouldReopenUDPWriteError distinguishes a broken socket/path from transient
// send pressure. ENOBUFS/EAGAIN/EINTR and timeouts are expected to recover on
// the existing socket and are already covered by ARQ retransmission. Other
// errors (including a closed descriptor or interface teardown) trigger an
// in-place socket rebuild.
func shouldReopenUDPWriteError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ENOBUFS) ||
		errors.Is(err, syscall.EAGAIN) ||
		errors.Is(err, syscall.EINTR) {
		return false
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return false
	}
	return true
}
