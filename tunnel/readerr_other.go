//go:build !linux

package tunnel

import (
	"net"
)

// isRetryableUDPReadError reports whether a failed datagram read should be
// retried instead of tearing the receive loop down.
//
// Non-Linux builds stay conservative: only deadline timeouts are retried. The
// syscall errnos worth retrying (ENOBUFS, EINTR, EAGAIN) either do not exist
// as constants in this platform's syscall package or have WSA-specific
// equivalents, and Linux is the platform this server deploys to.
func isRetryableUDPReadError(err error) bool {
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	return false
}
