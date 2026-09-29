//go:build !linux

package tunnel

import "net"

// Non-Linux platforms do not expose one portable errno set for UDP send
// pressure. Treat timeout/temporary network errors as transient and rebuild on
// all other failures.
func shouldReopenUDPWriteError(err error) bool {
	if err == nil {
		return false
	}
	if ne, ok := err.(net.Error); ok {
		if ne.Timeout() || ne.Temporary() {
			return false
		}
	}
	return true
}
