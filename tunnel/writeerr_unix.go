//go:build unix && !linux

package tunnel

import (
	"errors"
	"net"
	"syscall"
)

// shouldReopenUDPWriteError mirrors the Linux variant's semantics: transient
// send pressure (ENOBUFS under a burst, EAGAIN, EINTR) and timeouts are
// expected to recover on the existing socket and are already covered by ARQ
// retransmission; everything else — including net.ErrClosed from a poisoned
// cached descriptor (the sendsock repair path depends on that) — triggers an
// in-place socket rebuild. 10b056d claimed this alignment; the original
// "other" file only exempted timeouts.
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
