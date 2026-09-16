//go:build linux

package tunnel

import (
	"errors"
	"net"
	"syscall"
)

// isRetryableUDPReadError reports whether a failed datagram read should be
// retried instead of tearing the receive loop down.
//
// ENOBUFS is the important one: under a burst the kernel socket buffer or the
// NIC queue can momentarily overflow and recvmsg surfaces it as an error on
// the receive path. The senders retransmit anyway, so a live loop that drops
// the occasional datagram is strictly better than a dead loop that answers
// nothing (the old behaviour — the process stayed up but went deaf).
func isRetryableUDPReadError(err error) bool {
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	return errors.Is(err, syscall.ENOBUFS) ||
		errors.Is(err, syscall.EINTR) ||
		errors.Is(err, syscall.EAGAIN)
}
