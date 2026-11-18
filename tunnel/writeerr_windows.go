//go:build windows

package tunnel

import (
	"errors"
	"net"

	"golang.org/x/sys/windows"
)

// shouldReopenUDPWriteError mirrors the Linux errno allowlist with the Winsock
// equivalents. Go's syscall.EAGAIN on Windows is an APPLICATION_ERROR-series
// value, NOT WSAEWOULDBLOCK (10035), so the Linux-style errors.Is checks would
// never match real send-pressure errors here — the WSA constants come from
// x/sys/windows and are checked explicitly instead. WSAEWOULDBLOCK
// (non-blocking socket busy) and WSAEINPROGRESS (overlapped send in flight)
// are transient; WSAENOBUFS is the ENOBUFS analogue under burst load.
// Everything else — including WSAECONNRESET from an earlier send's ICMP
// port-unreachable and net.ErrClosed from a poisoned cached descriptor (the
// sendsock repair path depends on that) — triggers an in-place socket rebuild.
func shouldReopenUDPWriteError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, windows.WSAEWOULDBLOCK) ||
		errors.Is(err, windows.WSAEINPROGRESS) ||
		errors.Is(err, windows.WSAENOBUFS) {
		return false
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return false
	}
	return true
}
