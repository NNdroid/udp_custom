//go:build !linux && !unix && !windows

package tunnel

import (
	"net"
)

// shouldReopenUDPWriteError for platforms without a portable errno surface
// (plan9, js/wasm, ...): timeouts are transient send pressure that ARQ
// retransmission already covers, and EVERYTHING else — including net.ErrClosed
// from a poisoned cached descriptor (the sendsock repair path depends on
// that) — triggers an in-place socket rebuild.
//
// net.Error.Temporary is deprecated and not consulted here; the Linux side
// never used it either.
func shouldReopenUDPWriteError(err error) bool {
	if err == nil {
		return false
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return false
	}
	return true
}
