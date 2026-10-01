package tunnel

import (
	"net"
	"net/netip"
	"time"
)

// packetReader batches datagram reception on ONE UDP socket: next() blocks for
// the first datagram through net.UDPConn (so the Go runtime poller owns the
// blocking wait), then drains the ready burst. Linux uses recvmmsg through the
// x/net batch socket layer; other platforms retain the portable immediate-
// deadline drain. This keeps idle sockets cheap while amortizing receive
// syscalls under load.
//
// The returned packets BORROW the reader's internal buffers — they are valid
// only until the next next() call, so callers must process (or copy) them
// before reading again. Serve paths already dispatch synchronously.
type packetReader struct {
	conn   *net.UDPConn
	logger Logger      // may be nil; truncation diagnostics (warn level)
	debug  bool        // gates the per-burst drain trace (debug level)
	bufs   [][]byte    // recvBatch receive buffers, reused every call
	oob    [][]byte    // linux: ancillary-data buffers (origdst); nil elsewhere
	pkts   []udpPacket // result views into bufs
	batch  packetBatchState

	// truncLogAt throttles the "datagram larger than our buffer" warning: a
	// truncated datagram is unauthenticated (any peer can trigger it), so the
	// log rate must not be attacker controlled.
	truncLogAt time.Time
}

// udpPacket is one received datagram: payload (borrowed), sender, and the
// original destination port when the platform reports it (Linux origdst).
type udpPacket struct {
	data     []byte
	from     netip.AddrPort
	origPort int
}

const recvBatch = 16

func newPacketReader(conn *net.UDPConn, logger Logger, debug bool) *packetReader {
	r := &packetReader{conn: conn, logger: logger, debug: debug}
	for i := 0; i < recvBatch; i++ {
		buf := make([]byte, UDPC_MAX_PKT)
		r.bufs = append(r.bufs, buf)
		r.pkts = append(r.pkts, udpPacket{})
	}
	r.oob = newPacketReaderOOB(recvBatch)
	r.batch = newPacketBatchState(conn, r.bufs, r.oob)
	return r
}

// next returns 1..recvBatch received datagrams. A non-timeout error means the
// socket is broken (closed) and the reader is done.
func (r *packetReader) next() ([]udpPacket, error) {
	// First read blocks in net.UDPConn, preserving Go netpoll integration. The
	// portable drain below may have left an expired deadline, so clear it once
	// per burst; the Linux batch path never sets one.
	r.conn.SetReadDeadline(time.Time{})

	var (
		n        int
		oobn     int
		msgFlags int
		from     netip.AddrPort
		origPort int
		err      error
	)
	if r.oob != nil {
		n, oobn, msgFlags, from, err = r.conn.ReadMsgUDPAddrPort(r.bufs[0], r.oob[0])
		if err == nil {
			if msgFlags&msgTruncFlag != 0 {
				origPort = 0 // truncated control data: never guess
			} else {
				origPort = packetReaderOOBPort(r.oob[0][:oobn])
			}
			if msgFlags&msgTruncDataFlag != 0 {
				// The peer sent more bytes than one record can hold. The tail
				// is gone, so authentication can only fail — drop it here and
				// say so, instead of reporting an opaque MAC failure.
				r.warnTruncated(n, from)
				return r.pkts[:0], nil
			}
		}
	} else {
		n, from, err = r.conn.ReadFromUDPAddrPort(r.bufs[0])
	}
	if err != nil {
		return nil, err
	}
	from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port()) // normalize v4-in-v6
	r.pkts[0] = udpPacket{data: r.bufs[0][:n], from: from, origPort: origPort}
	k := 1

	// Linux: after the poller-backed first read proved the socket readable,
	// drain the rest of the burst in one non-blocking recvmmsg call. If the
	// platform helper is unavailable it reports handled=false and we fall back
	// to the portable loop below.
	if end, handled, batchErr := r.batch.drain(r, k); handled {
		// Never discard the first packet because a follow-up batch drain failed.
		// The next cycle's blocking read will surface a persistent socket error.
		if batchErr == nil {
			k = end
		}
		if r.debug && k > 1 {
			r.logger.Debugf("[Recv] 🌊 batch drain: %d datagrams in one wakeup", k)
		}
		return r.pkts[:k], nil
	}

	// Portable fallback: an already-expired deadline makes every further read
	// return immediately (data or timeout), so up to recvBatch-1 extra datagrams
	// are drained without extra poller wakeups. It still pays one recv syscall
	// per datagram; Linux avoids that above with recvmmsg.
	drain := time.Now().Add(-time.Millisecond)
	r.conn.SetReadDeadline(drain)
	for ; k < recvBatch; k++ {
		if r.oob != nil {
			n, oobn, msgFlags, from, err = r.conn.ReadMsgUDPAddrPort(r.bufs[k], r.oob[k])
			if err == nil {
				if msgFlags&msgTruncFlag != 0 {
					origPort = 0
				} else {
					origPort = packetReaderOOBPort(r.oob[k][:oobn])
				}
				if msgFlags&msgTruncDataFlag != 0 {
					r.warnTruncated(n, from)
					// The slot still holds the PREVIOUS batch's packet — reuse
					// it for the next datagram instead of shipping the stale
					// view to the caller (k-- cancels this loop step).
					k--
					continue
				}
			}
		} else {
			n, from, err = r.conn.ReadFromUDPAddrPort(r.bufs[k])
		}
		if err != nil {
			break // drained: timeout (or socket closed — surfaced next cycle)
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		r.pkts[k] = udpPacket{data: r.bufs[k][:n], from: from, origPort: origPort}
	}
	// Restore blocking behaviour for the next cycle's first read.
	r.conn.SetReadDeadline(time.Time{})
	if r.debug && k > 1 {
		r.logger.Debugf("[Recv] 🌊 burst drain: %d datagrams in one wakeup", k)
	}
	return r.pkts[:k], nil
}

// warnTruncated reports a datagram the kernel had to cut down to the receive
// buffer — a peer sending records larger than this end's max_pkt. The bytes
// are incomplete and unauthenticated, so this is the only signal an operator
// gets; without it the packet simply fails MAC verification and vanishes.
func (r *packetReader) warnTruncated(n int, from netip.AddrPort) {
	if r.logger == nil {
		return
	}
	now := time.Now()
	if now.Sub(r.truncLogAt) < 5*time.Second {
		return
	}
	r.truncLogAt = now
	r.logger.Warnf("[Recv] ✂️ datagram from %s truncated at %d bytes (buffer %d): the peer sends larger records than this end accepts — align max_pkt on both sides",
		from, n, len(r.bufs[0]))
}
