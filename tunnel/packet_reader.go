package tunnel

import (
	"net"
	"net/netip"
	"time"
)

// packetReader batches datagram reception on ONE UDP socket. Linux provides a
// recvmmsg(2) backend (packet_reader_batch_linux.go), while other platforms and
// kernels without recvmmsg support use nextDrain below. Both paths preserve the
// same borrowed-buffer, truncation and original-destination semantics.
//
// The returned packets BORROW the reader's internal buffers — they are valid
// only until the next next() call, so callers must process (or copy) them
// before reading again. Serve paths already dispatch synchronously.
type packetReader struct {
	conn   *net.UDPConn
	logger Logger      // may be nil; truncation diagnostics (warn level)
	debug  bool        // gates the per-burst receive trace (debug level)
	bufs   [][]byte    // recvBatch receive buffers, reused every call
	oob    [][]byte    // linux: ancillary-data buffers (origdst); nil elsewhere
	pkts   []udpPacket // result views into bufs

	// batch contains platform-specific receive state. The concrete type is
	// supplied by packet_reader_batch_{linux,other}.go.
	batch packetReaderBatch

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
	r.initPacketReaderBatch()
	return r
}

// nextDrain is the portable fallback. The first read blocks and then an expired
// deadline drains up to recvBatch-1 more datagrams without another poller wait.
// It still performs one recv syscall per datagram, which is why Linux prefers
// recvmmsg(2), but it is retained for portability and as an ENOSYS fallback.
func (r *packetReader) nextDrain() ([]udpPacket, error) {
	// First read blocks: the deadline must be clear here (drain below leaves
	// it set to the past, so clear it defensively every cycle).
	_ = r.conn.SetReadDeadline(time.Time{})

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

	// Drain the socket: an already-expired deadline makes every further read
	// return immediately (data or timeout), so up to recvBatch-1 extra
	// datagrams are pulled with zero poller wakeups. The deadline is set once
	// — an expired deadline stays expired, and successful reads do not clear it.
	drain := time.Now().Add(-time.Millisecond)
	_ = r.conn.SetReadDeadline(drain)
	for ; k < recvBatch; k++ {
		origPort = 0
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
	_ = r.conn.SetReadDeadline(time.Time{})
	if r.debug && k > 1 && r.logger != nil {
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
