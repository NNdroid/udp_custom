package tunnel

import (
	"net"
	"net/netip"
	"time"
)

// packetReader batches datagram reception on ONE UDP socket: next() blocks for
// the first datagram, then drains up to recvBatch-1 more with an immediate
// deadline until the socket is empty. Under load this amortizes one poller
// wakeup and one deadline syscall across a whole burst instead of paying both
// per datagram.
//
// The returned packets BORROW the reader's internal buffers — they are valid
// only until the next next() call, so callers must process (or copy) them
// before reading again. Serve paths already dispatch synchronously.
//
// A true recvmmsg(2) batch would shave the remaining per-datagram recvmsg
// syscalls, but golang.org/x/sys does not export Recvmmsg/Mmsghdr on the
// toolchain's dependency set and hand-rolled raw syscall numbers per
// architecture are a maintenance hazard for a security tool. The drain loop
// captures most of the win portably.
type packetReader struct {
	conn   *net.UDPConn
	logger Logger      // may be nil; burst-drain visibility
	bufs   [][]byte    // recvBatch receive buffers, reused every call
	oob    [][]byte    // linux: ancillary-data buffers (origdst); nil elsewhere
	pkts   []udpPacket // result views into bufs

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

func newPacketReader(conn *net.UDPConn, logger Logger) *packetReader {
	r := &packetReader{conn: conn, logger: logger}
	for i := 0; i < recvBatch; i++ {
		buf := make([]byte, UDPC_MAX_PKT)
		r.bufs = append(r.bufs, buf)
		r.pkts = append(r.pkts, udpPacket{})
	}
	r.oob = newPacketReaderOOB(recvBatch)
	return r
}

// next returns 1..recvBatch received datagrams. A non-timeout error means the
// socket is broken (closed) and the reader is done.
func (r *packetReader) next() ([]udpPacket, error) {
	// First read blocks: the deadline must be clear here (drain below leaves
	// it set to the past, so clear it defensively every cycle).
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

	// Drain the socket: an already-expired deadline makes every further read
	// return immediately (data or timeout), so up to recvBatch-1 extra
	// datagrams are pulled with zero poller wakeups.
	drain := time.Now().Add(-time.Millisecond)
	for ; k < recvBatch; k++ {
		r.conn.SetReadDeadline(drain)
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
					continue // keep the slot for the next datagram
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
	// Burst visibility: one poller wakeup yielding k>1 datagrams proves the
	// drain loop is amortizing syscalls under load.
	if r.logger != nil && k > 1 {
		r.logger.Debugf("[Recv] burst drain: %d datagrams in one wakeup", k)
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
	r.logger.Warnf("[Recv] datagram from %s truncated at %d bytes (buffer %d): the peer sends larger records than this end accepts — align max_pkt on both sides",
		from, n, len(r.bufs[0]))
}
