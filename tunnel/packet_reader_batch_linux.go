//go:build linux

package tunnel

import (
	"errors"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// packetBatchState owns the prebuilt x/net Message descriptors used to drain
// packets 1..recvBatch-1 after packetReader has obtained packet 0 through the
// poller-backed net.UDPConn read. x/net maps ReadBatch to recvmmsg on Linux.
type packetBatchState struct {
	v4       *ipv4.PacketConn
	v6       *ipv6.PacketConn
	msgs     []ipv4.Message // ipv4.Message and ipv6.Message alias the same socket.Message type
	disabled bool
}

func newPacketBatchState(conn *net.UDPConn, bufs [][]byte, oob [][]byte) packetBatchState {
	b := packetBatchState{}
	if len(bufs) <= 1 {
		b.disabled = true
		return b
	}

	b.msgs = make([]ipv4.Message, len(bufs)-1)
	for i := 1; i < len(bufs); i++ {
		b.msgs[i-1].Buffers = [][]byte{bufs[i]}
		if i < len(oob) {
			b.msgs[i-1].OOB = oob[i]
		}
	}

	// A wildcard IPv6 listener is commonly dual-stack; use the IPv6 wrapper
	// there and normalize v4-mapped source addresses after reception.
	if la, ok := conn.LocalAddr().(*net.UDPAddr); ok && la.IP.To4() != nil {
		b.v4 = ipv4.NewPacketConn(conn)
	} else {
		b.v6 = ipv6.NewPacketConn(conn)
	}
	return b
}

func (b *packetBatchState) drain(r *packetReader, start int) (end int, handled bool, err error) {
	if b == nil || b.disabled || start != 1 || len(b.msgs) == 0 {
		return start, false, nil
	}

	limit := recvBatch - start
	if limit > len(b.msgs) {
		limit = len(b.msgs)
	}
	msgs := b.msgs[:limit]

	var n int
	if b.v4 != nil {
		n, err = b.v4.ReadBatch(msgs, syscall.MSG_DONTWAIT)
	} else if b.v6 != nil {
		n, err = b.v6.ReadBatch(msgs, syscall.MSG_DONTWAIT)
	} else {
		b.disabled = true
		return start, false, nil
	}

	// recvmmsg may report already-consumed messages together with an error.
	// Preserve those datagrams first; only an error with n==0 affects fallback.
	k := start
	for i := 0; i < n; i++ {
		m := &msgs[i]
		ua, ok := m.Addr.(*net.UDPAddr)
		if !ok || ua == nil {
			continue
		}
		from := ua.AddrPort()
		if !from.IsValid() {
			continue
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())

		origPort := 0
		if m.Flags&msgTruncFlag == 0 && m.NN > 0 && m.NN <= len(m.OOB) {
			origPort = packetReaderOOBPort(m.OOB[:m.NN])
		}
		if m.Flags&msgTruncDataFlag != 0 {
			r.warnTruncated(m.N, from)
			continue
		}
		if len(m.Buffers) == 0 || m.N < 0 || m.N > len(m.Buffers[0]) {
			continue
		}
		r.pkts[k] = udpPacket{data: m.Buffers[0][:m.N], from: from, origPort: origPort}
		k++
	}
	if n > 0 {
		return k, true, nil
	}
	if err == nil || errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
		return start, true, nil
	}

	// If a kernel/platform combination cannot provide the batch operation,
	// disable it once and let packetReader use the existing portable drain.
	if errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.EOPNOTSUPP) {
		b.disabled = true
		return start, false, nil
	}
	return start, true, err
}
