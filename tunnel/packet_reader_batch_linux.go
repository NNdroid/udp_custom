//go:build linux

package tunnel

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// linuxMMsgHdr mirrors Linux struct mmsghdr. Go supplies the same trailing
// alignment padding that C applies after msg_len, so an array of these can be
// passed directly to recvmmsg(2) on every Linux architecture supported by Go.
type linuxMMsgHdr struct {
	Hdr unix.Msghdr
	Len uint32
}

// packetReaderBatch owns all recvmmsg descriptors. Their backing memory is
// allocated once with the packetReader and reused for every receive burst.
type packetReaderBatch struct {
	raw      syscall.RawConn
	initErr  error
	disabled bool
	msgs     [recvBatch]linuxMMsgHdr
	iov      [recvBatch]unix.Iovec
	names    [recvBatch]unix.RawSockaddrAny
}

func (r *packetReader) initPacketReaderBatch() {
	raw, err := r.conn.SyscallConn()
	if err != nil {
		r.batch.initErr = err
		return
	}
	r.batch.raw = raw
}

// next receives up to recvBatch datagrams with one recvmmsg(2) syscall. The
// syscall itself is non-blocking; RawConn.Read integrates EAGAIN with Go's
// network poller so an idle socket still sleeps efficiently without deadline
// syscalls. Kernels that unexpectedly lack recvmmsg fall back permanently to
// the portable drain loop.
func (r *packetReader) next() ([]udpPacket, error) {
	if r.batch.raw == nil || r.batch.disabled {
		return r.nextDrain()
	}
	if r.batch.initErr != nil {
		return nil, r.batch.initErr
	}

	r.prepareRecvMMsg()

	var (
		n       int
		callErr error
	)
	err := r.batch.raw.Read(func(fd uintptr) bool {
		n0, _, errno := unix.Syscall6(
			unix.SYS_RECVMMSG,
			fd,
			uintptr(unsafe.Pointer(&r.batch.msgs[0])),
			uintptr(recvBatch),
			uintptr(unix.MSG_DONTWAIT),
			0,
			0,
		)
		if errno == unix.EAGAIN || errno == unix.EWOULDBLOCK {
			return false
		}
		if errno == unix.ENOSYS {
			r.batch.disabled = true
			callErr = errno
			return true
		}
		if errno != 0 {
			callErr = errno
			return true
		}
		n = int(n0)
		return true
	})
	if err != nil {
		return nil, err
	}
	if callErr == unix.ENOSYS {
		return r.nextDrain()
	}
	if callErr != nil {
		return nil, callErr
	}

	got := 0
	for i := 0; i < n; i++ {
		m := &r.batch.msgs[i]
		from, ok := rawSockaddrAddrPort(&r.batch.names[i])
		if !ok {
			return nil, fmt.Errorf("packet reader: unsupported source address family %d", r.batch.names[i].Addr.Family)
		}

		msgLen := int(m.Len)
		flags := int(m.Hdr.Flags)
		if flags&msgTruncDataFlag != 0 {
			r.warnTruncated(msgLen, from)
			continue
		}
		// Be defensive even though a non-truncated datagram cannot be larger
		// than its iovec. This also prevents a malformed kernel result from
		// becoming a slice-bounds panic in the receive loop.
		if msgLen > len(r.bufs[i]) {
			msgLen = len(r.bufs[i])
		}

		origPort := 0
		if flags&msgTruncFlag == 0 && m.Hdr.Controllen > 0 && len(r.oob[i]) > 0 {
			oobn := int(m.Hdr.Controllen)
			if oobn > len(r.oob[i]) {
				oobn = len(r.oob[i])
			}
			origPort = packetReaderOOBPort(r.oob[i][:oobn])
		}
		r.pkts[got] = udpPacket{data: r.bufs[i][:msgLen], from: from, origPort: origPort}
		got++
	}
	// Keep all backing arrays reachable until the kernel has finished writing
	// through the raw pointers stored in the message headers.
	keepPacketReaderAlive(r)

	if r.debug && n > 1 && r.logger != nil {
		r.logger.Debugf("[Recv] 🌊 recvmmsg: %d datagrams in one syscall", n)
	}
	return r.pkts[:got], nil
}

func (r *packetReader) prepareRecvMMsg() {
	for i := 0; i < recvBatch; i++ {
		buf := r.bufs[i]
		iov := &r.batch.iov[i]
		*iov = unix.Iovec{Base: &buf[0]}
		iov.SetLen(len(buf))

		msg := &r.batch.msgs[i]
		msg.Len = 0
		msg.Hdr = unix.Msghdr{}
		msg.Hdr.Name = (*byte)(unsafe.Pointer(&r.batch.names[i]))
		msg.Hdr.Namelen = uint32(unsafe.Sizeof(r.batch.names[i]))
		msg.Hdr.Iov = iov
		msg.Hdr.SetIovlen(1)
		if len(r.oob[i]) > 0 {
			msg.Hdr.Control = &r.oob[i][0]
			msg.Hdr.SetControllen(len(r.oob[i]))
		}
	}
}

// keepPacketReaderAlive is split out so the receive path documents the lifetime
// requirement without importing runtime in the portable implementation file.
func keepPacketReaderAlive(r *packetReader) {
	// The compiler recognizes KeepAlive only through runtime.KeepAlive; keeping
	// an explicit use here after the syscall is also sufficient because r owns
	// every pointed-to buffer and descriptor.
	_ = r.batch.msgs[0].Len
}

func rawSockaddrAddrPort(raw *unix.RawSockaddrAny) (netip.AddrPort, bool) {
	switch raw.Addr.Family {
	case unix.AF_INET:
		sa := (*unix.RawSockaddrInet4)(unsafe.Pointer(raw))
		b := unsafe.Slice((*byte)(unsafe.Pointer(sa)), int(unsafe.Sizeof(*sa)))
		port := binary.BigEndian.Uint16(b[2:4])
		return netip.AddrPortFrom(netip.AddrFrom4(sa.Addr), port), true
	case unix.AF_INET6:
		sa := (*unix.RawSockaddrInet6)(unsafe.Pointer(raw))
		b := unsafe.Slice((*byte)(unsafe.Pointer(sa)), int(unsafe.Sizeof(*sa)))
		port := binary.BigEndian.Uint16(b[2:4])
		return netip.AddrPortFrom(netip.AddrFrom16(sa.Addr).Unmap(), port), true
	default:
		return netip.AddrPort{}, false
	}
}
