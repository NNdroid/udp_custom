//go:build !linux

package tunnel

import (
	"errors"
	"net"
	"net/netip"
)

// enableOrigDst reports the platform limitation instead of pretending to
// succeed: a nil here would flip ServerStats.OrigDstOK to true on non-Linux
// platforms while origdst is actually unavailable. The server then logs an
// honest warning and falls back to the main reply socket.
func enableOrigDst(conn *net.UDPConn) error {
	return errors.New("IP_RECVORIGDSTADDR is Linux-only")
}

// readWithOrigDst falls back to a plain recvfrom. origDstPort is always 0,
// which makes sendTo use the main socket (pre-existing behaviour). The address
// is normalized like the Linux path so session bookkeeping sees one form.
func readWithOrigDst(conn *net.UDPConn, buf []byte) (int, netip.AddrPort, int, error) {
	n, addr, err := conn.ReadFromUDPAddrPort(buf)
	if err != nil {
		return 0, netip.AddrPort{}, 0, err
	}
	return n, netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port()), 0, nil
}

// packetReaderOOBPort never runs outside Linux (the reader has no OOB buffers
// there); it exists so the batched reader compiles on every platform.
func packetReaderOOBPort(oob []byte) int {
	return 0
}
