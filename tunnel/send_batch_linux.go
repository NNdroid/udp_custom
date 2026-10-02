//go:build linux

package tunnel

import (
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"net"
	"net/netip"
	"syscall"
)

// Linux WriteBatch maps to sendmmsg. The caller retains every wire buffer
// through completion and falls back only for the unsent suffix on short writes.
func writeUDPBatch(conn *net.UDPConn, wires [][]byte, destinations []netip.AddrPort) (int, error) {
	msgs := make([]ipv4.Message, len(wires))
	for i := range wires {
		msgs[i].Buffers = [][]byte{wires[i]}
		msgs[i].Addr = net.UDPAddrFromAddrPort(destinations[i])
	}
	if la, ok := conn.LocalAddr().(*net.UDPAddr); ok && la.IP.To4() != nil {
		return ipv4.NewPacketConn(conn).WriteBatch(msgs, syscall.MSG_DONTWAIT)
	}
	return ipv6.NewPacketConn(conn).WriteBatch(msgs, syscall.MSG_DONTWAIT)
}
