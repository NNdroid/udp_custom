//go:build !linux

package tunnel

import (
	"net"
	"net/netip"
)

func writeUDPBatch(conn *net.UDPConn, wires [][]byte, destinations []netip.AddrPort) (int, error) {
	for i := range wires {
		if _, err := conn.WriteToUDPAddrPort(wires[i], destinations[i]); err != nil {
			return i, err
		}
	}
	return len(wires), nil
}
