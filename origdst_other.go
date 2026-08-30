//go:build !linux

package main

import "net"

// enableOrigDst is a no-op outside Linux: IP_RECVORIGDSTADDR is Linux-specific.
// On other platforms the server keeps its original behaviour and always replies
// from the main listening socket.
func enableOrigDst(conn *net.UDPConn) error { return nil }

// readWithOrigDst falls back to a plain recvfrom. origDstPort is always 0,
// which makes sendTo use the main socket (pre-existing behaviour).
func readWithOrigDst(conn *net.UDPConn, buf []byte) (int, *net.UDPAddr, int, error) {
	n, addr, err := conn.ReadFromUDP(buf)
	if err != nil {
		return 0, nil, 0, err
	}
	return n, addr, 0, nil
}
