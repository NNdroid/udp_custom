//go:build !linux

package tunnel

import "net"

// bindReuseportUDP is the non-Linux stub: other platforms have no portable
// SO_REUSEPORT (and the server's origdst mirroring is Linux-only anyway), so
// multi-socket receive degrades to the plain single bind. NewServer clamps
// ReceiveSockets to 1 on these platforms.
func bindReuseportUDP(addr *net.UDPAddr) (*net.UDPConn, error) {
	return net.ListenUDP("udp", addr)
}

// reuseportSupported reports whether the platform implements the reuseport
// bind helper. Used to clamp ReceiveSockets at startup.
const reuseportSupported = false
