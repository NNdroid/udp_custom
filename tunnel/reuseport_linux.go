//go:build linux

package tunnel

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// bindReuseportUDP binds one UDP socket to addr with SO_REUSEPORT set BEFORE
// bind — the kernel records group membership at bind(2) time, so setting the
// option after a plain bind is ineffective and every later join to the port
// fails with EADDRINUSE. This is why ListenConfig.Control (which runs between
// socket(2) and bind(2)) is used here instead of post-bind SetsockoptInt.
//
// On Linux the kernel then load-balances incoming datagrams across all
// sockets sharing the (protocol, addr, port) reuseport group, hashing on the
// 4-tuple — so every datagram from one client source socket lands on the same
// receiver (in-order per client), while different clients spread across the
// group. The FIRST socket of the group must carry the option too, otherwise
// no later socket can join.
func bindReuseportUDP(addr *net.UDPAddr) (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var serr error
			if cerr := c.Control(func(fd uintptr) {
				serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			}); cerr != nil {
				return cerr
			}
			return serr
		},
	}
	pc, err := lc.ListenPacket(context.Background(), "udp", addr.String())
	if err != nil {
		return nil, err
	}
	conn, ok := pc.(*net.UDPConn)
	if !ok {
		return nil, fmt.Errorf("reuseport: %T is not a UDP connection", pc)
	}
	return conn, nil
}

// reuseportSupported reports whether the platform implements the reuseport
// bind helper. Used to clamp ReceiveSockets at startup.
const reuseportSupported = true
