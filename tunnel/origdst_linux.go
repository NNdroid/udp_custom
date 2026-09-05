//go:build linux

package tunnel

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
)

// IP_RECVORIGDSTADDR (socket option) and IP_ORIGDSTADDR (ancillary-data type)
// are both 20 on Linux. They let the server recover the ORIGINAL destination
// address of a datagram, i.e. the address BEFORE nftables/iptables DNAT rewrote
// it. This is the only way for the server to learn which port of the client's
// spread range a given packet was actually sent to.
//
// Why this matters: when a client spreads every datagram across a destination
// port range and the firewall DNATs the whole range onto one internal port, the
// server sees every packet arriving on that single port and cannot tell them
// apart. Without the original destination port it must reply from the single
// socket, so the reply's source port does not match the port the client sent
// to — and a client behind a symmetric NAT/CGNAT drops those replies.
const (
	// IPv4: both the "enable" socket option and the ancillary-data type are 20.
	ipRecvOrigDstAddr = 20
	ipOrigDstAddr     = 20

	// IPv6: IPV6_RECVORIGDSTADDR / IPV6_ORIGDSTADDR are both 74. Needed because
	// net.ListenUDP("udp", ":port") produces a DUAL-STACK socket, on which IPv4
	// datagrams may be reported through the IPv6 control-message path.
	ipv6RecvOrigDstAddr = 74
	ipv6OrigDstAddr     = 74
)

// enableOrigDst makes the socket report the pre-DNAT destination address via
// ancillary data on recvmsg.
//
// It enables both the IPv4 and the IPv6 option. Which one actually applies
// depends on the socket's family, and a dual-stack socket can use either, so we
// simply request both and fail only if neither is accepted.
func enableOrigDst(conn *net.UDPConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := raw.Control(func(fd uintptr) {
		// An IPv4-only socket rejects the IPv6 option and vice versa, so treat
		// "at least one accepted" as success.
		v4err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipRecvOrigDstAddr, 1)
		v6err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6RecvOrigDstAddr, 1)
		if v4err != nil && v6err != nil {
			serr = fmt.Errorf("IP_RECVORIGDSTADDR: %v; IPV6_RECVORIGDSTADDR: %v", v4err, v6err)
		}
	}); err != nil {
		return err
	}
	return serr
}

// readWithOrigDst reads one datagram and returns (n, srcAddr, origDstPort, err).
// origDstPort is the destination port the client originally addressed (before
// DNAT); it is 0 when the kernel did not report it, in which case callers fall
// back to replying from the main socket.
func readWithOrigDst(conn *net.UDPConn, buf []byte) (int, *net.UDPAddr, int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, nil, 0, err
	}

	// 512 bytes comfortably holds a full IPv4/IPv6 ORIGDSTADDR control message
	// (cmsg_hdr 16 + sockaddr_in6 28 ≈ 44 bytes); the size mainly guards
	// against MSG_CTRUNC if the kernel ever coalesces extra control data, in
	// which case the original port would be unparsable and we must NOT guess.
	oob := make([]byte, 512)
	var (
		n, oobn  int
		msgFlags int
		from     syscall.Sockaddr
		rerr     error
		done     bool
	)

	// raw.Read drives the runtime poller: returning false means "would block",
	// so the runtime waits for the fd to become readable and retries.
	if err := raw.Read(func(fd uintptr) bool {
		n, oobn, msgFlags, from, rerr = syscall.Recvmsg(int(fd), buf, oob, 0)
		if rerr == syscall.EAGAIN || rerr == syscall.EWOULDBLOCK || rerr == syscall.EINTR {
			return false
		}
		done = true
		return true
	}); err != nil {
		return 0, nil, 0, err
	}
	if rerr != nil {
		return 0, nil, 0, rerr
	}
	if !done {
		return 0, nil, 0, syscall.EAGAIN
	}

	// A truncated control message may contain a partial (garbage) sockaddr;
	// treat it as "no original port" and fall back to the main socket.
	if msgFlags&syscall.MSG_CTRUNC != 0 {
		return n, sockaddrToUDP(from), 0, nil
	}

	return n, sockaddrToUDP(from), parseOrigDstPort(oob[:oobn]), nil
}

func sockaddrToUDP(sa syscall.Sockaddr) *net.UDPAddr {
	switch v := sa.(type) {
	case *syscall.SockaddrInet4:
		ip := make(net.IP, net.IPv4len)
		copy(ip, v.Addr[:])
		return &net.UDPAddr{IP: ip, Port: v.Port}
	case *syscall.SockaddrInet6:
		ip := make(net.IP, net.IPv6len)
		copy(ip, v.Addr[:])
		return &net.UDPAddr{IP: ip, Port: v.Port}
	}
	return nil
}

// parseOrigDstPort extracts the original (pre-DNAT) destination port from the
// IP_ORIGDSTADDR / IPV6_ORIGDSTADDR control message. It returns 0 when the
// kernel reported nothing, which callers treat as "reply from the main socket".
func parseOrigDstPort(oob []byte) int {
	if len(oob) == 0 {
		return 0
	}
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return 0
	}
	for i := range msgs {
		m := &msgs[i]
		var minLen int
		switch {
		case m.Header.Level == syscall.IPPROTO_IP && m.Header.Type == ipOrigDstAddr:
			minLen = 16 // sizeof(struct sockaddr_in)
		case m.Header.Level == syscall.IPPROTO_IPV6 && m.Header.Type == ipv6OrigDstAddr:
			minLen = 28 // sizeof(struct sockaddr_in6)
		default:
			continue
		}
		if len(m.Data) < minLen {
			continue
		}
		// Both sockaddr_in and sockaddr_in6 place the port at byte offset 2 as
		// a big-endian uint16, so one decode covers both — and avoids unsafe
		// and any host-endianness assumption.
		return int(binary.BigEndian.Uint16(m.Data[2:4]))
	}
	return 0
}
