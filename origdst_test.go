//go:build linux

package main

import (
	"encoding/binary"
	"net"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// buildCmsg hand-crafts an ancillary-data buffer exactly as recvmsg would
// deliver it, so parseOrigDstPort can be tested without a real DNAT setup.
func buildCmsg(t *testing.T, level, typ int32, data []byte) []byte {
	t.Helper()
	var hdr syscall.Cmsghdr
	hdr.Level = level
	hdr.Type = typ
	hdr.SetLen(syscall.CmsgLen(len(data)))

	buf := make([]byte, syscall.CmsgSpace(len(data)))
	copy(buf, (*(*[syscall.SizeofCmsghdr]byte)(unsafe.Pointer(&hdr)))[:])
	copy(buf[syscall.CmsgLen(0):], data)
	return buf
}

// sockaddrIn lays out struct sockaddr_in: family(2) + port(2, big endian).
func TestParseOrigDstPort_IPv4(t *testing.T) {
	data := make([]byte, 16)
	binary.LittleEndian.PutUint16(data[0:2], syscall.AF_INET)
	binary.BigEndian.PutUint16(data[2:4], 25007)
	copy(data[4:8], []byte{203, 0, 113, 10})

	oob := buildCmsg(t, syscall.IPPROTO_IP, ipOrigDstAddr, data)
	if got := parseOrigDstPort(oob); got != 25007 {
		t.Fatalf("parseOrigDstPort(IPv4) = %d, want 25007", got)
	}
}

// A dual-stack socket can report IPv4 datagrams through the IPv6 path, so
// IPV6_ORIGDSTADDR must be understood too.
func TestParseOrigDstPort_IPv6(t *testing.T) {
	data := make([]byte, 28)
	binary.LittleEndian.PutUint16(data[0:2], syscall.AF_INET6)
	binary.BigEndian.PutUint16(data[2:4], 25013)

	oob := buildCmsg(t, syscall.IPPROTO_IPV6, ipv6OrigDstAddr, data)
	if got := parseOrigDstPort(oob); got != 25013 {
		t.Fatalf("parseOrigDstPort(IPv6) = %d, want 25013", got)
	}
}

func TestParseOrigDstPort_NoOrigDst(t *testing.T) {
	if got := parseOrigDstPort(nil); got != 0 {
		t.Fatalf("parseOrigDstPort(nil) = %d, want 0", got)
	}
	if got := parseOrigDstPort([]byte{}); got != 0 {
		t.Fatalf("parseOrigDstPort(empty) = %d, want 0", got)
	}
	if got := parseOrigDstPort([]byte{1, 2, 3, 4}); got != 0 {
		t.Fatalf("parseOrigDstPort(garbage) = %d, want 0", got)
	}

	// An unrelated control message must be ignored, not mistaken for origdst.
	data := make([]byte, 16)
	binary.BigEndian.PutUint16(data[2:4], 9999)
	oob := buildCmsg(t, syscall.IPPROTO_IP, 1234, data)
	if got := parseOrigDstPort(oob); got != 0 {
		t.Fatalf("parseOrigDstPort(unrelated cmsg) = %d, want 0", got)
	}

	// Right type but truncated payload must not be read out of bounds.
	oob = buildCmsg(t, syscall.IPPROTO_IP, ipOrigDstAddr, []byte{0, 0})
	if got := parseOrigDstPort(oob); got != 0 {
		t.Fatalf("parseOrigDstPort(truncated) = %d, want 0", got)
	}
}

// TestReadWithOrigDst_NoAncillaryData is a smoke test for the recvmsg path on a
// plain loopback socket: with no DNAT there is no origdst cmsg, so the port must
// come back as 0 and the datagram must still be delivered.
func TestReadWithOrigDst_NoAncillaryData(t *testing.T) {
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer srv.Close()

	// Not fatal if the kernel refuses: some sandboxed environments block it.
	if err := enableOrigDst(srv); err != nil {
		t.Skipf("IP_RECVORIGDSTADDR unavailable: %v", err)
	}

	cli, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	defer cli.Close()

	payload := []byte("origdst-smoke")
	if _, err := cli.WriteToUDP(payload, srv.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("client write: %v", err)
	}

	buf := make([]byte, 128)
	_ = srv.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, from, origDstPort, err := readWithOrigDst(srv, buf)
	if err != nil {
		t.Fatalf("readWithOrigDst: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("got %q, want %q", buf[:n], payload)
	}
	if from == nil || from.Port != cli.LocalAddr().(*net.UDPAddr).Port {
		t.Fatalf("peer = %v, want %s", from, cli.LocalAddr())
	}
	// No DNAT is in place, so the kernel reports no original destination.
	if origDstPort != 0 {
		t.Fatalf("origDstPort = %d, want 0 with no DNAT", origDstPort)
	}
}
