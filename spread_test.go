package main

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// --- helpers ----------------------------------------------------------------

func echoServeAll(t *testing.T, ln net.Listener) {
	t.Helper()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer conn.Close()
			io.Copy(conn, conn)
		}(c)
	}
}

func buildSynFrameWithPSK(t *testing.T, psk string) *UDPCFrame {
	t.Helper()
	var nonce [16]byte
	rand.Read(nonce[:])
	now := time.Now().Unix()
	payload := make([]byte, 56)
	copy(payload[0:16], nonce[:])
	binary.BigEndian.PutUint64(payload[16:24], uint64(now))
	copy(payload[24:56], ComputeAuthHMAC(nonce[:], psk, now))
	return &UDPCFrame{
		Magic:   UDPC_MAGIC_DEFAULT,
		Version: UDPC_VERSION,
		Cmd:     CMD_HANDSHAKE_SYN,
		Data:    payload,
	}
}

func readFrameFromConn(t *testing.T, conn *net.UDPConn, timeout time.Duration) *UDPCFrame {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 2048)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	f, err := DecodeUDPCFrame(buf[:n], UDPC_MAGIC_DEFAULT)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return f
}

func TestSpreadDialerBindsSocketsAndSpreadsPorts(t *testing.T) {
	d, err := NewSpreadDialer("203.0.113.10:25000-25499", 4, 0)
	if err != nil {
		t.Fatalf("NewSpreadDialer: %v", err)
	}
	defer d.Close()

	if d.Len() != 4 {
		t.Fatalf("Len = %d, want 4", d.Len())
	}
	if d.PortRange().Total() != 500 {
		t.Fatalf("port range total = %d, want 500", d.PortRange().Total())
	}

	// Distinct local source ports: K sockets must really use K source ports.
	srcPorts := map[int]bool{}
	for _, c := range d.Conns() {
		srcPorts[c.LocalAddr().(*net.UDPAddr).Port] = true
	}
	if len(srcPorts) != 4 {
		t.Fatalf("expected 4 distinct local ports, got %d", len(srcPorts))
	}

	// Both dimensions must vary: sockets round-robin, ports are random.
	seenSockets := map[int]bool{}
	seenPorts := map[int]bool{}
	for i := 0; i < 2000; i++ {
		idx, port := d.Next()
		if idx < 0 || idx > 3 {
			t.Fatalf("socket index out of range: %d", idx)
		}
		if port < 25000 || port > 25499 {
			t.Fatalf("port %d outside the advertised range", port)
		}
		seenSockets[idx] = true
		seenPorts[port] = true
	}
	if len(seenSockets) != 4 {
		t.Fatalf("only %d sockets used, want 4", len(seenSockets))
	}
	// 2000 samples over 500 ports: essentially the whole range should appear.
	if len(seenPorts) < 400 {
		t.Fatalf("only %d distinct ports used out of 500 (after 2000 samples)", len(seenPorts))
	}
}

func TestSpreadDialerRejectsBadAddress(t *testing.T) {
	if _, err := NewSpreadDialer("not-an-address", 2, 0); err == nil {
		t.Fatal("expected an error for a malformed address")
	}
	if _, err := NewSpreadDialer("203.0.113.10:70000-70001", 1, 0); err == nil {
		t.Fatal("expected an error for an out-of-range port")
	}
	// A single port is still valid (no spreading at all).
	d, err := NewSpreadDialer("127.0.0.1:36712", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if d.Len() != 1 {
		t.Fatalf("Len = %d, want 1", d.Len())
	}
}

// Multi-socket clients must work against the real server: the client's source
// port changes when it sends from a different socket, and the server follows
// that (port-only change on the same IP = NAT rebinding, always accepted).
// The echo must come back to the socket that sent the request.
func TestSpreadDialerMultiSocketAgainstServer(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	defer echoLn.Close()
	go echoServeAll(t, echoLn)

	serverUDP := "127.0.0.1:39720"
	srv, err := NewUDPCServer(ServerConfig{
		ListenAddr: serverUDP,
		TargetAddr: echoLn.Addr().String(),
		Passwords:  []string{"secret_psk"},
	})
	if err != nil {
		t.Fatalf("NewUDPCServer: %v", err)
	}
	go srv.Start()
	defer srv.Close()
	time.Sleep(100 * time.Millisecond)

	// Single remote port (no DNAT available in tests) x 3 local sockets.
	d, err := NewSpreadDialer(serverUDP, 3, 0)
	if err != nil {
		t.Fatalf("NewSpreadDialer: %v", err)
	}
	defer d.Close()

	// Handshake from socket 0.
	syn := buildSynFrameWithPSK(t, "secret_psk")
	if err := d.SendAt(0, syn.Encode()); err != nil {
		t.Fatalf("send syn: %v", err)
	}
	ackFrame := readFrameFromConn(t, d.Conn(0), time.Second)
	if ackFrame.Cmd != CMD_HANDSHAKE_ACK {
		t.Fatalf("want ACK, got cmd=%d", ackFrame.Cmd)
	}
	sid := ackFrame.SessionID

	// Request from socket 1 → the server must follow the new source port and
	// reply to socket 1.
	seq := uint32(1)
	for _, idx := range []int{1, 2, 0} {
		payload := []byte{byte('a' + idx)}
		dataSeq := seq
		seq++
		if err := d.SendAt(idx, (&UDPCFrame{
			Magic:     UDPC_MAGIC_DEFAULT,
			Version:   UDPC_VERSION,
			Cmd:       CMD_DATA,
			SessionID: sid,
			Seq:       dataSeq,
			Data:      payload,
		}).Encode()); err != nil {
			t.Fatalf("send from socket %d: %v", idx, err)
		}
		// The ACK and the echo both land on the socket that sent.
		_ = readFrameFromConn(t, d.Conn(idx), time.Second) // ACK
		echo := readFrameFromConn(t, d.Conn(idx), time.Second)
		if echo.Cmd != CMD_DATA {
			t.Fatalf("socket %d: want DATA, got cmd=%d", idx, echo.Cmd)
		}
		if len(echo.Data) != 1 || echo.Data[0] != payload[0] {
			t.Fatalf("socket %d: echo mismatch %q", idx, echo.Data)
		}
	}
}

// Paths > 0 must pin a fixed subset of remote ports for the session, all
// within the configured range and all distinct.
func TestSpreadDialerPicksFixedPaths(t *testing.T) {
	d, err := NewSpreadDialer("203.0.113.10:25000-25499", 2, 32)
	if err != nil {
		t.Fatalf("NewSpreadDialer: %v", err)
	}
	defer d.Close()

	if d.Paths() != 32 {
		t.Fatalf("Paths() = %d, want 32", d.Paths())
	}
	if d.PortRange().Total() != 500 {
		t.Fatalf("PortRange().Total() = %d, want 500 (configured range unchanged)", d.PortRange().Total())
	}

	seen := map[int]bool{}
	for i := 0; i < 4000; i++ {
		_, port := d.Next()
		if port < 25000 || port > 25499 {
			t.Fatalf("port %d outside the configured range", port)
		}
		seen[port] = true
	}
	// With 32 fixed ports, only those 32 should ever appear.
	if len(seen) != 32 {
		t.Fatalf("distinct ports used = %d, want exactly 32 (fixed subset)", len(seen))
	}
}

// Paths >= range size collapses to the whole range.
func TestSpreadDialerPathsExceedsRange(t *testing.T) {
	d, err := NewSpreadDialer("203.0.113.10:25000-25499", 1, 9999)
	if err != nil {
		t.Fatalf("NewSpreadDialer: %v", err)
	}
	defer d.Close()
	if d.Paths() != 500 {
		t.Fatalf("Paths() = %d, want 500 (clamped to range)", d.Paths())
	}
}
