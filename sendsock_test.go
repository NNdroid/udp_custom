package main

import (
	"net"
	"sync"
	"testing"
	"time"
)

// freeUDPPorts reserves n ephemeral UDP ports, releases them, and returns the
// numbers. They are very likely still free for the duration of the test, and
// using the OS's own choice avoids hard-coding ports that may already be taken.
func freeUDPPorts(t *testing.T, n int) []int {
	t.Helper()
	ports := make([]int, 0, n)
	conns := make([]*net.UDPConn, 0, n)
	for i := 0; i < n; i++ {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			for _, open := range conns {
				_ = open.Close()
			}
			t.Fatalf("reserve ephemeral port: %v", err)
		}
		conns = append(conns, c)
		ports = append(ports, c.LocalAddr().(*net.UDPAddr).Port)
	}
	for _, c := range conns {
		_ = c.Close()
	}
	return ports
}

func TestSendSockPool_BindsRequestedSourcePort(t *testing.T) {
	ports := freeUDPPorts(t, 1)
	p := newSendSockPool(8, nil)
	defer p.Close()

	c, err := p.Get(ports[0])
	if err != nil {
		t.Fatalf("Get(%d): %v", ports[0], err)
	}
	if got := c.LocalAddr().(*net.UDPAddr).Port; got != ports[0] {
		t.Fatalf("socket bound to port %d, want %d", got, ports[0])
	}

	// Second request must be served from the cache (same *net.UDPConn).
	c2, err := p.Get(ports[0])
	if err != nil {
		t.Fatalf("Get(%d) again: %v", ports[0], err)
	}
	if c2 != c {
		t.Fatal("expected a cache hit to return the very same socket")
	}
}

func TestSendSockPool_RejectsInvalidPorts(t *testing.T) {
	p := newSendSockPool(4, nil)
	defer p.Close()
	for _, bad := range []int{0, -1, 65536, 70000} {
		if _, err := p.Get(bad); err == nil {
			t.Errorf("Get(%d) succeeded, want error", bad)
		}
	}
}

func TestSendSockPool_LRUEvictsLeastRecentlyUsed(t *testing.T) {
	ports := freeUDPPorts(t, 3)
	p := newSendSockPool(2, nil) // deliberately smaller than the 3 ports
	defer p.Close()

	first, err := p.Get(ports[0])
	if err != nil {
		t.Fatalf("Get(%d): %v", ports[0], err)
	}
	if _, err := p.Get(ports[1]); err != nil {
		t.Fatalf("Get(%d): %v", ports[1], err)
	}

	// Touch ports[0] so ports[1] becomes the eviction candidate.
	if _, err := p.Get(ports[0]); err != nil {
		t.Fatalf("Get(%d) refresh: %v", ports[0], err)
	}

	if _, err := p.Get(ports[2]); err != nil {
		t.Fatalf("Get(%d): %v", ports[2], err)
	}
	if p.Len() != 2 {
		t.Fatalf("pool size after overflow = %d, want 2", p.Len())
	}

	// ports[0] survived (it was used most recently)...
	again, err := p.Get(ports[0])
	if err != nil {
		t.Fatalf("Get(%d) after eviction: %v", ports[0], err)
	}
	if again != first {
		t.Error("ports[0] was evicted despite being the most recently used")
	}

	// ...and ports[1] was evicted, so it now gets a brand new socket.
	if _, err := p.Get(ports[1]); err != nil {
		t.Fatalf("Get(%d) after eviction: %v", ports[1], err)
	}
}

func TestSendSockPool_DefaultLimitAndConcurrentGet(t *testing.T) {
	p := newSendSockPool(0, nil) // 0 must mean "use the default"
	defer p.Close()
	if p.limit != 512 {
		t.Fatalf("default limit = %d, want 512", p.limit)
	}

	ports := freeUDPPorts(t, 4)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if _, err := p.Get(ports[i%len(ports)]); err != nil {
					t.Errorf("concurrent Get: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
	if p.Len() > p.limit {
		t.Fatalf("pool grew to %d, over the limit %d", p.Len(), p.limit)
	}
}

func TestSendSockPool_CloseReleasesEverything(t *testing.T) {
	ports := freeUDPPorts(t, 2)
	p := newSendSockPool(4, nil)
	for _, pt := range ports {
		if _, err := p.Get(pt); err != nil {
			t.Fatalf("Get(%d): %v", pt, err)
		}
	}
	p.Close()
	if p.Len() != 0 {
		t.Fatalf("pool size after Close = %d, want 0", p.Len())
	}
}

// TestReplyFromOrigPort_UsesPerPortSocket is the core regression test for
// port-range spreading: given the pre-DNAT destination port a client
// addressed, the server must reply FROM that port. A client behind symmetric
// NAT / CGNAT drops anything else.
func TestReplyFromOrigPort_UsesPerPortSocket(t *testing.T) {
	ports := freeUDPPorts(t, 2)
	replyPort := ports[0]
	clientPort := ports[1]

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: clientPort})
	if err != nil {
		t.Fatalf("client socket: %v", err)
	}
	defer client.Close()

	srv, err := NewUDPCServer(ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TargetAddr: "udp://127.0.0.1:1",
		Magic:      UDPC_MAGIC_DEFAULT,
		LogLevel:   "error",
	})
	if err != nil {
		t.Fatalf("NewUDPCServer: %v", err)
	}
	defer srv.Close()

	payload := []byte("mirror-me")
	// The server recovers replyPort via IP_RECVORIGDSTADDR on the real path;
	// here we feed it directly. replyFromOrigPort must bind a socket on
	// replyPort and send from it.
	srv.replyFromOrigPort(replyPort, client.LocalAddr(), payload)

	buf := make([]byte, 64)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, from, err := client.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("client got %q, want %q", buf[:n], payload)
	}
	if from.Port != replyPort {
		t.Fatalf("reply came from source port %d, want %d (server did not reply from the origdst port)",
			from.Port, replyPort)
	}
}

// TestReplyFromOrigPort_FallsBackToMain guards the "mismatch beats silence"
// rule: with no original port available (origPort == 0) the reply must still
// go out through the main listening socket.
func TestReplyFromOrigPort_FallsBackToMain(t *testing.T) {
	ports := freeUDPPorts(t, 1)
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: ports[0]})
	if err != nil {
		t.Fatalf("client socket: %v", err)
	}
	defer client.Close()

	srv, err := NewUDPCServer(ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TargetAddr: "udp://127.0.0.1:1",
		Magic:      UDPC_MAGIC_DEFAULT,
		LogLevel:   "error",
	})
	if err != nil {
		t.Fatalf("NewUDPCServer: %v", err)
	}
	defer srv.Close()

	payload := []byte("fallback")
	srv.replyFromOrigPort(0, client.LocalAddr(), payload) // origPort 0 -> main socket

	buf := make([]byte, 64)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, from, err := client.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("client got %q, want %q", buf[:n], payload)
	}
	if from.Port != srv.bindPort {
		t.Fatalf("fallback reply came from port %d, want main %d", from.Port, srv.bindPort)
	}
}

// TestSendToSession_RepliesFromLastPath covers the case where a server-
// initiated send must leave from the port of the path the session was last
// seen on (the multi-path rule that lets a CGNAT accept the reply).
func TestSendToSession_RepliesFromLastPath(t *testing.T) {
	ports := freeUDPPorts(t, 2)
	pathPort := ports[0]
	clientPort := ports[1]

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: clientPort})
	if err != nil {
		t.Fatalf("client socket: %v", err)
	}
	defer client.Close()

	srv, err := NewUDPCServer(ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TargetAddr: "udp://127.0.0.1:1",
		Magic:      UDPC_MAGIC_DEFAULT,
		LogLevel:   "error",
	})
	if err != nil {
		t.Fatalf("NewUDPCServer: %v", err)
	}
	defer srv.Close()

	sess := &ServerSession{
		server:       srv,
		sessionID:    1,
		lastOrigPort: int32(pathPort),
		pathAddrs:    map[int]net.Addr{pathPort: client.LocalAddr()},
	}
	sess.sendToSession([]byte("via-path"))

	buf := make([]byte, 64)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, from, err := client.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(buf[:n]) != "via-path" {
		t.Fatalf("client got %q, want %q", buf[:n], "via-path")
	}
	if from.Port != pathPort {
		t.Fatalf("reply came from port %d, want %d (multi-path reply used the wrong port)",
			from.Port, pathPort)
	}
}

// TestMultipathSession_RoutesReplyPerPath proves the core multi-path rule:
// a server-initiated frame leaves from the port of the path the session was
// most recently seen on, not a fixed primary. With N distinct
// (client-port, server-port) tuples this is what lets every path traverse a
// CGNAT — each reply's source port matches the port the client contacted.
func TestMultipathSession_RoutesReplyPerPath(t *testing.T) {
	ports := freeUDPPorts(t, 2)
	p1, p2 := ports[0], ports[1]

	client1, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("client1 socket: %v", err)
	}
	defer client1.Close()
	client2, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("client2 socket: %v", err)
	}
	defer client2.Close()

	srv, err := NewUDPCServer(ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TargetAddr: "udp://127.0.0.1:1",
		Magic:      UDPC_MAGIC_DEFAULT,
		LogLevel:   "error",
	})
	if err != nil {
		t.Fatalf("NewUDPCServer: %v", err)
	}
	defer srv.Close()

	sess := &ServerSession{
		server:       srv,
		sessionID:    1,
		lastOrigPort: int32(p1),
		pathAddrs:    map[int]net.Addr{p1: client1.LocalAddr(), p2: client2.LocalAddr()},
	}

	// Reply while the active path is p1: must leave from p1 and reach client1.
	sess.sendToSession([]byte("via-p1"))
	buf := make([]byte, 64)
	_ = client1.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, from, err := client1.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("client1 read: %v", err)
	}
	if string(buf[:n]) != "via-p1" {
		t.Fatalf("client1 got %q, want %q", buf[:n], "via-p1")
	}
	if from.Port != p1 {
		t.Fatalf("reply to client1 came from port %d, want %d", from.Port, p1)
	}

	// Switch the active path to p2 and reply again: must leave from p2.
	sess.setPath(p2, client2.LocalAddr())
	sess.sendToSession([]byte("via-p2"))
	_ = client2.SetReadDeadline(time.Now().Add(2 * time.Second))
	n2, from2, err := client2.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("client2 read: %v", err)
	}
	if string(buf[:n2]) != "via-p2" {
		t.Fatalf("client2 got %q, want %q", buf[:n2], "via-p2")
	}
	if from2.Port != p2 {
		t.Fatalf("reply to client2 came from port %d, want %d (server did not switch reply path)",
			from2.Port, p2)
	}
}

func TestCmdOfEncoded(t *testing.T) {
	frame := &UDPCFrame{
		Magic: UDPC_MAGIC_DEFAULT,
		Cmd:   CMD_DATA,
		Seq:   7,
	}
	if got := cmdOfEncoded(frame.Encode()); got != CMD_DATA {
		t.Fatalf("cmdOfEncoded = 0x%02X, want 0x%02X", got, CMD_DATA)
	}
	if got := cmdOfEncoded(nil); got != 0 {
		t.Fatalf("cmdOfEncoded(nil) = 0x%02X, want 0", got)
	}
	if got := cmdOfEncoded([]byte{1, 2, 3}); got != 0 {
		t.Fatalf("cmdOfEncoded(short) = 0x%02X, want 0", got)
	}
}
