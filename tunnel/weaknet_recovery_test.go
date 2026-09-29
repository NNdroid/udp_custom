package tunnel

import (
	"bytes"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestSpreadDialerRepairsClosedSocketOnWrite(t *testing.T) {
	recv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("receiver listen: %v", err)
	}
	defer recv.Close()

	d, err := NewSpreadDialer(recv.LocalAddr().String(), 1, 1)
	if err != nil {
		t.Fatalf("NewSpreadDialer: %v", err)
	}
	defer d.Close()

	old := d.Conn(0)
	if old == nil {
		t.Fatal("dialer has no socket 0")
	}
	beforeGeneration := d.Generation()
	if err := old.Close(); err != nil {
		t.Fatalf("close old socket: %v", err)
	}

	payload := []byte("self-heal-after-write-failure")
	if err := d.Send(payload); err != nil {
		t.Fatalf("Send after socket failure: %v", err)
	}
	if got := d.Conn(0); got == nil || got == old {
		t.Fatalf("socket was not replaced: old=%p new=%p", old, got)
	}
	if got := d.Generation(); got <= beforeGeneration {
		t.Fatalf("generation did not advance: before=%d after=%d", beforeGeneration, got)
	}

	if err := recv.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 256)
	n, _, err := recv.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("receiver did not get retry: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("received %q, want %q", buf[:n], payload)
	}
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("reserve UDP port: %v", err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	if err := c.Close(); err != nil {
		t.Fatalf("release UDP port: %v", err)
	}
	return port
}

func TestSendSockPoolRepairsPoisonedReplySocket(t *testing.T) {
	recv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("receiver listen: %v", err)
	}
	defer recv.Close()

	pool := newSendSockPool(8, nil)
	defer pool.Close()
	port := freeUDPPort(t)
	pc, err := pool.Get(port)
	if err != nil {
		t.Fatalf("pool.Get(%d): %v", port, err)
	}
	if err := pc.conn.Close(); err != nil {
		t.Fatalf("poison cached socket: %v", err)
	}

	payload := []byte("reply-from-repaired-source-port")
	dst := recv.LocalAddr().(*net.UDPAddr).AddrPort()
	if _, err := pc.WriteToUDPAddrPort(payload, dst); err != nil {
		t.Fatalf("write through poisoned pooled socket: %v", err)
	}

	replacement, err := pool.Get(port)
	if err != nil {
		t.Fatalf("pool.Get replacement: %v", err)
	}
	if replacement == pc {
		t.Fatal("poisoned pooled socket remained cached")
	}
	if got := replacement.LocalAddr().(*net.UDPAddr).Port; got != port {
		t.Fatalf("replacement source port=%d, want %d", got, port)
	}

	if err := recv.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 256)
	n, from, err := recv.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("receiver did not get repaired write: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("received %q, want %q", buf[:n], payload)
	}
	if from.Port != port {
		t.Fatalf("reply source port=%d, want repaired port %d", from.Port, port)
	}
}

func TestMtuProbeCacheInvalidatesOnSocketGenerationChange(t *testing.T) {
	cache := &mtuProbeCache{}
	cache.storeFor(1000, 7)
	if got := cache.getFor(7); got != 1000 {
		t.Fatalf("same generation cache=%d, want 1000", got)
	}
	if got := cache.getFor(8); got != 0 {
		t.Fatalf("new generation reused stale cache=%d", got)
	}
}

func TestConservativeMtuFallback(t *testing.T) {
	for _, tc := range []struct {
		ceiling int
		want    int
	}{
		{1450, 1200},
		{1300, 1200},
		{1200, 1200},
		{1000, 1000},
		{548, 548},
	} {
		t.Run(fmt.Sprintf("ceiling_%d", tc.ceiling), func(t *testing.T) {
			if got := conservativeMtuFallback(tc.ceiling); got != tc.want {
				t.Fatalf("conservativeMtuFallback(%d)=%d, want %d", tc.ceiling, got, tc.want)
			}
		})
	}
}
