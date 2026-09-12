//go:build linux

package tunnel

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
)

// truncCaptureLogger records Warnf calls so tests can assert on the MSG_TRUNC
// diagnostic without pulling in the real logger implementation.
type truncCaptureLogger struct {
	mu    sync.Mutex
	warns []string
}

func (l *truncCaptureLogger) Debugf(string, ...any) {}
func (l *truncCaptureLogger) Infof(string, ...any)  {}
func (l *truncCaptureLogger) Errorf(string, ...any) {}
func (l *truncCaptureLogger) Warnf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.warns = append(l.warns, fmt.Sprintf(format, args...))
}

func (l *truncCaptureLogger) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.warns)
}

func (l *truncCaptureLogger) last() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.warns) == 0 {
		return ""
	}
	return l.warns[len(l.warns)-1]
}

// truncRig wires a packetReader on a loopback socket with a sending socket on
// the other end. The reader's receive buffers are UDPC_MAX_PKT (1450) bytes,
// so anything larger than oversized() is cut down by the kernel.
func truncRig(t *testing.T, log Logger) (*packetReader, *net.UDPConn) {
	t.Helper()
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	cli, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	t.Cleanup(func() { cli.Close() })
	return newPacketReader(srv, log), cli
}

func truncSend(t *testing.T, cli *net.UDPConn, r *packetReader, payload []byte) {
	t.Helper()
	srvAddr := r.conn.LocalAddr().(*net.UDPAddr)
	if _, err := cli.WriteToUDP(payload, srvAddr); err != nil {
		t.Fatalf("send: %v", err)
	}
}

func oversized() []byte { return make([]byte, UDPC_MAX_PKT+150) } // 1600 > 1450 buffer

// A datagram larger than the receive buffer must be dropped by the first-read
// path — the tail is gone, so authentication could only fail — and must raise
// exactly one WARN. The reader must stay usable afterwards.
func TestPacketReaderDropsTruncatedDatagram(t *testing.T) {
	log := &truncCaptureLogger{}
	r, cli := truncRig(t, log)

	truncSend(t, cli, r, oversized())
	pkts, err := r.next()
	if err != nil {
		t.Fatalf("next: %v", err)
	}
	if len(pkts) != 0 {
		t.Fatalf("got %d packets, want 0 (truncated datagram must be dropped)", len(pkts))
	}
	if log.count() != 1 {
		t.Fatalf("warn count = %d, want 1", log.count())
	}
	if !strings.Contains(log.last(), "truncated at 1450 bytes (buffer 1450)") {
		t.Fatalf("warn text = %q, want truncation sizes", log.last())
	}

	// The reader must remain fully functional after the drop.
	small := []byte("still-alive")
	truncSend(t, cli, r, small)
	pkts, err = r.next()
	if err != nil {
		t.Fatalf("next after truncation: %v", err)
	}
	if len(pkts) != 1 || string(pkts[0].data) != string(small) {
		t.Fatalf("got %d packets after truncation, want the intact payload", len(pkts))
	}
}

// The truncation warning is rate limited to one line per 5 seconds: a
// truncated datagram is unauthenticated, so any peer can trigger it and the
// log rate must not be attacker controlled.
func TestPacketReaderTruncationThrottled(t *testing.T) {
	log := &truncCaptureLogger{}
	r, cli := truncRig(t, log)

	for i := 0; i < 3; i++ {
		truncSend(t, cli, r, oversized())
		pkts, err := r.next()
		if err != nil {
			t.Fatalf("next #%d: %v", i, err)
		}
		if len(pkts) != 0 {
			t.Fatalf("next #%d: got %d packets, want 0", i, len(pkts))
		}
	}
	if log.count() != 1 {
		t.Fatalf("warn count = %d after 3 truncations, want 1 (throttled)", log.count())
	}
}

// A truncated datagram inside the burst-drain loop must be skipped while the
// slot is kept for the following datagram.
func TestPacketReaderDrainSkipsTruncated(t *testing.T) {
	log := &truncCaptureLogger{}
	r, cli := truncRig(t, log)

	good := []byte("drain-me")
	truncSend(t, cli, r, good)
	truncSend(t, cli, r, oversized())

	pkts, err := r.next()
	if err != nil {
		t.Fatalf("next: %v", err)
	}
	if len(pkts) != 1 || string(pkts[0].data) != string(good) {
		t.Fatalf("got %d packets, want exactly the intact one; first=%q", len(pkts), pkts[0].data)
	}
	if log.count() != 1 {
		t.Fatalf("warn count = %d, want 1 (drain-loop truncation)", log.count())
	}
}

// Every drained datagram must parse origdst from its OWN ancillary-data slot,
// not from slot 0 (regression: the drain loop previously re-parsed the stale
// r.oob[0] buffer, which reports the previous cycle's destination). Without
// DNAT every datagram's origdst equals the socket's own bound port, so that is
// the value asserted here; differing ports require real netfilter rules.
func TestPacketReaderDrainParsesOwnAncillarySlot(t *testing.T) {
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer srv.Close()

	// Not fatal if the kernel refuses: some sandboxed environments block it.
	if err := enableOrigDst(srv); err != nil {
		t.Skipf("IP_RECVORIGDSTADDR unavailable: %v", err)
	}

	r := newPacketReader(srv, nil)
	cli, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	defer cli.Close()

	// Queue 3 datagrams BEFORE the first read so the drain loop covers #2/#3.
	payload := []byte("slot-plumbing")
	for i := 0; i < 3; i++ {
		truncSend(t, cli, r, payload)
	}

	pkts, err := r.next()
	if err != nil {
		t.Fatalf("next: %v", err)
	}
	if len(pkts) != 3 {
		t.Fatalf("drained %d datagrams, want 3", len(pkts))
	}
	wantPort := srv.LocalAddr().(*net.UDPAddr).Port
	for i, p := range pkts {
		if string(p.data) != string(payload) {
			t.Fatalf("pkt #%d data = %q, want %q", i, p.data, payload)
		}
		if p.origPort != wantPort {
			t.Fatalf("pkt #%d origPort = %d, want %d (its own cmsg, not a stale slot)", i, p.origPort, wantPort)
		}
	}
}
