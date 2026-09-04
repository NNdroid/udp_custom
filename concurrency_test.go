package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These tests exercise the real 2-clients : 1-server topology: ONE UDPCServer
// (single UDP read loop, single target address) serving two independent clients
// at the same time. They cover what unit tests cannot:
//
//   - session isolation: sessions are keyed by SessionID, so two clients
//     sharing one target and one read loop must never see each other's data;
//   - concurrent handshakes (the per-IP limiter, the nonce cache, the SID
//     allocator and the sessions map are all shared state);
//   - concurrent data paths (one goroutine dispatches to both sessions);
//   - no head-of-line blocking: a slow target connection for one session must
//     not stall the other (handleData writes to the target outside recvMu).

// --- helpers ----------------------------------------------------------------

// echoTarget is a TCP echo server whose FIRST accepted connection is optionally
// slowed down, so we can prove that one stalled session does not block its peer.
type echoTarget struct {
	ln       net.Listener
	delay    time.Duration
	slowOnce sync.Once
	stopped  chan struct{}
	wg       sync.WaitGroup
}

func newEchoTarget(t *testing.T, delay time.Duration) *echoTarget {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	e := &echoTarget{ln: ln, delay: delay, stopped: make(chan struct{})}
	e.wg.Add(1)
	go e.serve()
	t.Cleanup(func() {
		close(e.stopped)
		ln.Close()
		e.wg.Wait()
	})
	return e
}

func (e *echoTarget) addr() string { return e.ln.Addr().String() }

func (e *echoTarget) serve() {
	defer e.wg.Done()
	isFirst := true
	for {
		c, err := e.ln.Accept()
		if err != nil {
			return
		}
		slow := isFirst
		isFirst = false
		e.wg.Add(1)
		go func(conn net.Conn, slow bool) {
			defer e.wg.Done()
			defer conn.Close()
			buf := make([]byte, 4096)
			for {
				n, err := conn.Read(buf)
				if n > 0 {
					if slow && e.delay > 0 {
						select {
						case <-time.After(e.delay):
						case <-e.stopped:
							return
						}
					}
					if _, werr := conn.Write(buf[:n]); werr != nil {
						return
					}
				}
				if err != nil {
					return
				}
			}
		}(c, slow)
	}
}

// fakeClient is a full udp_custom client: its own UDP socket, its own handshake,
// optional Noise session.
type fakeClient struct {
	t      *testing.T
	name   string
	conn   *net.UDPConn
	server *net.UDPAddr
	sid    uint32
	psk    string
	noise  *NoiseSession
	seq    uint32
}

func newFakeClient(t *testing.T, name, serverUDP, psk string, serverStatic *[32]byte) *fakeClient {
	t.Helper()
	saddr, err := net.ResolveUDPAddr("udp", serverUDP)
	if err != nil {
		t.Fatalf("%s resolve: %v", name, err)
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("%s listen: %v", name, err)
	}
	c := &fakeClient{t: t, name: name, conn: conn, server: saddr, psk: psk}
	if serverStatic != nil {
		clientNK, err := NewClientNK(*serverStatic)
		if err != nil {
			t.Fatalf("%s NewClientNK: %v", name, err)
		}
		msg1, err := clientNK.Message1()
		if err != nil {
			t.Fatalf("%s Message1: %v", name, err)
		}
		c.handshakeWith(msg1, clientNK)
		return c
	}
	c.handshakeWith(nil, nil)
	return c
}

// handshakeWith performs the SYN/ACK exchange. noiseMsg1 == nil means a
// PSK-only handshake (server has no privkey).
func (c *fakeClient) handshakeWith(noiseMsg1 []byte, nk *ClientNK) {
	c.t.Helper()
	payload := make([]byte, 56+len(noiseMsg1))
	var nonce [16]byte
	rand.Read(nonce[:])
	now := time.Now().Unix()
	copy(payload[0:16], nonce[:])
	binary.BigEndian.PutUint64(payload[16:24], uint64(now))
	copy(payload[24:56], ComputeAuthHMAC(nonce[:], c.psk, now))
	copy(payload[56:], noiseMsg1)

	c.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.conn.WriteToUDP((&UDPCFrame{
		Magic: UDPC_MAGIC_DEFAULT, Version: UDPC_VERSION,
		Cmd: CMD_HANDSHAKE_SYN, Data: payload,
	}).Encode(), c.server); err != nil {
		c.t.Fatalf("%s write syn: %v", c.name, err)
	}

	buf := make([]byte, 2048)
	n, _, err := c.conn.ReadFromUDP(buf)
	if err != nil {
		c.t.Fatalf("%s read ack: %v", c.name, err)
	}
	ack, err := DecodeUDPCFrame(buf[:n], UDPC_MAGIC_DEFAULT)
	if err != nil {
		c.t.Fatalf("%s decode ack: %v", c.name, err)
	}
	if ack.Cmd != CMD_HANDSHAKE_ACK {
		c.t.Fatalf("%s expected ACK, got cmd=%d", c.name, ack.Cmd)
	}
	if ack.SessionID == 0 {
		c.t.Fatalf("%s server returned a zero SessionID", c.name)
	}
	c.sid = ack.SessionID
	if nk != nil {
		sess, err := nk.Finish(ack.Data)
		if err != nil {
			c.t.Fatalf("%s Noise finish: %v", c.name, err)
		}
		c.noise = sess
	}
}

func (c *fakeClient) send(payload []byte) uint32 {
	c.t.Helper()
	c.seq++
	seq := c.seq
	data := payload
	if c.noise != nil {
		data = c.noise.SendCipher.Encrypt(seq, payload)
	}
	if _, err := c.conn.WriteToUDP((&UDPCFrame{
		Magic: UDPC_MAGIC_DEFAULT, Version: UDPC_VERSION, Cmd: CMD_DATA,
		SessionID: c.sid, Seq: seq, Data: data,
	}).Encode(), c.server); err != nil {
		c.t.Fatalf("%s write data: %v", c.name, err)
	}
	return seq
}

// readData blocks until the next DATA frame (ACKs are skipped) and returns its
// decrypted payload.
func (c *fakeClient) readData(timeout time.Duration) (uint32, []byte) {
	c.t.Helper()
	c.conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 2048)
	for {
		n, _, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			c.t.Fatalf("%s read: %v", c.name, err)
		}
		f, err := DecodeUDPCFrame(buf[:n], UDPC_MAGIC_DEFAULT)
		if err != nil {
			c.t.Fatalf("%s decode: %v", c.name, err)
		}
		if f.Cmd != CMD_DATA {
			continue // ACK
		}
		payload := f.Data
		if c.noise != nil {
			payload, err = c.noise.RecvCipher.Decrypt(f.Seq, f.Data)
			if err != nil {
				c.t.Fatalf("%s decrypt seq=%d: %v", c.name, f.Seq, err)
			}
		}
		return f.Seq, payload
	}
}

func (c *fakeClient) close() { c.conn.Close() }

func payloadFor(name string, i int) []byte {
	return []byte(fmt.Sprintf("%s-%04d-%s", name, i, strings.Repeat("x", 64)))
}

// echoStream sends `frames` payloads and reassembles the echoed BYTE STREAM.
//
// The target is a TCP stream service, so the tunnel deliberately does NOT
// preserve datagram boundaries: several requests written close together come
// back coalesced in one DATA frame. The only contracts that matter are that the
// byte stream is identical and in order, and that no other session's bytes ever
// appear. Clients that need message boundaries must frame their own payloads.
func echoStream(c *fakeClient, frames int, timeout time.Duration) ([]byte, time.Duration, error) {
	want := make([]byte, 0, frames*80)
	start := time.Now()
	for i := 1; i <= frames; i++ {
		p := payloadFor(c.name, i)
		want = append(want, p...)
		c.send(p)
	}
	got := make([]byte, 0, len(want))
	for len(got) < len(want) {
		_, payload := c.readData(timeout)
		got = append(got, payload...)
	}
	return got, time.Since(start), nil
}

// --- tests ------------------------------------------------------------------

// Two clients (different PSKs from the server's allowed list) hammer one server
// at the same time. Each must receive exactly its own echoes, in its own
// session, with no cross-talk.
func TestTwoClientsOneServer_ConcurrentEcho(t *testing.T) {
	target := newEchoTarget(t, 0)
	serverUDP := "127.0.0.1:0"

	srv, err := NewUDPCServer(ServerConfig{
		ListenAddr: serverUDP,
		TargetAddr: target.addr(),
		Passwords:  []string{"psk-alpha", "psk-beta"},
		LogLevel:   "error",
	})
	if err != nil {
		t.Fatalf("NewUDPCServer: %v", err)
	}
	serverUDP = srv.conn.LocalAddr().String()
	go srv.Start()
	defer srv.Close()

	a := newFakeClient(t, "A", serverUDP, "psk-alpha", nil)
	defer a.close()
	b := newFakeClient(t, "B", serverUDP, "psk-beta", nil)
	defer b.close()

	if a.sid == b.sid {
		t.Fatalf("two concurrent clients got the same SessionID 0x%08X", a.sid)
	}
	if n := sessionCount(srv); n != 2 {
		t.Fatalf("server holds %d sessions, want 2", n)
	}

	const frames = 50
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	runClient := func(c *fakeClient, peer string) {
		defer wg.Done()
		want := make([]byte, 0, frames*80)
		for i := 1; i <= frames; i++ {
			want = append(want, payloadFor(c.name, i)...)
		}
		got, _, err := echoStream(c, frames, 5*time.Second)
		if err != nil {
			errs <- err
			return
		}
		if !bytes.Equal(got, want) {
			errs <- fmt.Errorf("%s stream mismatch: got %d bytes, want %d bytes", c.name, len(got), len(want))
			return
		}
		// Cross-talk guard: not one byte of the peer's stream may show up.
		if bytes.Contains(got, []byte(peer+"-")) {
			errs <- fmt.Errorf("%s received peer session data", c.name)
			return
		}
		errs <- nil
	}
	wg.Add(2)
	go runClient(a, "B")
	go runClient(b, "A")
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

// Same topology with Noise_NK enabled: both clients derive independent
// transport keys from the same server static key.
func TestTwoClientsOneServer_ConcurrentNoise(t *testing.T) {
	target := newEchoTarget(t, 0)
	kp, err := GenerateNoiseKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	serverUDP := "127.0.0.1:0"
	srv, err := NewUDPCServer(ServerConfig{
		ListenAddr: serverUDP,
		TargetAddr: target.addr(),
		Passwords:  []string{"psk-shared"},
		PrivateKey: hexOf(kp.PrivateKey),
		LogLevel:   "error",
	})
	if err != nil {
		t.Fatalf("NewUDPCServer: %v", err)
	}
	serverUDP = srv.conn.LocalAddr().String()
	go srv.Start()
	defer srv.Close()

	a := newFakeClient(t, "A", serverUDP, "psk-shared", &kp.PublicKey)
	defer a.close()
	b := newFakeClient(t, "B", serverUDP, "psk-shared", &kp.PublicKey)
	defer b.close()

	if a.noise == nil || b.noise == nil {
		t.Fatal("Noise session not established")
	}
	if a.noise.HandshakeHash == b.noise.HandshakeHash {
		t.Fatal("two sessions share a channel binding value (keys not per-handshake)")
	}

	const frames = 25
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	run := func(c *fakeClient, peer string) {
		defer wg.Done()
		want := make([]byte, 0, frames*80)
		for i := 1; i <= frames; i++ {
			want = append(want, payloadFor(c.name, i)...)
		}
		got, _, err := echoStream(c, frames, 5*time.Second)
		if err != nil {
			errs <- err
			return
		}
		if !bytes.Equal(got, want) {
			errs <- fmt.Errorf("%s stream mismatch: got %d bytes, want %d bytes", c.name, len(got), len(want))
			return
		}
		if bytes.Contains(got, []byte(peer+"-")) {
			errs <- fmt.Errorf("%s received peer session data", c.name)
			return
		}
		errs <- nil
	}
	wg.Add(2)
	go run(a, "B")
	go run(b, "A")
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

// Handshakes from two clients racing at the same instant: the SYN limiter,
// the handshake semaphore, the nonce cache and the SessionID allocator are all
// shared state and must stay consistent.
func TestTwoClientsOneServer_RacingHandshakes(t *testing.T) {
	target := newEchoTarget(t, 0)
	serverUDP := "127.0.0.1:0"
	srv, err := NewUDPCServer(ServerConfig{
		ListenAddr: serverUDP,
		TargetAddr: target.addr(),
		Passwords:  []string{"psk"},
		LogLevel:   "error",
	})
	if err != nil {
		t.Fatalf("NewUDPCServer: %v", err)
	}
	serverUDP = srv.conn.LocalAddr().String()
	go srv.Start()
	defer srv.Close()

	sids := make([]uint32, 2)
	errs := make(chan error, 2)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			name := fmt.Sprintf("C%d", idx)
			c := newFakeClient(t, name, serverUDP, "psk", nil)
			defer c.close()
			sids[idx] = c.sid
			// Prove the session works end to end.
			payload := payloadFor(name, 1)
			c.send(payload)
			_, got := c.readData(3 * time.Second)
			if !bytes.Equal(got, payload) {
				errs <- fmt.Errorf("%s echo mismatch: got %q", name, got)
				return
			}
			errs <- nil
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if sids[0] == 0 || sids[1] == 0 {
		t.Fatalf("a client got a zero SessionID: %v", sids)
	}
	if sids[0] == sids[1] {
		t.Fatalf("racing handshakes collided on SessionID 0x%08X", sids[0])
	}
}

// A slow target connection for one session must NOT stall the other session:
// handleData writes to the target outside recvMu, and each session owns its own
// target connection, so the peer keeps flowing.
func TestTwoClientsOneServer_SlowPeerDoesNotBlock(t *testing.T) {
	const (
		slowDelay = 150 * time.Millisecond
		frames    = 4
	)
	target := newEchoTarget(t, slowDelay)
	serverUDP := "127.0.0.1:0"
	srv, err := NewUDPCServer(ServerConfig{
		ListenAddr: serverUDP,
		TargetAddr: target.addr(),
		Passwords:  []string{"psk"},
		LogLevel:   "error",
	})
	if err != nil {
		t.Fatalf("NewUDPCServer: %v", err)
	}
	serverUDP = srv.conn.LocalAddr().String()
	go srv.Start()
	defer srv.Close()

	// Client A handshakes first, so it owns the first (slow) target connection.
	a := newFakeClient(t, "A", serverUDP, "psk", nil)
	defer a.close()
	b := newFakeClient(t, "B", serverUDP, "psk", nil)
	defer b.close()

	type result struct {
		name string
		dur  time.Duration
		err  error
	}
	results := make(chan result, 2)
	run := func(c *fakeClient) {
		want := make([]byte, 0, frames*80)
		for i := 1; i <= frames; i++ {
			want = append(want, payloadFor(c.name, i)...)
		}
		got, dur, err := echoStream(c, frames, 20*time.Second)
		if err != nil {
			results <- result{c.name, dur, err}
			return
		}
		if !bytes.Equal(got, want) {
			results <- result{c.name, dur, fmt.Errorf("%s stream mismatch", c.name)}
			return
		}
		results <- result{c.name, dur, nil}
	}

	// Interleave: A handshaked first (so it owns the slow connection), then
	// both run their streams concurrently.
	go run(a)
	go run(b)

	var resA, resB result
	for i := 0; i < 2; i++ {
		r := <-results
		if r.err != nil {
			t.Fatal(r.err)
		}
		if r.name == "A" {
			resA = r
		} else {
			resB = r
		}
	}

	// The slow session must really be slow (otherwise the test proves nothing).
	if resA.dur < slowDelay*frames/2 {
		t.Fatalf("slow session A finished in %v — delay not applied, test invalid", resA.dur)
	}
	// ...and the fast session must not have waited for it. Head-of-line
	// blocking would cost B at least frames*slowDelay.
	if resB.dur > slowDelay*frames {
		t.Fatalf("session B took %v (>= %v): the slow peer is blocking the fast one",
			resB.dur, slowDelay*frames)
	}
}

// --- helpers ----------------------------------------------------------------

func sessionCount(srv *UDPCServer) int {
	n := 0
	srv.sessions.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}

func hexOf(k [32]byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 64)
	for i, b := range k {
		out[i*2] = digits[b>>4]
		out[i*2+1] = digits[b&0x0f]
	}
	return string(out)
}

// BenchmarkTwoClientsOneServer measures one server's aggregate throughput with
// two concurrent clients (the real deployment shape).
func BenchmarkTwoClientsOneServer(b *testing.B) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				io.Copy(conn, conn)
			}(c)
		}
	}()

	srv, err := NewUDPCServer(ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TargetAddr: echoLn.Addr().String(),
		Passwords:  []string{"psk"},
		LogLevel:   "error",
	})
	if err != nil {
		b.Fatal(err)
	}
	go srv.Start()
	defer srv.Close()

	// Minimal clients (no reconciliation with the testing.T helpers above).
	type client struct {
		conn *net.UDPConn
		sid  uint32
		seq  uint32
	}
	dials := make([]*client, 2)
	saddr := srv.conn.LocalAddr().(*net.UDPAddr)
	for i := range dials {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			b.Fatal(err)
		}
		defer conn.Close()
		payload := make([]byte, 56)
		var nonce [16]byte
		rand.Read(nonce[:])
		now := time.Now().Unix()
		copy(payload[0:16], nonce[:])
		binary.BigEndian.PutUint64(payload[16:24], uint64(now))
		copy(payload[24:56], ComputeAuthHMAC(nonce[:], "psk", now))
		conn.WriteToUDP((&UDPCFrame{Magic: UDPC_MAGIC_DEFAULT, Version: UDPC_VERSION,
			Cmd: CMD_HANDSHAKE_SYN, Data: payload}).Encode(), saddr)
		buf := make([]byte, 2048)
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			b.Fatalf("handshake: %v", err)
		}
		ack, err := DecodeUDPCFrame(buf[:n], UDPC_MAGIC_DEFAULT)
		if err != nil {
			b.Fatal(err)
		}
		dials[i] = &client{conn: conn, sid: ack.SessionID}
	}

	msg := make([]byte, 512)
	b.SetBytes(int64(len(msg)))
	b.ResetTimer()

	var wg sync.WaitGroup
	perClient := b.N / 2
	if perClient < 1 {
		perClient = 1
	}
	var failed int32
	for _, c := range dials {
		wg.Add(1)
		go func(c *client) {
			defer wg.Done()
			buf := make([]byte, 2048)
			for i := 0; i < perClient; i++ {
				c.seq++
				c.conn.WriteToUDP((&UDPCFrame{Magic: UDPC_MAGIC_DEFAULT, Version: UDPC_VERSION,
					Cmd: CMD_DATA, SessionID: c.sid, Seq: c.seq, Data: msg}).Encode(), saddr)
				for {
					c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
					n, _, err := c.conn.ReadFromUDP(buf)
					if err != nil {
						atomic.AddInt32(&failed, 1)
						return
					}
					f, err := DecodeUDPCFrame(buf[:n], UDPC_MAGIC_DEFAULT)
					if err != nil {
						continue
					}
					if f.Cmd == CMD_DATA {
						// Release the server's bounded send window; without this
						// benchmark eventually stalls after 256 responses and only
						// measures retransmission timeouts.
						ack := (&UDPCFrame{
							Magic: UDPC_MAGIC_DEFAULT, Version: UDPC_VERSION, Cmd: CMD_ACK,
							SessionID: c.sid, Ack: f.Seq,
						}).Encode()
						if _, err := c.conn.WriteToUDP(ack, saddr); err != nil {
							atomic.AddInt32(&failed, 1)
							return
						}
						break
					}
				}
			}
		}(c)
	}
	wg.Wait()
	if failed != 0 {
		b.Fatalf("%d client(s) hit an error", failed)
	}
}
