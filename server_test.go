package main

import (
	"bytes"
	"encoding/hex"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testRig wires a real UDPCServer (never Started) to a fake client (a local
// UDP socket that receives the server's frames) and a fake target (net.Pipe).
type testRig struct {
	t          *testing.T
	server     *UDPCServer
	sess       *ServerSession
	client     *net.UDPConn
	clientAddr *net.UDPAddr
	target     net.Conn

	targetMu sync.Mutex
	targetBu bytes.Buffer

	// Client-side mirrors of the session cipher pair (non-nil when noise is
	// on). NoiseCipherState is stateless since P0-2 (nonce = Seq), so the
	// session and the test client safely share the same key material via
	// separate state objects.
	clientSend *NoiseCipherState // encrypts what the session's RecvCipher opens
	clientRecv *NoiseCipherState // opens what the session's SendCipher seals
}

func newTestRig(t *testing.T, withNoise bool) *testRig {
	t.Helper()

	cfg := ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TargetAddr: "tcp://127.0.0.1:1", // never dialed in unit tests
		Passwords:  []string{"psk"},
		LogLevel:   "error",
	}

	var serverSession, clientSession *NoiseSession
	if withNoise {
		// Run a real Noise_NK handshake so the rig exercises the same key
		// material the server would derive in handleHandshake.
		kp, err := GenerateNoiseKeyPair()
		if err != nil {
			t.Fatalf("keypair: %v", err)
		}
		cfg.PrivateKey = hex.EncodeToString(kp.PrivateKey[:])

		clientNK, err := NewClientNK(kp.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		msg1, err := clientNK.Message1()
		if err != nil {
			t.Fatal(err)
		}
		session, msg2, err := NewServerNoiseSession(kp.PrivateKey, msg1)
		if err != nil {
			t.Fatal(err)
		}
		serverSession = session
		clientSession, err = clientNK.Finish(msg2)
		if err != nil {
			t.Fatal(err)
		}
	}

	srv, err := NewUDPCServer(cfg)
	if err != nil {
		t.Fatalf("NewUDPCServer: %v", err)
	}

	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	clientAddr := client.LocalAddr().(*net.UDPAddr)

	targetSrv, targetCli := net.Pipe()

	rig := &testRig{
		t:          t,
		server:     srv,
		client:     client,
		clientAddr: clientAddr,
		target:     targetSrv,
	}
	if withNoise {
		rig.clientSend = clientSession.SendCipher
		rig.clientRecv = clientSession.RecvCipher
	}

	sess := &ServerSession{
		server:        srv,
		sessionID:     0x11223344,
		raddr:         clientAddr,
		targetNetwork: "tcp",
		targetAddr:    "127.0.0.1:1",
		tcpConn:       targetCli,
		sendSeq:       1,
		recvSeq:       1,
		recvQueue:     make(map[uint32][]byte),
		unacked:       make(map[uint32]*unackedPkt),
		lastActive:    time.Now(),
		closeChan:     make(chan struct{}),
		rttEst:        newRTTEstimator(200*time.Millisecond, 200*time.Millisecond, 10*time.Second),
	}
	sess.unackedCond = sync.NewCond(&sess.unackedMu)
	sess.noiseSession = serverSession // nil unless withNoise
	rig.sess = sess

	// Drain the fake target so pipe writes never block.
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := targetSrv.Read(buf)
			if n > 0 {
				rig.targetMu.Lock()
				rig.targetBu.Write(buf[:n])
				rig.targetMu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()

	t.Cleanup(func() {
		client.Close()
		targetCli.Close()
		targetSrv.Close()
		srv.Close()
	})
	return rig
}

func (r *testRig) makeDataFrame(seq uint32, payload []byte, encrypt bool) *UDPCFrame {
	data := payload
	if encrypt {
		data = r.clientSend.Encrypt(seq, payload)
	}
	return &UDPCFrame{
		Magic:     r.server.cfg.Magic,
		Version:   UDPC_VERSION,
		Cmd:       CMD_DATA,
		SessionID: r.sess.sessionID,
		Seq:       seq,
		Data:      data,
	}
}

func (r *testRig) recvFrame(timeout time.Duration) *UDPCFrame {
	r.t.Helper()
	r.client.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 2048)
	n, _, err := r.client.ReadFromUDP(buf)
	if err != nil {
		r.t.Fatalf("recvFrame: %v", err)
	}
	f, err := DecodeUDPCFrame(buf[:n], r.server.cfg.Magic)
	if err != nil {
		r.t.Fatalf("recvFrame decode: %v", err)
	}
	return f
}

func (r *testRig) expectNoFrame(timeout time.Duration) {
	r.t.Helper()
	r.client.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 2048)
	if _, _, err := r.client.ReadFromUDP(buf); err == nil {
		r.t.Fatalf("expected no frame, but one arrived")
	}
}

func (r *testRig) targetBytes() []byte {
	r.targetMu.Lock()
	defer r.targetMu.Unlock()
	out := make([]byte, r.targetBu.Len())
	copy(out, r.targetBu.Bytes())
	return out
}

func (r *testRig) waitForTargetBytes(n int, timeout time.Duration) []byte {
	r.t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if b := r.targetBytes(); len(b) >= n {
			return b[:n]
		}
		if time.Now().After(deadline) {
			r.t.Fatalf("timed out waiting for %d target bytes (have %d)", n, len(r.targetBytes()))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// --- handleData behaviour ---------------------------------------------------

func TestHandleDataInOrderAndCumulativeAck(t *testing.T) {
	rig := newTestRig(t, false)

	rig.sess.handleData(rig.makeDataFrame(1, []byte("AAAA"), false), rig.clientAddr)
	if got := rig.waitForTargetBytes(4, time.Second); string(got) != "AAAA" {
		t.Fatalf("target got %q", got)
	}
	ack := rig.recvFrame(time.Second)
	if ack.Cmd != CMD_ACK || ack.Ack != 1 {
		t.Fatalf("want ACK(1), got cmd=%d ack=%d", ack.Cmd, ack.Ack)
	}

	rig.sess.handleData(rig.makeDataFrame(2, []byte("BB"), false), rig.clientAddr)
	if got := rig.waitForTargetBytes(6, time.Second); string(got) != "AAAABB" {
		t.Fatalf("target got %q", got)
	}
	ack = rig.recvFrame(time.Second)
	if ack.Ack != 2 {
		t.Fatalf("want cumulative ACK(2), got %d", ack.Ack)
	}
}

// P0-1 integration: only a DATA frame that is actually delivered may move the
// session to a new IP.
func TestMigrationViaAuthenticatedDataOnly(t *testing.T) {
	rig := newTestRig(t, true)
	evil := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 9999}

	// A garbage "DATA" frame from the attacker must neither deliver nor migrate.
	bad := rig.makeDataFrame(1, []byte("AAAA"), false) // sealed with the wrong key
	rig.sess.handleData(bad, evil)
	if rig.sess.getRemoteAddr().String() != rig.clientAddr.String() {
		t.Fatal("unauthenticated (undecryptable) frame must not migrate the session")
	}
	rig.expectNoFrame(150 * time.Millisecond)

	// A frame that opens cleanly (seq-derived nonce) may migrate.
	good := rig.makeDataFrame(1, []byte("AAAA"), true)
	rig.sess.handleData(good, evil)
	rig.waitForTargetBytes(4, time.Second)
	if rig.sess.getRemoteAddr().String() != evil.String() {
		t.Fatalf("authenticated DATA must migrate the session, raddr=%s", rig.sess.getRemoteAddr())
	}
}

// updateRemoteAddr policy unit tests (see P0-1).
func TestUpdateRemoteAddrPolicy(t *testing.T) {
	rig := newTestRig(t, false)
	sess := rig.sess

	// Same IP, new port: always allowed (NAT rebinding).
	portBump := &net.UDPAddr{IP: rig.clientAddr.IP, Port: rig.clientAddr.Port + 1}
	sess.updateRemoteAddr(portBump, false)
	if sess.getRemoteAddr().String() != portBump.String() {
		t.Fatal("port-only change must be accepted even without authentication")
	}

	// Different IP without authentication: rejected.
	evil := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 1}
	sess.updateRemoteAddr(evil, false)
	if sess.getRemoteAddr().String() != portBump.String() {
		t.Fatal("unauthenticated IP change must be rejected")
	}

	// Different IP with authentication: accepted.
	sess.updateRemoteAddr(evil, true)
	if sess.getRemoteAddr().String() != evil.String() {
		t.Fatal("authenticated IP change must be accepted")
	}
}

// The P0-2 scenario end-to-end through handleData: seq 2 arrives before seq 1
// (buffered), then seq 1 opens with ITS nonce and the queued seq 2 opens with
// ITS nonce. With the old counter nonce this desynced and bricked the session.
func TestHandleDataNoiseOutOfOrder(t *testing.T) {
	rig := newTestRig(t, true)

	// Client encrypts 1 and 2 up front (its encryption order), but sends 2 first.
	ct1 := rig.clientSend.Encrypt(1, []byte("first"))
	ct2 := rig.clientSend.Encrypt(2, []byte("second"))

	rig.sess.handleData(&UDPCFrame{Magic: rig.server.cfg.Magic, Version: UDPC_VERSION,
		Cmd: CMD_DATA, SessionID: rig.sess.sessionID, Seq: 2, Data: ct2}, rig.clientAddr)
	rig.expectNoFrame(150 * time.Millisecond) // buffered, deliberately un-ACKed

	rig.sess.handleData(&UDPCFrame{Magic: rig.server.cfg.Magic, Version: UDPC_VERSION,
		Cmd: CMD_DATA, SessionID: rig.sess.sessionID, Seq: 1, Data: ct1}, rig.clientAddr)

	if got := rig.waitForTargetBytes(11, time.Second); string(got) != "firstsecond" {
		t.Fatalf("target got %q", got)
	}
	ack := rig.recvFrame(time.Second)
	if ack.Ack != 2 {
		t.Fatalf("want cumulative ACK(2), got %d", ack.Ack)
	}
}

// A corrupt (undecryptable) in-order frame must stall the stream exactly at
// that frame — no target write, no ACK, recvSeq untouched — and a clean
// retransmission with the same seq must then deliver it (self-heal).
func TestHandleDataDecryptFailureStallsThenHeals(t *testing.T) {
	rig := newTestRig(t, true)

	corrupt := rig.makeDataFrame(1, []byte("AAAA"), true)
	corrupt.Data[len(corrupt.Data)-1] ^= 0xFF
	rig.sess.handleData(corrupt, rig.clientAddr)
	if n := len(rig.targetBytes()); n != 0 {
		t.Fatalf("corrupt frame must not reach the target (got %d bytes)", n)
	}
	rig.expectNoFrame(150 * time.Millisecond)
	if got := atomic.LoadUint32(&rig.sess.recvSeq); got != 1 {
		t.Fatalf("recvSeq must stay 1, got %d", got)
	}

	rig.sess.handleData(rig.makeDataFrame(1, []byte("AAAA"), true), rig.clientAddr)
	rig.waitForTargetBytes(4, time.Second)
	ack := rig.recvFrame(time.Second)
	if ack.Ack != 1 {
		t.Fatalf("want ACK(1) after heal, got %d", ack.Ack)
	}
}

// A frame dropped because the reorder queue was full must remain
// retransmittable (the replay filter must not dead-lock the session).
func TestHandleDataQueueFullAllowsRetransmission(t *testing.T) {
	rig := newTestRig(t, false)
	rig.server.maxRecvQueue = 1

	// Buffer seq 2 (queue now full), then seq 3 must be dropped-not-buffered.
	rig.sess.handleData(rig.makeDataFrame(2, []byte("22"), false), rig.clientAddr)
	rig.sess.handleData(rig.makeDataFrame(3, []byte("33"), false), rig.clientAddr)
	if _, ok := rig.sess.recvQueue[3]; ok {
		t.Fatal("seq 3 should have been dropped (queue full)")
	}

	// Deliver seq 1 → drains 2 only; 3 is NOT delivered.
	rig.sess.handleData(rig.makeDataFrame(1, []byte("11"), false), rig.clientAddr)
	if got := rig.waitForTargetBytes(4, time.Second); string(got) != "1122" {
		t.Fatalf("target got %q", got)
	}
	rig.recvFrame(time.Second) // ACK(2)

	// Retransmitted seq 3 is now the expected frame and must deliver.
	rig.sess.handleData(rig.makeDataFrame(3, []byte("33"), false), rig.clientAddr)
	got := rig.waitForTargetBytes(6, time.Second)
	if string(got[len(got)-2:]) != "33" {
		t.Fatalf("retransmitted seq 3 not delivered, target tail %q", got)
	}
}

// --- send window ------------------------------------------------------------

func TestSendWindowBackpressure(t *testing.T) {
	rig := newTestRig(t, false)
	rig.server.sendWindow = 2

	// Drain the DATA frames the server emits towards the client.
	done := make(chan struct{})
	go func() {
		for i := 0; i < 2; i++ {
			rig.recvFrame(time.Second)
		}
		close(done)
	}()

	if err := rig.sess.sendData([]byte("A")); err != nil {
		t.Fatalf("sendData A: %v", err)
	}
	if err := rig.sess.sendData([]byte("B")); err != nil {
		t.Fatalf("sendData B: %v", err)
	}
	<-done

	blocked := make(chan error, 1)
	go func() { blocked <- rig.sess.sendData([]byte("C")) }()

	time.Sleep(150 * time.Millisecond)
	select {
	case err := <-blocked:
		t.Fatalf("sendData should be blocked by the window, returned %v", err)
	default:
	}
	if n := len(rig.sess.unacked); n != 2 {
		t.Fatalf("unacked=%d, want 2", n)
	}

	rig.sess.handleAck(1) // frees one slot
	select {
	case err := <-blocked:
		if err != nil {
			t.Fatalf("sendData C failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("sendData C still blocked after ACK")
	}
	if n := len(rig.sess.unacked); n != 2 {
		t.Fatalf("unacked after ACK+send = %d, want 2 (frames 2 and 3)", n)
	}
}

func TestSendWindowCloseUnblocks(t *testing.T) {
	rig := newTestRig(t, false)
	rig.server.sendWindow = 1

	go rig.recvFrame(time.Second) // swallow the first DATA frame
	if err := rig.sess.sendData([]byte("A")); err != nil {
		t.Fatalf("sendData A: %v", err)
	}

	blocked := make(chan error, 1)
	go func() { blocked <- rig.sess.sendData([]byte("B")) }()
	time.Sleep(100 * time.Millisecond)

	rig.sess.Close()
	select {
	case err := <-blocked:
		if err == nil || !strings.Contains(err.Error(), "closed") {
			t.Fatalf("expected session-closed error, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock the parked sender")
	}
}
