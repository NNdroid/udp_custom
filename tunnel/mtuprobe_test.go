package tunnel

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestValidSessionFrameShapeMtuCommands(t *testing.T) {
	base := UDPCFrame{SessionID: 1, PacketNo: 1}
	mid := make([]byte, 300)

	cases := []struct {
		name  string
		frame UDPCFrame
		want  bool
	}{
		{"probe at the smallest legal size", mtuFrame(base, CMD_MTU_PROBE, make([]byte, mtuProbeIDSize)), true},
		{"probe mid size", mtuFrame(base, CMD_MTU_PROBE, mid), true},
		{"probe at the largest legal size", mtuFrame(base, CMD_MTU_PROBE, make([]byte, mtuProbeMaxPayload)), true},
		{"probe below the minimum", mtuFrame(base, CMD_MTU_PROBE, make([]byte, mtuProbeIDSize-1)), false},
		{"probe above the ceiling", mtuFrame(base, CMD_MTU_PROBE, make([]byte, mtuProbeMaxPayload+1)), false},
		{"probe with a data sequence", mtuFrame(UDPCFrame{SessionID: 1, PacketNo: 1, Seq: 1}, CMD_MTU_PROBE, mid), false},
		{"reply echoes the probe", mtuFrame(base, CMD_MTU_PROBE_REPLY, mid), true},
		{"reply too short", mtuFrame(base, CMD_MTU_PROBE_REPLY, make([]byte, 4)), false},
		{"commit with a size", mtuFrame(base, CMD_MTU_COMMIT, make([]byte, mtuCommitSize)), true},
		{"commit wrong size", mtuFrame(base, CMD_MTU_COMMIT, make([]byte, 4)), false},
		{"commit empty", mtuFrame(base, CMD_MTU_COMMIT, nil), false},
	}
	for _, tc := range cases {
		if got := validSessionFrameShape(&tc.frame); got != tc.want {
			t.Errorf("%s: validSessionFrameShape = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func mtuFrame(base UDPCFrame, cmd uint8, payload []byte) UDPCFrame {
	base.Cmd = cmd
	base.Data = payload
	return base
}

func TestMtuLadderFor(t *testing.T) {
	cases := []struct {
		ceiling int
		want    []int
	}{
		{UDPC_MAX_PKT, []int{1450, 1392, 1200, 1000, 800, 548}},
		{1420, []int{1420, 1392, 1200, 1000, 800, 548}},
		{1392, []int{1392, 1200, 1000, 800, 548}},
		{1200, []int{1200, 1000, 800, 548}},
		{900, []int{900, 800, 548}},
		{548, []int{548}},
		{300, []int{300}},
	}
	for _, tc := range cases {
		got := mtuLadderFor(tc.ceiling)
		if len(got) != len(tc.want) {
			t.Fatalf("mtuLadderFor(%d) = %v, want %v", tc.ceiling, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("mtuLadderFor(%d) = %v, want %v", tc.ceiling, got, tc.want)
			}
		}
	}
}

// fakeProbeServer answers CMD_MTU_PROBE records up to a ceiling and records
// commits, exercising the client prober over a real loopback socket.
type fakeProbeServer struct {
	conn      *net.UDPConn
	keys      *FrameKeys   // SERVER-side ciphers: what a real server would seal with
	maxRecord atomic.Int32 // largest record size it will echo; 0 = never answer
	silence   atomic.Bool  // drop everything (the old-peer fallback contract)

	commitsMu sync.Mutex
	commits   []int

	sendPacket atomic.Uint64
}

func newFakeProbeServer(t *testing.T, keys *FrameKeys) *fakeProbeServer {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("fake probe server listen: %v", err)
	}
	f := &fakeProbeServer{conn: conn, keys: keys}
	go f.loop()
	t.Cleanup(func() { conn.Close() })
	return f
}

func (f *fakeProbeServer) addr() netip.AddrPort {
	return f.conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

func (f *fakeProbeServer) commitValues() []int {
	f.commitsMu.Lock()
	defer f.commitsMu.Unlock()
	return append([]int(nil), f.commits...)
}

func (f *fakeProbeServer) loop() {
	buf := make([]byte, UDPC_MAX_PKT)
	for {
		n, from, err := f.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		frame, err := DecodeUDPCFrame(buf[:n], UDPC_MAGIC_DEFAULT)
		if err != nil {
			continue
		}
		// Control records arrive ENCRYPTED: open with this side's Recv cipher
		// before looking at the payload, exactly like the real server does.
		plain, err := OpenFrameAEAD(frame, f.keys.Recv)
		if err != nil {
			continue
		}
		switch frame.Cmd {
		case CMD_MTU_COMMIT:
			if len(plain) == mtuCommitSize {
				f.commitsMu.Lock()
				f.commits = append(f.commits, int(binary.BigEndian.Uint16(plain)))
				f.commitsMu.Unlock()
			}
		case CMD_MTU_PROBE:
			if f.silence.Load() || len(plain)+UDPC_HDR_SIZE+UDPC_TRAILER_SIZE > int(f.maxRecord.Load()) {
				continue // no answer: the size under test does not fit the path
			}
			reply := &UDPCFrame{
				Magic: UDPC_MAGIC_DEFAULT, Version: UDPC_VERSION, Cmd: CMD_MTU_PROBE_REPLY,
				SessionID: frame.SessionID, Data: append([]byte(nil), plain...),
			}
			reply.PacketNo = f.sendPacket.Add(1)
			wire := SealFrameAEAD(reply, f.keys.Send, reply.Data)
			if _, err := f.conn.WriteToUDPAddrPort(wire, from); err != nil {
				return
			}
		}
	}
}

// proberKeyPair holds BOTH sides of one session's record ciphers, so the fake
// server seals exactly what the client's session can open (and vice versa).
type proberKeyPair struct {
	clientNonce, serverNonce [clientNonceSize]byte
	sid                      uint32
	client                   *FrameKeys
	server                   *FrameKeys
}

func newProberKeyPair(t *testing.T) *proberKeyPair {
	t.Helper()
	pk := &proberKeyPair{sid: 0x11223344}
	pk.clientNonce[0], pk.serverNonce[0] = 1, 2
	keys := DerivePSKSessionKeys("psk", pk.clientNonce, pk.serverNonce, pk.sid)
	var err error
	if pk.client, err = keys.ClientFrameCiphers(); err != nil {
		t.Fatalf("client frame ciphers: %v", err)
	}
	if pk.server, err = keys.ServerFrameCiphers(); err != nil {
		t.Fatalf("server frame ciphers: %v", err)
	}
	return pk
}

// newProberRig wires a real Client (dialing the fake server) to a hand-built
// session whose key material mirrors what a real handshake would produce.
func newProberRig(t *testing.T, fake *fakeProbeServer, pk *proberKeyPair) (*Client, *clientSession) {
	t.Helper()
	cli, err := NewClient(ClientConfig{
		ServerAddr: fake.addr().String(),
		Passwords:  []string{"psk"},
		MaxPkt:     UDPC_MAX_PKT,
		LogLevel:   "error",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(cli.Close)

	sess := &clientSession{
		client:    cli,
		sid:       pk.sid,
		frameKeys: pk.client,

		recvQueue:  make(map[uint64][]byte),
		unacked:    make(map[uint64]*unackedPkt),
		lastActive: time.Now(),
		lastSent:   time.Now(),
		closeChan:  make(chan struct{}),
	}
	sess.sendCap.Store(int32(mtuStartCap(cli.maxPkt, mtuProbeEnabled(cli.cfg.MtuProbe))))
	sess.unackedCond = sync.NewCond(&sess.unackedMu)
	cli.sessions.Store(pk.sid, sess)
	// The prober's echo arrives through the client's receive loops (same path
	// as production: DialTunnel starts them before establish).
	cli.startOnce.Do(cli.startRecvLoops)
	// The spread dialer creates its slot sockets inside the recv loops; sends
	// before that are dropped with ErrNoRoute. Wait for slot 0 to exist, like
	// a real client implicitly does (its handshake already round-tripped).
	deadline := time.Now().Add(2 * time.Second)
	for cli.dialer.Conn(0) == nil {
		if time.Now().After(deadline) {
			t.Fatal("spread dialer socket never came up")
		}
		time.Sleep(2 * time.Millisecond)
	}
	return cli, sess
}

func withFastProbing(t *testing.T) {
	t.Helper()
	oldTimeout, oldAttempts := mtuProbeTimeout.Load(), mtuProbeAttempts.Load()
	mtuProbeTimeout.Store(int64(50 * time.Millisecond))
	mtuProbeAttempts.Store(1)
	t.Cleanup(func() {
		mtuProbeTimeout.Store(oldTimeout)
		mtuProbeAttempts.Store(oldAttempts)
	})
}

// waitForCommit polls until the fake server observed the expected commit.
func (f *fakeProbeServer) waitForCommit(want int, timeout time.Duration) []int {
	deadline := time.Now().Add(timeout)
	for {
		got := f.commitValues()
		for _, v := range got {
			if v == want {
				return got
			}
		}
		if time.Now().After(deadline) {
			return nil
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestProbePathConvergesOnLargestAnsweredSize(t *testing.T) {
	withFastProbing(t)
	pk := newProberKeyPair(t)
	fake := newFakeProbeServer(t, pk.server)
	fake.maxRecord.Store(1250) // 1450 must go unanswered, 1200 must succeed

	_, sess := newProberRig(t, fake, pk)
	if got := probePath(context.Background(), sess); got != 1200 {
		t.Fatalf("probePath() = %d, want 1200 (largest ladder step the fake server answers)", got)
	}
}

func TestProbePathFallsBackWhenNothingIsAnswered(t *testing.T) {
	withFastProbing(t)
	pk := newProberKeyPair(t)
	fake := newFakeProbeServer(t, pk.server)
	fake.silence.Store(true) // the old-peer contract: unknown commands are dropped

	_, sess := newProberRig(t, fake, pk)
	if got := probePath(context.Background(), sess); got != 0 {
		t.Fatalf("probePath() = %d, want 0 (fall back to the configured max_pkt)", got)
	}
}

func TestConvergeFrameBudgetAppliesCacheAndCommit(t *testing.T) {
	withFastProbing(t)
	pk := newProberKeyPair(t)
	fake := newFakeProbeServer(t, pk.server)

	cli, sess := newProberRig(t, fake, pk)
	cli.probeCache.store(800) // warm cache: no probe traffic, straight to the commit

	cli.convergeFrameBudget(context.Background(), sess)
	if got := int(sess.sendCap.Load()); got != 800 {
		t.Fatalf("session sendCap = %d, want the cached 800", got)
	}
	commits := fake.waitForCommit(800, time.Second)
	if commits == nil {
		t.Fatal("the server never received the 800-byte commit")
	}
}

func TestServerEchoesMtuProbe(t *testing.T) {
	rig := newTestRig(t, false)
	probe := rig.makeWireFrame(&UDPCFrame{
		Cmd: CMD_MTU_PROBE, PacketNo: 1, Data: make([]byte, 500),
	})
	if !rig.deliverWireData(probe, rig.clientAddr) {
		t.Fatal("probe frame rejected")
	}
	reply := rig.recvFrame(time.Second)
	if reply.Cmd != CMD_MTU_PROBE_REPLY {
		t.Fatalf("reply cmd = 0x%02X, want CMD_MTU_PROBE_REPLY", reply.Cmd)
	}
	if len(reply.Data) != len(probe.Data) {
		t.Fatalf("echo length = %d, want %d (the length IS the probed size)", len(reply.Data), len(probe.Data))
	}
	for i := range probe.Data {
		if reply.Data[i] != probe.Data[i] {
			t.Fatalf("echo differs at byte %d", i)
		}
	}
}

func TestUpstreamGateHoldsUntilCommit(t *testing.T) {
	const commitSize = 300
	rig := newTestRig(t, false)
	rig.sess.mtuGate = make(chan struct{}) // the rig builds sessions without one

	go rig.sess.upstreamToUdpLoop()
	go func() { _, _ = rig.target.Write(make([]byte, 1000)) }()

	// Before the commit the pump must hold: no frame may leave the server.
	rig.expectNoFrame(400 * time.Millisecond)

	commit := rig.makeWireFrame(&UDPCFrame{Cmd: CMD_MTU_COMMIT, PacketNo: 1, Data: []byte{0x01, 0x2C}})
	if !rig.deliverWireData(commit, rig.clientAddr) {
		t.Fatal("commit frame rejected")
	}
	if rig.sess.maxPkt.Load() != commitSize {
		t.Fatalf("session maxPkt = %d, want %d", rig.sess.maxPkt.Load(), commitSize)
	}

	largest, total := 0, 0
	deadline := time.Now().Add(3 * time.Second)
	buf := make([]byte, 4096)
	for total < 1000 && time.Now().Before(deadline) {
		if err := rig.client.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
		n, err := rig.client.Read(buf)
		if err != nil {
			continue
		}
		total += n - UDPC_HDR_SIZE - UDPC_TRAILER_SIZE
		if n > largest {
			largest = n
		}
	}
	if total < 1000 {
		t.Fatalf("only %d of 1000 payload bytes arrived after the commit", total)
	}
	if largest > commitSize {
		t.Fatalf("largest emitted record is %d bytes, exceeds the committed %d", largest, commitSize)
	}
}

func TestUpstreamSplitsOversizedTcpChunks(t *testing.T) {
	rig := newTestRig(t, false)
	rig.sess.mtuGate = make(chan struct{})
	rig.sess.maxPkt.Store(300) // as if a commit had arrived
	rig.sess.openMtuGate()

	go rig.sess.upstreamToUdpLoop()
	go func() { _, _ = rig.target.Write(make([]byte, 1000)) }()

	largest, total := 0, 0
	deadline := time.Now().Add(3 * time.Second)
	buf := make([]byte, 4096)
	for total < 1000 && time.Now().Before(deadline) {
		if err := rig.client.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
		n, err := rig.client.Read(buf)
		if err != nil {
			continue
		}
		total += n - UDPC_HDR_SIZE - UDPC_TRAILER_SIZE
		if n > largest {
			largest = n
		}
	}
	if total < 1000 {
		t.Fatalf("only %d of 1000 payload bytes arrived", total)
	}
	if largest != 300 {
		t.Fatalf("largest record is %d bytes, want exactly the committed 300", largest)
	}
}

func TestMtuInitialCap(t *testing.T) {
	for _, tc := range []struct {
		maxPkt int
		want   int
	}{
		{1450, 548},
		{800, 548},
		{548, 548},
		{300, 300},
		{120, 120},
	} {
		if got := mtuInitialCap(tc.maxPkt); got != tc.want {
			t.Errorf("mtuInitialCap(%d) = %d, want %d", tc.maxPkt, got, tc.want)
		}
	}
}

// The floor commit must reach the server BEFORE the ladder has a chance to
// overrun it: otherwise the server's upstream gate sits on mtuCommitWait and
// encodes records the path cannot carry, and those frames can never be
// re-chunked on retransmission.
func TestConvergeFrameBudgetCommitsFloorFirst(t *testing.T) {
	withFastProbing(t)
	pk := newProberKeyPair(t)
	fake := newFakeProbeServer(t, pk.server)
	fake.silence.Store(true) // no rung answers at all

	cli, sess := newProberRig(t, fake, pk)

	cli.convergeFrameBudget(context.Background(), sess)

	commits := fake.commitValues()
	if len(commits) == 0 {
		t.Fatal("the server received no commit at all")
	}
	if commits[0] != mtuProbeFloor {
		t.Fatalf("first commit = %d, want the never-fragment floor %d", commits[0], mtuProbeFloor)
	}
	// Everything the client committed must be a size it is actually willing to
	// send, and never above the ceiling.
	for _, v := range commits {
		if v > UDPC_MAX_PKT || v < mtuInitialCap(UDPC_MAX_PKT) {
			t.Fatalf("commit %d is outside [%d,%d]", v, mtuInitialCap(UDPC_MAX_PKT), UDPC_MAX_PKT)
		}
	}
	// The probe answered nothing, so the session must end at the fallback floor
	// rather than the configured ceiling.
	if got := int(sess.sendCap.Load()); got != weakNetworkMtuFallback {
		t.Fatalf("session sendCap = %d, want the no-answer fallback %d", got, weakNetworkMtuFallback)
	}
}

// applyMtuCommit must honor both growth (floor commit, then the converged
// value) and shrink (an idle re-probe that found the path degraded). Every
// applied value stays inside the server's own configured budget.
func TestServerApplyMtuCommitHonorsGrowAndShrink(t *testing.T) {
	srv := &Server{maxPkt: 1450}
	sess := &ServerSession{sessionID: 1, server: srv}

	sess.applyMtuCommit(mtuProbeFloor)
	if got := int(sess.maxPkt.Load()); got != mtuProbeFloor {
		t.Fatalf("after floor commit maxPkt = %d, want %d", got, mtuProbeFloor)
	}

	sess.applyMtuCommit(1450)
	if got := int(sess.maxPkt.Load()); got != 1450 {
		t.Fatalf("after grow maxPkt = %d, want 1450", got)
	}

	sess.applyMtuCommit(1200)
	if got := int(sess.maxPkt.Load()); got != 1200 {
		t.Fatalf("after shrink maxPkt = %d, want 1200", got)
	}

	// Duplicate copies are a no-op, so the extra sends are harmless.
	sess.applyMtuCommit(1200)
	if got := int(sess.maxPkt.Load()); got != 1200 {
		t.Fatalf("after duplicate maxPkt = %d, want 1200", got)
	}

	// A commit can never push the server past its own configured budget.
	sess.applyMtuCommit(99999)
	if got := int(sess.maxPkt.Load()); got != 1450 {
		t.Fatalf("after over-ceiling commit maxPkt = %d, want 1450", got)
	}

	// And never below the usable floor.
	sess.applyMtuCommit(10)
	if got := int(sess.maxPkt.Load()); got != maxPktFloor {
		t.Fatalf("after under-floor commit maxPkt = %d, want %d", got, maxPktFloor)
	}
}

func TestLowerSendCapIsShrinkOnly(t *testing.T) {
	sess := &clientSession{}
	sess.sendCap.Store(1450)

	sess.lowerSendCap(1200)
	if got := int(sess.sendCap.Load()); got != 1200 {
		t.Fatalf("after shrink sendCap = %d, want 1200", got)
	}
	sess.lowerSendCap(1000)
	if got := int(sess.sendCap.Load()); got != 1000 {
		t.Fatalf("after second shrink sendCap = %d, want 1000", got)
	}
	// Raises are refused: only raiseSendCap grows the cap.
	sess.lowerSendCap(1400)
	sess.lowerSendCap(9999)
	if got := int(sess.sendCap.Load()); got != 1000 {
		t.Fatalf("after refused raise sendCap = %d, want 1000", got)
	}
	// Equal is a no-op, not a failure.
	sess.lowerSendCap(1000)
	if got := int(sess.sendCap.Load()); got != 1000 {
		t.Fatalf("after equal sendCap = %d, want 1000", got)
	}
}

func TestRaiseSendCapIsGrowOnly(t *testing.T) {
	sess := &clientSession{}
	sess.sendCap.Store(800)

	sess.raiseSendCap(1200)
	if got := int(sess.sendCap.Load()); got != 1200 {
		t.Fatalf("after raise sendCap = %d, want 1200", got)
	}
	// Shrinks are refused: only lowerSendCap shrinks the cap. (The ceiling is
	// the caller's job — tryRaiseOneRung only ever offers verified ladder
	// rungs at or below max_pkt.)
	sess.raiseSendCap(1000)
	if got := int(sess.sendCap.Load()); got != 1200 {
		t.Fatalf("after refused shrink sendCap = %d, want 1200", got)
	}
	// Equal is a no-op.
	sess.raiseSendCap(1200)
	if got := int(sess.sendCap.Load()); got != 1200 {
		t.Fatalf("after equal sendCap = %d, want 1200", got)
	}
}

// TestLargestRungBelowAndNextRungAbove pin the ladder-navigation helpers the
// idle re-probe walks with. The ladder is DESCENDING, and the old inline
// loops broke on the first entry at-or-above the current size — finding
// nothing below and slamming the session straight to the floor.
func TestLargestRungBelowAndNextRungAbove(t *testing.T) {
	ladder := mtuLadderFor(UDPC_MAX_PKT) // 1450 1392 1200 1000 800 548

	cases := []struct {
		cur, below, above int
	}{
		{1450, 1392, 0}, // ceiling rung: nothing above
		{1392, 1200, 1450},
		{1300, 1200, 1392}, // between rungs
		{1200, 1000, 1392},
		{1000, 800, 1200},
		{801, 800, 1000},
		{800, 548, 1000},
		{548, 0, 800}, // floor rung: nothing below
		{400, 0, 548},
	}
	for _, tc := range cases {
		if got := largestRungBelow(ladder, tc.cur); got != tc.below {
			t.Fatalf("largestRungBelow(ladder, %d) = %d, want %d", tc.cur, got, tc.below)
		}
		if got := nextLadderRungAbove(ladder, tc.cur); got != tc.above {
			t.Fatalf("nextLadderRungAbove(ladder, %d) = %d, want %d", tc.cur, got, tc.above)
		}
	}
}

// backdateIdle makes the rig's session look quiet so reprobeIdleTick's
// idle gate lets the probe through.
func backdateIdle(t *testing.T, sess *clientSession) {
	t.Helper()
	stale := time.Now().Add(-mtuReprobeInterval)
	sess.mu.Lock()
	sess.lastActive = stale
	sess.lastSent = stale
	sess.mu.Unlock()
}

// A path that degrades from 1450-capable to 1000-capable must converge one
// rung down, not slam to the never-fragment floor: the old walk-down loop
// broke on the first ladder entry at-or-above the current cap, found nothing
// below it, and dropped every session straight to 548.
func TestReprobeIdleTickWalksDownOneRung(t *testing.T) {
	withFastProbing(t)
	pk := newProberKeyPair(t)
	fake := newFakeProbeServer(t, pk.server)
	fake.maxRecord.Store(1000) // 1450/1392/1200 unanswered, 1000 answers

	cli, sess := newProberRig(t, fake, pk)
	backdateIdle(t, sess)
	sess.sendCap.Store(1450)

	sess.reprobeIdleTick(mtuLadderFor(cli.maxPkt))

	if got := int(sess.sendCap.Load()); got != 1000 {
		t.Fatalf("after re-probe sendCap = %d, want 1000 (the largest answered rung)", got)
	}
	if commits := fake.waitForCommit(1000, time.Second); commits == nil {
		t.Fatal("the shrunken cap was never committed to the server")
	}
}

// A cap lowered by a transient loss burst must recover once the path heals:
// an idle tick at the floor (the no-answer fallback) probes one rung up and,
// when it round-trips, raises the cap and republishes it.
func TestReprobeIdleTickRecoversFromFloor(t *testing.T) {
	withFastProbing(t)
	pk := newProberKeyPair(t)
	fake := newFakeProbeServer(t, pk.server)
	fake.maxRecord.Store(1450) // everything answers

	cli, sess := newProberRig(t, fake, pk)
	backdateIdle(t, sess)
	// Simulate a session stranded at the floor by a blackout at setup time.
	sess.sendCap.Store(int32(mtuProbeFloor))

	sess.reprobeIdleTick(mtuLadderFor(cli.maxPkt))

	// One rung per tick: 548 -> 800, committed so the server can follow.
	if got := int(sess.sendCap.Load()); got != 800 {
		t.Fatalf("after recovery tick sendCap = %d, want 800 (one rung up)", got)
	}
	if commits := fake.waitForCommit(800, time.Second); commits == nil {
		t.Fatal("the raised cap was never committed to the server")
	}
}

// A mid-session shrink is not permanent either: after dropping to 1000 the
// next idle tick re-verifies the current size and climbs one rung back.
func TestReprobeIdleTickClimbsAfterShrink(t *testing.T) {
	withFastProbing(t)
	pk := newProberKeyPair(t)
	fake := newFakeProbeServer(t, pk.server)
	fake.maxRecord.Store(1392) // 1450 fails, everything at or below 1392 works

	cli, sess := newProberRig(t, fake, pk)
	backdateIdle(t, sess)
	sess.sendCap.Store(1000)

	sess.reprobeIdleTick(mtuLadderFor(cli.maxPkt))

	if got := int(sess.sendCap.Load()); got != 1200 {
		t.Fatalf("after climb tick sendCap = %d, want 1200 (one rung up)", got)
	}
}

// An idle re-probe must never raise past a size the path cannot carry.
func TestReprobeIdleTickNeverRaisesAbovePath(t *testing.T) {
	withFastProbing(t)
	pk := newProberKeyPair(t)
	fake := newFakeProbeServer(t, pk.server)
	fake.maxRecord.Store(1000)

	cli, sess := newProberRig(t, fake, pk)
	backdateIdle(t, sess)
	sess.sendCap.Store(1000)

	sess.reprobeIdleTick(mtuLadderFor(cli.maxPkt))

	if got := int(sess.sendCap.Load()); got != 1000 {
		t.Fatalf("after tick sendCap = %d, want unchanged 1000 (1200 probe failed)", got)
	}
}

// The probe must ignore the DIAL context: a DialTunnel caller whose context
// covers only the dial (WithTimeout + defer cancel) cancels it right after
// establishment, and without WithoutCancel every rung would fail and strand
// the session at the no-answer floor for its whole lifetime.
func TestConvergeFrameBudgetIgnoresCancelledDialContext(t *testing.T) {
	withFastProbing(t)
	pk := newProberKeyPair(t)
	fake := newFakeProbeServer(t, pk.server)
	fake.maxRecord.Store(1200)

	cli, sess := newProberRig(t, fake, pk)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cli.convergeFrameBudget(ctx, sess)

	if got := int(sess.sendCap.Load()); got != 1200 {
		t.Fatalf("session sendCap = %d, want 1200 (probe must survive a cancelled dial ctx)", got)
	}
}
