package tunnel

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// udpEcho starts a UDP target that echoes every datagram it receives back to
// the sender, and returns the connected socket the session dials it with. The
// read buffer is well above UDPC_MAX_PKT so the echo never truncates: any
// shortfall the test observes is the tunnel's doing, not the target's.
func udpEcho(t *testing.T) *net.UDPConn {
	t.Helper()
	srv, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	ec := srv.(*net.UDPConn)
	t.Cleanup(func() { ec.Close() })
	go func() {
		buf := make([]byte, 8192)
		for {
			n, addr, err := ec.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if _, err := ec.WriteToUDP(buf[:n], addr); err != nil {
				return
			}
		}
	}()
	cli, err := net.DialUDP("udp", nil, ec.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("echo dial: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	return cli
}

// TestUpstreamDoesNotDropEchoOverStaleCommit is the regression test for the
// silently-corrupted "udp" byte stream: the client commits the never-fragment
// floor, converges to the full size, and because UDP does not order records its
// first full-size record can reach the session before the commit that authorizes
// it. The session then believes a narrow budget, echoes the record to the
// target, and forwardUpstream refused to send the reply back — dropping the
// round trip's bytes on the floor.
//
// The fix is observedPayload: a record the session decoded and authenticated is
// itself proof that the path carries that size right now, so the reply is
// budgeted by what the client demonstrably sent rather than by the commit that
// is still in flight.
func TestUpstreamDoesNotDropEchoOverStaleCommit(t *testing.T) {
	want := payloadCap(UDPC_MAX_PKT)
	payload := make([]byte, want)
	for i := range payload {
		payload[i] = byte(i*7 + 3)
	}

	rig := newTestRig(t, false)
	rig.sess.mtuGate = make(chan struct{}) // the rig builds sessions without one
	rig.sess.targetNetwork = "udp"
	rig.sess.upstream = udpEcho(t)

	// The floor commit landed first, as it does in the real MTU climb, so the
	// session's budget is the narrow floor while the client is already writing
	// full-size records.
	rig.sess.maxPkt.Store(maxPktFloor)
	if got := rig.sess.maxPayload(); got != payloadCap(maxPktFloor) {
		t.Fatalf("floor commit budget = %d, want %d", got, payloadCap(maxPktFloor))
	}
	rig.sess.openMtuGate()
	go rig.sess.upstreamToUdpLoop()

	// A full-size record arrives ahead of the commit that justifies it.
	f := rig.makeWireData(1, 1, payload)
	if !rig.deliverWireData(f, rig.clientAddr) {
		t.Fatal("full-size data frame rejected")
	}

	// The delivery ACK leaves the server before the echo, so skip control
	// frames until the echo record itself arrives.
	deadline := time.Now().Add(3 * time.Second)
	buf := make([]byte, 2048)
	for time.Now().Before(deadline) {
		rig.client.SetReadDeadline(deadline)
		n, _, err := rig.client.ReadFromUDP(buf)
		if err != nil {
			break
		}
		f, err := DecodeUDPCFrame(buf[:n], rig.server.cfg.Magic)
		if err != nil || f.Cmd != CMD_DATA {
			continue
		}
		plain, err := OpenFrameAEAD(f, rig.clientKeys.Recv)
		if err != nil {
			t.Fatalf("echo frame AEAD: %v", err)
		}
		if len(plain) != want {
			t.Fatalf("echo payload is %d bytes, want the full %d (a stale commit ate %d bytes)",
				len(plain), want, want-len(plain))
		}
		if !bytes.Equal(plain, payload) {
			t.Fatalf("echo payload does not match the record the client sent")
		}
		return
	}
	t.Fatal("no echo frame came back from the target: the full-size record was dropped upstream")
}

// TestObservedPayloadBudget pins the budget arithmetic: the observed high-water
// may raise the budget past a stale commit but never past the operator's
// ceiling, a shrink commit discards it, and growth keeps it.
func TestObservedPayloadBudget(t *testing.T) {
	rig := newTestRig(t, false)
	sess := rig.sess

	ceiling := rig.server.maxPayload()
	if ceiling < payloadCap(maxPktFloor) {
		t.Fatalf("server budget %d is below the never-fragment floor budget", ceiling)
	}

	// No commit yet: the server's configured budget applies.
	if got := sess.maxPayload(); got != ceiling {
		t.Fatalf("maxPayload with no commit = %d, want the configured %d", got, ceiling)
	}

	// A floor commit narrows it.
	sess.applyMtuCommit(maxPktFloor)
	narrow := payloadCap(maxPktFloor)
	if got := sess.maxPayload(); got != narrow {
		t.Fatalf("maxPayload after the %d commit = %d, want %d", maxPktFloor, got, narrow)
	}

	// A larger record the client actually sent raises it back up, because that
	// record proves the path carries the size.
	sess.noteObservedPayload(ceiling)
	if got := sess.maxPayload(); got != ceiling {
		t.Fatalf("maxPayload after observing %d = %d, want %d", ceiling, got, ceiling)
	}

	// Smaller observations never lower it; a duplicate never changes it.
	sess.noteObservedPayload(1)
	sess.noteObservedPayload(ceiling)
	if got := sess.maxPayload(); got != ceiling {
		t.Fatalf("maxPayload after a smaller observation = %d, want %d", got, ceiling)
	}

	// Garbage cannot raise it.
	sess.noteObservedPayload(0)
	sess.noteObservedPayload(-1)
	if got := sess.maxPayload(); got != ceiling {
		t.Fatalf("maxPayload after a zero/negative observation = %d, want %d", got, ceiling)
	}

	// Growth keeps the high-water: it is exactly what a climb in flight needs.
	sess.applyMtuCommit(800)
	if got := sess.observedPayload.Load(); got != int32(ceiling) {
		t.Fatalf("observedPayload = %d after a growth commit, want it kept", got)
	}
	if got := sess.maxPayload(); got != ceiling {
		t.Fatalf("maxPayload after a growth commit = %d, want %d", got, ceiling)
	}

	// A shrink commit is the client's word that the path narrowed, so it
	// discards the high-water.
	sess.applyMtuCommit(maxPktFloor)
	if got := sess.observedPayload.Load(); got != 0 {
		t.Fatalf("observedPayload = %d after a shrink commit, want it cleared", got)
	}
	if got := sess.maxPayload(); got != narrow {
		t.Fatalf("maxPayload after a shrink commit = %d, want the narrowed %d", got, narrow)
	}

	// A genuine observation raises the narrowed budget again.
	sess.noteObservedPayload(ceiling)
	if got := sess.maxPayload(); got != ceiling {
		t.Fatalf("maxPayload after observing %d = %d, want %d", ceiling, got, ceiling)
	}

	// A second shrink clears it, and an observation above the operator's ceiling
	// is evidence about the path, not permission to exceed it.
	sess.applyMtuCommit(maxPktFloor)
	sess.noteObservedPayload(ceiling + 1)
	if got := sess.maxPayload(); got != narrow {
		t.Fatalf("maxPayload with obs %d = %d, want the narrowed %d (above the ceiling)",
			ceiling+1, got, narrow)
	}
	if got := sess.observedPayload.Load(); got != int32(ceiling+1) {
		t.Fatalf("observedPayload = %d, want %d (recorded but unactionable)", got, ceiling+1)
	}
}
