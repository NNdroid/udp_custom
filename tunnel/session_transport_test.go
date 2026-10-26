package tunnel

import (
	"testing"
	"time"
)

func TestAckCoalesceIntervalScalesWithRTT(t *testing.T) {
	// Fresh session: no RTT sample yet, so the window is the 1 ms floor and the
	// first feedback goes out at once.
	if iv := ackCoalesceInterval(0); iv != time.Millisecond {
		t.Fatalf("no-sample interval=%v, want 1ms", iv)
	}
	// Bounded below by the RTO margin: half an SRTT always clears the sender's
	// next timeout, which is at least 1.5*SRTT.
	if iv := ackCoalesceInterval(40 * time.Millisecond); iv != 20*time.Millisecond {
		t.Fatalf("40ms interval=%v, want 20ms", iv)
	}
	// Capped so a high-latency path does not add visible repair latency.
	if iv := ackCoalesceInterval(3 * time.Second); iv != ackMaxCoalesce {
		t.Fatalf("3s interval=%v, want the %v cap", iv, ackMaxCoalesce)
	}
}

func TestAckCoalescerSuppressesNonAdvances(t *testing.T) {
	const iv = 50 * time.Millisecond
	var c ackCoalescer

	// The first advance goes straight out: nothing has been communicated yet.
	if !c.claim(1, iv, false) {
		t.Fatal("first advance was suppressed")
	}
	if ack, wait := c.flushDue(iv); ack != 0 || wait != 0 {
		t.Fatalf("nothing was deferred, so flushDue=(%v,%v), want (0,0)", ack, wait)
	}

	// Repeating the same value adds no information and must never be sent.
	if c.claim(1, iv, false) {
		t.Fatal("an unchanged cumulative ACK was sent")
	}
	// A record that already carried the value suppresses it too, which is what
	// makes standalone ACKs unnecessary whenever DATA is in flight.
	c.commitSent(1)
	if c.claim(1, iv, false) {
		t.Fatal("a value already piggybacked was ACKed standalone")
	}
}

func TestAckCoalescerCoalescesAdvances(t *testing.T) {
	const iv = 50 * time.Millisecond
	var c ackCoalescer
	if !c.claim(1, iv, false) {
		t.Fatal("first advance was suppressed")
	}

	// Advances inside the window are deferred, newest wins.
	for _, seq := range []uint64{2, 3, 4} {
		if c.claim(seq, iv, false) {
			t.Fatalf("advance %d escaped the suppression window", seq)
		}
	}
	ack, wait := c.flushDue(iv)
	if ack != 0 || wait <= 0 || wait > iv {
		t.Fatalf("flushDue=(%v,%v), want (0, 0<wait<=%v)", ack, wait, iv)
	}

	// Once the window has elapsed the newest advance goes out and nothing is
	// left pending.
	time.Sleep(iv + time.Millisecond)
	ack, wait = c.flushDue(iv)
	if ack != 4 || wait != 0 {
		t.Fatalf("flushDue=(%v,%v), want (4,0)", ack, wait)
	}
	if ack, wait := c.flushDue(iv); ack != 0 || wait != 0 {
		t.Fatalf("flushDue=(%v,%v), want (0,0): emitted twice for one advance", ack, wait)
	}
	if c.claim(4, iv, false) {
		t.Fatal("a flushed value was re-ACKed")
	}
	// The flush itself restarted the suppression window.
	if c.claim(5, iv, false) {
		t.Fatal("an advance inside the window escaped")
	}
	time.Sleep(iv + time.Millisecond)
	if !c.claim(5, iv, false) {
		t.Fatal("the next advance after a flush was suppressed")
	}
}

func TestAckCoalescerUrgentGapBypassesWindow(t *testing.T) {
	const iv = time.Second
	var c ackCoalescer
	if !c.claim(1, iv, false) {
		t.Fatal("first advance was suppressed")
	}
	// A gap-bearing SACK triggers the sender's fast repair; delaying it would
	// trade a coalesced datagram for a slower repair, so it must bypass.
	if !c.claim(7, iv, true) {
		t.Fatal("an urgent gap ACK was suppressed")
	}
	if !c.claim(8, iv, true) {
		t.Fatal("a second urgent gap ACK was suppressed")
	}
	if c.claim(8, iv, false) {
		t.Fatal("an unchanged value escaped the window while urgent")
	}
}

func TestAckCoalescerUrgentSurvivesZeroAck(t *testing.T) {
	const iv = time.Second
	var c ackCoalescer
	// Nothing is delivered yet, so the cumulative Ack is 0 — but the bitmap
	// already carries admissions after a hole, which is what triggers the
	// sender's fast repair. Gating the claim on the Ack advancing would drop
	// exactly this one and the loss would be repaired by a timeout instead.
	if !c.claim(0, iv, true) {
		t.Fatal("an urgent zero-ack gap SACK was suppressed")
	}
	// While the hole persists every admission is still new information.
	if !c.claim(0, iv, true) {
		t.Fatal("a second urgent zero-ack gap SACK was suppressed")
	}
	// An ack that never moved is not urgent, and is never sent.
	if c.claim(0, iv, false) {
		t.Fatal("a zero ack was sent")
	}
}

func TestSackGapsCountsBits(t *testing.T) {
	for _, tc := range []struct {
		bitmap [8]uint64
		want   int
	}{
		{[8]uint64{}, 0},
		{[8]uint64{1 << 2, 1 << 63}, 2},
		{[8]uint64{1<<1 | 1<<3 | 1<<5, ^uint64(0)}, 3 + 64},
	} {
		if got := sackGaps(tc.bitmap); got != tc.want {
			t.Fatalf("sackGaps=%d, want %d", got, tc.want)
		}
	}
}
