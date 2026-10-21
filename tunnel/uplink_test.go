package tunnel

import (
	"sync"
	"testing"
	"time"
	"unsafe"
)

// newUplinkSession builds a bare session good enough to exercise sendData:
// real frame keys (so the seal succeeds), a capture wire instead of a dialer,
// and no send flow — which is also the legacy path that must not report a zero
// send window.
func newUplinkSession(t *testing.T, maxPkt int, capValue int) (*clientSession, *[][]byte) {
	t.Helper()
	c := &Client{maxPkt: maxPkt}
	kp := newProberKeyPair(t)
	s := &clientSession{
		client:      c,
		sid:         kp.sid,
		frameKeys:   kp.client,
		recvQueue:   make(map[uint64][]byte),
		unacked:     make(map[uint64]*unackedPkt),
		rttEst:      newDefaultRTTEstimator(),
		retryWake:   make(chan struct{}, 1),
		closeChan:   make(chan struct{}),
		unackedCond: sync.NewCond(nil),
	}
	s.sendCap.Store(int32(capValue))
	s.sendSeq.Store(1)

	var mu sync.Mutex
	got := &[][]byte{}
	done := make(chan struct{})
	s.tx = newTransmitQueue(done, func(wires [][]byte) error {
		mu.Lock()
		for _, w := range wires {
			*got = append(*got, append([]byte(nil), w...))
		}
		mu.Unlock()
		return nil
	}, func(int) bool { return true }, func([][]byte) {}, func() int { return 256 }, nil)
	t.Cleanup(func() { close(done) })
	return s, got
}

func waitForCount(t *testing.T, got *[][]byte, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(*got) >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("after %d frames only %d were sent", n, len(*got))
}

// An oversized library write must be split into records, not rejected: the AEAD
// seal refuses an over-cap record and the pump used to tear the session down
// over one large write.
func TestSendDataSplitsOversizedPayload(t *testing.T) {
	const cap = mtuProbeFloor
	s, got := newUplinkSession(t, UDPC_MAX_PKT, cap)
	payload := make([]byte, 3*effectivePayloadCap(cap)+1)

	if err := s.sendData(payload); err != nil {
		t.Fatalf("sendData refused an oversized payload: %v", err)
	}
	want := 4
	waitForCount(t, got, want)
	if len(*got) != want {
		t.Fatalf("sent %d records for %d bytes at cap %d, want %d", len(*got), len(payload), cap, want)
	}
	for i, w := range *got {
		if len(w) > cap {
			t.Fatalf("record %d is %d bytes, exceeds the %d-byte cap", i, len(w), cap)
		}
		if len(w) < UDPC_HDR_SIZE+UDPC_TRAILER_SIZE {
			t.Fatalf("record %d is %d bytes, smaller than a bare header+tag", i, len(w))
		}
	}
	// A zero SendWindow means "adapt", which only the recovery path implements.
	// On a legacy session a zero window would park sendRecord on unackedCond
	// forever — sendData above would never have returned.
	if s.sendWindow() <= 0 {
		t.Fatalf("legacy sendWindow() = %d, want a positive floor", s.sendWindow())
	}
}

// The cap may shrink mid-call (idle re-probe). Whatever the scheduler interleaves,
// sendData must not error and no record may exceed the record ceiling: a chunk
// sized by a previously committed cap is still one the server already accepted.
func TestSendDataSurvivesConcurrentCapShrink(t *testing.T) {
	s, got := newUplinkSession(t, UDPC_MAX_PKT, UDPC_MAX_PKT)
	big := make([]byte, effectivePayloadCap(UDPC_MAX_PKT)*2)

	for i := 0; i < 8; i++ {
		go func() { s.lowerSendCap(mtuProbeFloor) }()
		time.Sleep(time.Microsecond * 200)
	}
	if err := s.sendData(big); err != nil {
		t.Fatalf("sendData rejected a payload while the cap shrank: %v", err)
	}
	if s.sendWindow() <= 0 {
		t.Fatalf("legacy sendWindow() = %d, want a positive floor", s.sendWindow())
	}
	// The exact split depends on when the shrink landed, so wait for the
	// transmit queue to drain and assert the ceiling instead of a count.
	waitForCount(t, got, 2)
	time.Sleep(20 * time.Millisecond)
	for i, w := range *got {
		if len(w) > UDPC_MAX_PKT {
			t.Fatalf("record %d is %d bytes, exceeds the %d-byte ceiling", i, len(w), UDPC_MAX_PKT)
		}
		if len(w) < UDPC_HDR_SIZE+UDPC_TRAILER_SIZE {
			t.Fatalf("record %d is %d bytes, smaller than a bare header+tag", i, len(w))
		}
	}
}

// flushUplink must ship the whole accumulator as one record and reset it: it is
// what turns several small Reads into a single wire record, and it must not
// shift the backing array out from under the next accumulation.
func TestFlushUplinkShipsAccumulatorAsOneRecord(t *testing.T) {
	const cap = mtuProbeFloor
	s, got := newUplinkSession(t, UDPC_MAX_PKT, cap)
	payload := make([]byte, effectivePayloadCap(cap))

	// Two appends whose total stays under the cap: they must travel as ONE
	// record, which is the whole point of accumulating.
	acc := make([]byte, 0, len(payload))
	acc = append(acc, []byte("hello, ")...)
	acc = append(acc, payload[:len(payload)-7]...)
	if len(acc) > effectivePayloadCap(cap) {
		t.Fatalf("test setup: accumulator is %d bytes, over the %d-byte cap", len(acc), effectivePayloadCap(cap))
	}
	// Keep the backing pointer alive across the reset: flushUplink must return
	// the buffer to length 0, not allocate a replacement, or the pump would
	// reallocate on every record.
	backing := unsafe.SliceData(acc)

	if !s.flushUplink(&acc) {
		t.Fatal("flushUplink reported failure")
	}
	if len(acc) != 0 {
		t.Fatalf("accumulator was not drained: %d bytes left", len(acc))
	}
	waitForCount(t, got, 1)
	if len(*got) != 1 {
		t.Fatalf("sent %d records for one accumulated buffer, want 1", len(*got))
	}
	if unsafe.SliceData(acc) != backing {
		t.Fatal("flushUplink replaced the accumulator's backing array")
	}

	// A second flush on the reset accumulator is a no-op, not a zero-length
	// record.
	if !s.flushUplink(&acc) {
		t.Fatal("flushUplink failed on an empty accumulator")
	}
	if len(*got) != 1 {
		t.Fatalf("sent %d records after the empty flush, want still 1", len(*got))
	}
}
