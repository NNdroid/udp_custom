package tunnel

import (
	"bytes"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestOrderedDeliveryBackpressureOwnershipAndOrder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		done := make(chan struct{})
		gate := make(chan struct{})
		var got bytes.Buffer
		d := newOrderedDelivery(4, done, func(p []byte) error { <-gate; got.Write(p); return nil }, func(err error) { t.Error(err) }, func(uint64) {}, nil)
		defer func() { d.close(); close(done) }()
		p := []byte("B")
		if !d.offer(2, p) || !d.offer(1, []byte("A")) {
			t.Fatal("admission failed")
		}
		p[0] = 'X'
		synctest.Wait()
		if d.delivered.Load() != 0 {
			t.Fatal("acknowledged before application read")
		}
		if !d.offer(4, []byte("D")) || !d.offer(3, []byte("C")) {
			t.Fatal("could not fill bounded queue")
		}
		if d.offer(5, []byte("E")) {
			t.Fatal("accepted beyond receive window")
		}
		if !d.offer(2, []byte("duplicate")) {
			t.Fatal("duplicate should be harmless")
		}
		close(gate)
		synctest.Wait()
		if got.String() != "ABCD" {
			t.Fatalf("got %q", got.String())
		}
		if ack, _, credit := d.snapshot(); ack != 4 || credit != 4 {
			t.Fatalf("ack=%d credit=%d", ack, credit)
		}
	})
}

func TestOrderedDeliveryConcurrentAdmission(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		done := make(chan struct{})
		gate := make(chan struct{})
		var got bytes.Buffer
		d := newOrderedDelivery(128, done, func(p []byte) error { <-gate; got.Write(p); return nil }, func(err error) { t.Error(err) }, func(uint64) {}, nil)
		defer func() { d.close(); close(done) }()
		var wg sync.WaitGroup
		for i := 1; i <= 128; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				if !d.offer(uint64(i), []byte{byte(i)}) {
					t.Errorf("rejected %d", i)
				}
			}(i)
		}
		wg.Wait()
		close(gate)
		synctest.Wait()
		if got.Len() != 128 {
			t.Fatalf("got %d bytes", got.Len())
		}
		for i, v := range got.Bytes() {
			if v != byte(i+1) {
				t.Fatalf("offset %d got %d", i, v)
			}
		}
	})
}

func TestDelayedACKSinglePairAndClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var d delayedACK
		acks := make(chan uint64, 8)
		send := func(n uint64) { acks <- n }
		d.queue(1, send)
		synctest.Wait()
		if len(acks) != 0 {
			t.Fatal("single frame ACK was not delayed")
		}
		time.Sleep(time.Millisecond)
		synctest.Wait()
		if len(acks) != 1 || <-acks != 1 {
			t.Fatal("single ACK did not flush")
		}
		d.queue(2, send)
		d.queue(3, send)
		if len(acks) != 1 || <-acks != 3 {
			t.Fatal("pair ACK did not coalesce")
		}
		d.queue(4, send)
		d.close()
		time.Sleep(2 * time.Millisecond)
		synctest.Wait()
		if len(acks) != 0 {
			t.Fatal("ACK after close")
		}
	})
}

// TestSnapshotNeverOverrunsBitmap: the bitmap horizon is the session's own
// delivery limit, so admissions up to `limit` above the delivered prefix are
// described at their exact bit, and anything beyond the limit (a stale map
// entry, a miscalculated admission) must be skipped instead of indexing past
// the bitmap.
func TestSnapshotNeverOverrunsBitmap(t *testing.T) {
	done := make(chan struct{})
	defer close(done)
	d := newOrderedDelivery(deliveryWindowWide, done, func([]byte) error { return nil }, func(error) {}, func(uint64) {}, nil)
	ack, bitmap, credit := d.snapshot()
	if ack != 0 || credit != deliveryWindowWide {
		t.Fatalf("empty snapshot ack=%d credit=%d", ack, credit)
	}
	d.mu.Lock()
	d.pending[5] = []byte("head")       // bit 4, word 0
	d.pending[1000] = []byte("far")     // bit 999, word 15
	d.pending[2048] = []byte("further") // bit 2047, word 31
	d.pending[5000] = []byte("beyond")  // past the limit: must be skipped, not panic
	d.mu.Unlock()
	ack, bitmap, credit = d.snapshot()
	want := func(bit int) uint64 { return uint64(1) << (bit % 64) }
	if bitmap[0] != want(4) {
		t.Fatalf("bitmap[0] = %#x, want %#x", bitmap[0], want(4))
	}
	if bitmap[15] != want(999) {
		t.Fatalf("bitmap[15] = %#x, want %#x", bitmap[15], want(999))
	}
	if bitmap[31] != want(2047) {
		t.Fatalf("bitmap[31] = %#x, want %#x", bitmap[31], want(2047))
	}
	for i, w := range bitmap {
		if i != 0 && i != 15 && i != 31 && w != 0 {
			t.Fatalf("bitmap[%d] = %#x, want 0", i, w)
		}
	}
	if credit != deliveryWindowWide-4 {
		t.Fatalf("credit = %d, want %d", credit, deliveryWindowWide-4)
	}
}

// TestDeliveryLimitFor: only a negotiated wide session may advertise credit
// beyond the 512-frame wire baseline (an old peer would reject it).
func TestDeliveryLimitFor(t *testing.T) {
	if got := deliveryLimitFor(false); got != deliveryWindow {
		t.Fatalf("baseline limit = %d, want %d", got, deliveryWindow)
	}
	if got := deliveryLimitFor(true); got != deliveryWindowWide {
		t.Fatalf("wide limit = %d, want %d", got, deliveryWindowWide)
	}
}

// TestOrderedDeliveryFeedsPeerWhileWriterStalls: a local reader that stops
// consuming must not silence the feedback path. Nothing has been delivered, so
// the peer's cumulative ACK cannot advance — correctly — but staying silent
// makes the peer's RTO ladder fire on frames we are already holding, collapse
// a window that was never congested, and starve its own upload behind it. The
// per-frame feedback keeps telling the peer what is buffered, and the credit
// snapshot it carries makes the peer settle at what we can accept.
func TestOrderedDeliveryFeedsPeerWhileWriterStalls(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		done := make(chan struct{})
		gate := make(chan struct{})
		var mu sync.Mutex
		var acks []uint64
		d := newOrderedDelivery(8, done,
			func([]byte) error { <-gate; return nil },
			func(err error) { t.Error(err) },
			func(seq uint64) { mu.Lock(); acks = append(acks, seq); mu.Unlock() }, nil)
		defer func() { d.close(); close(done) }()

		if !d.offer(1, []byte("A")) {
			t.Fatal("admission failed")
		}
		synctest.Wait() // the sole writer is now parked inside write()
		time.Sleep(2 * stallFeedbackInterval)

		mu.Lock()
		before := len(acks)
		mu.Unlock()
		for seq := uint64(2); seq <= 5; seq++ {
			if !d.offer(seq, []byte("xxxxxxxx")) {
				t.Fatalf("admission of %d failed", seq)
			}
		}
		synctest.Wait()

		mu.Lock()
		after := len(acks)
		mu.Unlock()
		if after <= before {
			t.Fatalf("no feedback while the writer was blocked (acks=%v)", acks)
		}
		// Credit must count the frames we are holding: limit 8, 5 buffered.
		if _, _, credit := d.snapshot(); credit != 3 {
			t.Fatalf("credit = %d, want 3 (8-5 buffered)", credit)
		}
		close(gate)
	})
}
