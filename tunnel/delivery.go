package tunnel

import (
	"sync"
	"sync/atomic"
	"time"
)

// deliveryWindow is the wire-safe baseline flight cap, in frames. The SACK
// bitmap is 512 bits wide (one admission per bit), so 512 needs no protocol
// extension at all; anything beyond it requires FLAG_WIDE_WINDOW (see
// deliveryWindowWide).
const deliveryWindow = 512

// deliveryWindowWide is the flight cap for sessions that negotiated
// FLAG_WIDE_WINDOW. The window IS the BDP ceiling: 512 frames of ~1450 bytes
// caps throughput at 24 Mbps at 250 ms RTT and 15 Mbps at 400 ms — exactly
// the high-RTT links weak networks run on. 2048 frames (~3 MB of wire
// buffers per session in the worst case) lifts the ceiling to ~95 Mbps at
// 250 ms. The SACK bitmap stays 512 bits: a short bitmap is legal (it only
// describes the head of the outstanding range) and keeps the wire format
// identical to the baseline.
const deliveryWindowWide = 2048

// deliveryLimitFor returns the ordered-delivery limit (and thus the credit
// this end advertises) for a session. Only a negotiated wide session may
// advertise credit beyond deliveryWindow: an old peer validates incoming
// credit against the 512 ceiling and would reject every SACK from us
// otherwise, silently disabling its own fast repair.
func deliveryLimitFor(wide bool) int {
	if wide {
		return deliveryWindowWide
	}
	return deliveryWindow
}

// orderedDelivery owns every accepted payload until the sole writer completes
// it. Admission, order, and memory limits are independent of socket readers.
// ACK means delivered, not merely copied into a queue.
type orderedDelivery struct {
	mu        sync.Mutex
	pending   map[uint64][]byte
	limit     int
	closed    bool
	wake      chan struct{}
	done      <-chan struct{}
	delivered atomic.Uint64
	write     func([]byte) error
	fail      func(error)
	ack       func(uint64)
	delayed   delayedACK
}

func newOrderedDelivery(limit int, done <-chan struct{}, write func([]byte) error, fail func(error), ack func(uint64)) *orderedDelivery {
	if limit <= 0 || limit > deliveryWindowWide {
		limit = deliveryWindowWide
	}
	d := &orderedDelivery{pending: make(map[uint64][]byte), limit: limit, wake: make(chan struct{}, 1), done: done, write: write, fail: fail, ack: ack}
	go d.run()
	return d
}

func (d *orderedDelivery) offer(seq uint64, payload []byte) bool {
	_, ok := d.offerObserved(seq, payload)
	return ok
}

// offerObserved is offer with loss attribution for the receive-driven path
// scorer: fresh reports whether the frame carried NEW data. A duplicate
// sequence (<= delivered prefix, or already pending) means the server
// retransmitted — the original copy was lost on that path.
func (d *orderedDelivery) offerObserved(seq uint64, payload []byte) (fresh bool, ok bool) {
	if seq == 0 {
		return false, false
	}
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return false, false
	}
	ack := d.delivered.Load()
	if seq <= ack {
		d.mu.Unlock()
		d.ack(ack)
		return false, true
	}
	if _, ok := d.pending[seq]; ok {
		d.mu.Unlock()
		return false, true
	}
	// Reserve the gap's slot even when later packets arrive first. Bound both
	// the number of frames and the sequence distance from the delivered prefix.
	if seq-ack > uint64(d.limit) || len(d.pending) >= d.limit {
		d.mu.Unlock()
		return false, false
	}
	d.pending[seq] = append([]byte(nil), payload...)
	_, hasNext := d.pending[ack+1]
	gap := seq > ack+1 && !hasNext
	d.mu.Unlock()
	select {
	case d.wake <- struct{}{}:
	default:
	}
	if gap {
		d.ack(ack)
	}
	return true, true
}

func (d *orderedDelivery) snapshot() (ack uint64, bitmap [8]uint64, credit uint16) {
	d.mu.Lock()
	defer d.mu.Unlock()
	ack = d.delivered.Load()
	// The bitmap has room for 512 admissions regardless of how wide the
	// delivery limit is: a wide session may hold far more pending frames, and
	// indexing past the bitmap would panic. Frames beyond the last bitmap bit
	// are simply not described here — the SACK covers its head, the peer's RTO
	// covers the rest.
	const bitmapBits = uint64(8 * 64)
	for seq := range d.pending {
		if seq > ack && seq-ack <= bitmapBits {
			bit := seq - ack - 1
			bitmap[bit/64] |= uint64(1) << (bit % 64)
		}
	}
	return ack, bitmap, uint16(d.limit - len(d.pending))
}

func (d *orderedDelivery) run() {
	for {
		select {
		case <-d.done:
			return
		case <-d.wake:
		}
		for {
			d.mu.Lock()
			seq := d.delivered.Load() + 1
			payload, ok := d.pending[seq]
			closed := d.closed
			d.mu.Unlock()
			if closed || !ok {
				break
			}
			select {
			case <-d.done:
				return
			default:
			}
			if err := d.write(payload); err != nil {
				d.fail(err)
				return
			}
			d.mu.Lock()
			delete(d.pending, seq)
			d.delivered.Store(seq)
			d.mu.Unlock()
			d.delayed.queue(seq, d.ack)
		}
	}
}

func (d *orderedDelivery) close() {
	d.mu.Lock()
	d.closed = true
	d.pending = nil
	d.mu.Unlock()
	d.delayed.close()
}

// ACK coalescing delays a lone packet by at most 1ms; two deliveries flush
// immediately. Explicit duplicate/gap feedback bypasses the timer.
type delayedACK struct {
	mu      sync.Mutex
	timer   *time.Timer
	pending uint64
	count   int
	closed  bool
}

func (d *delayedACK) queue(seq uint64, send func(uint64)) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return
	}
	if seq > d.pending {
		d.pending = seq
	}
	d.count++
	if d.count >= 2 {
		seq = d.pending
		d.count = 0
		if d.timer != nil {
			d.timer.Stop()
			d.timer = nil
		}
		d.mu.Unlock()
		send(seq)
		return
	}
	if d.timer == nil {
		d.timer = time.AfterFunc(time.Millisecond, func() {
			d.mu.Lock()
			if d.closed || d.count == 0 {
				d.mu.Unlock()
				return
			}
			seq := d.pending
			d.count = 0
			d.timer = nil
			d.mu.Unlock()
			send(seq)
		})
	}
	d.mu.Unlock()
}

func (d *delayedACK) close() {
	d.mu.Lock()
	d.closed = true
	if d.timer != nil {
		d.timer.Stop()
	}
	d.mu.Unlock()
}
