package tunnel

import (
	"sync"
	"sync/atomic"
	"time"
)

const deliveryWindow = 512

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
	if limit <= 0 || limit > deliveryWindow {
		limit = deliveryWindow
	}
	d := &orderedDelivery{pending: make(map[uint64][]byte), limit: limit, wake: make(chan struct{}, 1), done: done, write: write, fail: fail, ack: ack}
	go d.run()
	return d
}

func (d *orderedDelivery) offer(seq uint64, payload []byte) bool {
	if seq == 0 {
		return false
	}
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return false
	}
	ack := d.delivered.Load()
	if seq <= ack {
		d.mu.Unlock()
		d.ack(ack)
		return true
	}
	if _, ok := d.pending[seq]; ok {
		d.mu.Unlock()
		return true
	}
	// Reserve the gap's slot even when later packets arrive first. Bound both
	// the number of frames and the sequence distance from the delivered prefix.
	if seq-ack > uint64(d.limit) || len(d.pending) >= d.limit {
		d.mu.Unlock()
		return false
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
	return true
}

func (d *orderedDelivery) snapshot() (ack uint64, bitmap [8]uint64, credit uint16) {
	d.mu.Lock()
	defer d.mu.Unlock()
	ack = d.delivered.Load()
	for seq := range d.pending {
		if seq > ack && seq-ack <= deliveryWindow {
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
