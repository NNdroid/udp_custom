package tunnel

import "time"

// transmitBurst is the max frames one paced batch carries. It used to be 16:
// at a full 2048-frame window the batch interval was 16*rtt/window — tens of
// microseconds at LAN RTTs — so the per-batch timer wait dominated the drain
// rate and the measured send rate sat far below what the window allowed. 64
// cuts the timer round trips (and their oversleep) by 4x at the same pacing
// rate; the token bucket in waitBurst keeps the wire rate identical.
const transmitBurst = 64

// transmitQueue owns immutable DATA/parity wire slices. It never retains
// pooled control buffers. A bounded queue decouples the application pump from
// paced, batched sends without adding a batching latency timer.
type transmitQueue struct {
	queue chan []byte
	done  <-chan struct{}
	// send returns the first error, if any. It is called BEFORE before() so a
	// failed write cannot be mistaken for a successful one.
	send func([][]byte) error
	// onError is a rate-limited log hook. Frames whose write failed are still
	// marked transmitted by before(), so the retransmit loop repairs them on
	// the next RTO instead of being stranded.
	onError func(error)
	pace    func(int) bool
	before  func([][]byte)
	burst   func() int
}

func newTransmitQueue(done <-chan struct{}, send func([][]byte) error, pace func(int) bool, before func([][]byte), burst func() int, onError func(error)) *transmitQueue {
	t := &transmitQueue{queue: make(chan []byte, transmitBurst), done: done, send: send, pace: pace, before: before, burst: burst, onError: onError}
	go t.run()
	return t
}

func (t *transmitQueue) submit(wire []byte) bool {
	select {
	case <-t.done:
		return false
	case t.queue <- wire:
		return true
	}
}

func (t *transmitQueue) bestEffort(wire []byte) {
	select {
	case <-t.done:
	case t.queue <- wire:
	default:
	}
}

func (t *transmitQueue) run() {
	var batch [transmitBurst][]byte
	for {
		select {
		case <-t.done:
			return
		case batch[0] = <-t.queue:
		}
		n := 1
		// burst() returns the EFFECTIVE window, min(cwnd, credit). Bounding the
		// drain by cwnd alone made a tight receiver credit pace a full batch
		// at n*rtt/credit, which held the whole batch for several RTTs
		// before a single frame went out.
		limit := min(transmitBurst, max(1, t.burst()))
	drain:
		for n < limit {
			select {
			case batch[n] = <-t.queue:
				n++
			default:
				break drain
			}
		}
		if !t.pace(n) {
			return
		}
		if err := t.send(batch[:n]); err != nil && t.onError != nil {
			t.onError(err)
		}
		// Mark transmitted only after the datagrams left: stamping sentTime
		// before the write made a silently failed frame look sent, so it sat
		// unrepaired for a full RTO and the loss bookkeeping counted a loss
		// that never happened on the wire.
		t.before(batch[:n])
		clear(batch[:n])
	}
}

func markTransmitted(outstanding map[uint64]*unackedPkt, wires [][]byte, now time.Time) {
	for _, wire := range wires {
		if len(wire) < UDPC_HDR_SIZE || cmdOfEncoded(wire) != CMD_DATA {
			continue
		}
		seq := wireSequence(wire)
		if p := outstanding[seq]; p != nil {
			if p.queued {
				p.firstSent = now
				p.queued = false
			}
			p.sentTime = now
		}
	}
}
