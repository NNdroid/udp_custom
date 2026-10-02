package tunnel

import "time"

// transmitQueue owns immutable DATA/parity wire slices. It never retains
// pooled control buffers. A bounded queue decouples the application pump from
// paced, batched sends without adding a batching latency timer.
type transmitQueue struct {
	queue  chan []byte
	done   <-chan struct{}
	send   func([][]byte)
	pace   func(int) bool
	before func([][]byte)
	burst  func() int
}

func newTransmitQueue(done <-chan struct{}, send func([][]byte), pace func(int) bool, before func([][]byte), burst func() int) *transmitQueue {
	t := &transmitQueue{queue: make(chan []byte, 32), done: done, send: send, pace: pace, before: before, burst: burst}
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
	var batch [16][]byte
	for {
		select {
		case <-t.done:
			return
		case batch[0] = <-t.queue:
		}
		n := 1
		limit := min(16, max(1, t.burst()))
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
		t.before(batch[:n])
		t.send(batch[:n])
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
