package tunnel

import (
	"encoding/binary"
	"math/bits"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// ackMaxCoalesce caps the suppression window for a high-latency path: delaying a
// cumulative ACK by half an RTT is the point of coalescing, but past 100 ms it
// turns into visible repair latency for no further savings.
const ackMaxCoalesce = 100 * time.Millisecond

// ackGapUrgent is the gap size at which the sender's SACK fast repair fires (see
// updateSACK). A SACK carrying that much information is never deferred.
const ackGapUrgent = 3

// ackCoalesceInterval is how long a cumulative ACK may wait for more to
// coalesce into it. Bounded below so a fresh session still ACKs promptly, and
// above by the sender's own RTO: the RTO is at least 1.5*SRTT (see
// rttEstimator.Sample), so half an SRTT always beats the sender's next timeout.
// A delay past the RTO would buy packet savings at the cost of a spurious
// retransmit every time.
func ackCoalesceInterval(srtt time.Duration) time.Duration {
	iv := srtt / 2
	if iv < time.Millisecond {
		iv = time.Millisecond
	}
	if iv > ackMaxCoalesce {
		iv = ackMaxCoalesce
	}
	return iv
}

// sackGaps counts the bits a snapshot bitmap would advertise as gaps.
func sackGaps(bitmap [8]uint64) int {
	n := 0
	for _, w := range bitmap {
		n += bits.OnesCount64(w)
	}
	return n
}

// ackCoalescer decides whether a cumulative ACK/SACK deserves its own datagram.
//
// A standalone feedback frame is only ever worth sending to move the peer's
// cumulative ACK past where this end last told it. Nothing new means nothing
// sent; an advance inside the suppression window means nothing sent now, with the
// newest advance remembered for flushDue. Zero value is ready to use.
type ackCoalescer struct {
	mu        sync.Mutex
	lastValue uint64    // highest cumulative Ack this end has communicated
	lastAt    time.Time // when lastValue was put on the wire
	pending   uint64    // highest cumulative advance still unsent, if any
}

// commitSent records that a record carrying cumulative Ack ackSeq is now on the
// wire, so any standalone feedback at or below it is pure waste. Every record
// carries the Ack field, which is what makes this exact. Callers must only call
// it after the write succeeded — committing a value that never left the socket
// would suppress the ACK the peer needs and stall the sender for an RTO.
func (c *ackCoalescer) commitSent(ackSeq uint64) {
	if ackSeq == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if ackSeq > c.lastValue {
		c.lastValue = ackSeq
	}
	if ackSeq >= c.pending {
		c.pending = 0
	}
}

// commitSentBatch raises the watermark to the largest cumulative Ack carried by
// the batch. Called from the transmit queue's post-write hook, so every frame
// here did go out.
func (c *ackCoalescer) commitSentBatch(wires [][]byte) {
	ackSeq := uint64(0)
	for _, wire := range wires {
		if len(wire) < UDPC_HDR_SIZE {
			continue
		}
		if a := wireAck(wire); a > ackSeq {
			ackSeq = a
		}
	}
	c.commitSent(ackSeq)
}

// claim authorises one feedback datagram carrying at least ackSeq. urgent skips
// the suppression window entirely, which is how a gap-bearing SACK keeps the
// sender's fast repair at its normal latency.
//
// An urgent claim is authorised even when ackSeq has not advanced, because a
// SACK's value is not only its cumulative Ack: the bitmap can carry admissions
// the peer has never heard and that alone triggers a fast repair. Gating on the
// Ack would silently drop exactly those, and the loss would then be repaired by
// a timeout instead — which is the whole regression this function is for.
// Non-urgent claims still require an advance, since a SACK with no new bitmap
// and no new Ack carries nothing.
func (c *ackCoalescer) claim(ackSeq uint64, iv time.Duration, urgent bool) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if urgent {
		c.commitLocked(ackSeq)
		return true
	}
	if ackSeq == 0 || ackSeq <= c.lastValue {
		return false
	}
	if ackSeq > c.pending {
		c.pending = ackSeq
	}
	if time.Since(c.lastAt) < iv {
		return false
	}
	c.commitLocked(ackSeq)
	return true
}

// flushDue reports the advance a deferred claim may now put on the wire and how
// long until the next one if something is still held back. A zero ackSeq means
// there is nothing to emit; the wait value is how the retransmit loop caps its
// own sleep, so a deferred ACK is never held past the peer's next retransmit.
func (c *ackCoalescer) flushDue(iv time.Duration) (ackSeq uint64, wait time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending != 0 && c.pending > c.lastValue && time.Since(c.lastAt) >= iv {
		// Read pending before committing: commitLocked clears it.
		ackSeq = c.pending
		c.commitLocked(c.pending)
	}
	if c.pending == 0 || c.pending <= c.lastValue {
		return ackSeq, 0
	}
	if wait = iv - time.Since(c.lastAt); wait < 0 {
		wait = 0
	}
	return ackSeq, wait
}

func (c *ackCoalescer) commitLocked(ackSeq uint64) {
	if ackSeq > c.lastValue {
		c.lastValue = ackSeq
	}
	c.pending = 0
	c.lastAt = time.Now()
}

func wireSequence(wire []byte) uint64 { return binary.BigEndian.Uint64(wire[20:28]) }
func wireAck(wire []byte) uint64      { return binary.BigEndian.Uint64(wire[28:36]) }

func creditProbeInterval(flow *sendFlow, outstanding map[uint64]*unackedPkt) (time.Duration, bool) {
	if flow == nil {
		return 0, false
	}
	sacked, gap := false, false
	for _, p := range outstanding {
		if p.sacked {
			sacked = true
		} else if !p.queued {
			gap = true
		}
	}
	if sacked && gap {
		return 25 * time.Millisecond, true
	}
	// Probe zero credit even after PONG cumulatively ACKed the final frame:
	// losing the separate window-opening SACK must not strand the next write.
	return 100 * time.Millisecond, flow.credit == 0 || sacked
}

func (s *clientSession) initTransmitter() {
	s.tx = newTransmitQueue(s.closeChan, s.client.dialer.sendBatch, func(n int) bool {
		return s.paceBurst(n)
	}, func(wires [][]byte) {
		s.markBatchTransmitted(wires)
	}, s.burstWindow, func(err error) {
		s.client.logWarn("[Client] [Session 0x%08X] ⚠️ batch send failed: %v (affected frames will be repaired by the retransmit loop)", s.sid, err)
	})
}

// paceBurst paces one batch against the effective window. Guarded by
// unackedMu by the caller's closure only; the lock is held here so cwnd and
// credit are read consistently.
func (s *clientSession) paceBurst(n int) bool {
	if s.flow == nil {
		return true
	}
	s.unackedMu.Lock()
	window := s.flow.window()
	s.unackedMu.Unlock()
	return s.flow.waitBurst(n, window, s.rttEst.SRTT(), s.closeChan)
}

func (s *clientSession) markBatchTransmitted(wires [][]byte) {
	s.unackedMu.Lock()
	markTransmitted(s.unacked, wires, time.Now())
	s.unackedMu.Unlock()
	// Each frame's cumulative Ack is now on the wire, so repeating it in a
	// standalone ACK would be redundant.
	s.ackCoalesce.commitSentBatch(wires)
	notifyRetry(s.retryWake)
}

// burstWindow is the effective flight size: the smaller of the congestion
// window and the receiver's advertised credit.
func (s *clientSession) burstWindow() int {
	s.unackedMu.Lock()
	defer s.unackedMu.Unlock()
	if s.flow != nil {
		return s.flow.window()
	}
	return 16
}

func (s *ServerSession) initTransmitter() {
	s.tx = newTransmitQueue(s.closeChan, s.sendToSessionBatch, func(n int) bool {
		return s.paceBurst(n)
	}, func(wires [][]byte) {
		s.markBatchTransmitted(wires)
	}, s.burstWindow, func(err error) {
		s.server.logWarn("[Server] [Session 0x%08X] ⚠️ batch send failed: %v (affected frames will be repaired by the retransmit loop)", s.sessionID, err)
	})
}

func (s *ServerSession) paceBurst(n int) bool {
	if s.flow == nil {
		return true
	}
	s.unackedMu.Lock()
	window := s.flow.window()
	s.unackedMu.Unlock()
	return s.flow.waitBurst(n, window, s.rttEst.SRTT(), s.closeChan)
}

func (s *ServerSession) markBatchTransmitted(wires [][]byte) {
	s.unackedMu.Lock()
	markTransmitted(s.unacked, wires, time.Now())
	s.unackedMu.Unlock()
	// Each frame's cumulative Ack is now on the wire, so repeating it in a
	// standalone ACK would be redundant.
	s.ackCoalesce.commitSentBatch(wires)
	notifyRetry(s.retryWake)
}

func (s *ServerSession) burstWindow() int {
	s.unackedMu.Lock()
	defer s.unackedMu.Unlock()
	if s.flow != nil {
		return s.flow.window()
	}
	return 16
}

// sendToSessionBatch ships one batch. Every branch degrades to per-frame
// writes, so there is no observable failure to report: the caller marks the
// frames transmitted either way and the retransmit loop repairs anything the
// kernel did not accept.
func (s *ServerSession) sendToSessionBatch(wires [][]byte) error {
	port := int(atomic.LoadInt32(&s.lastOrigPort))
	s.pathMu.RLock()
	addr := s.pathAddrs[port].addr
	s.pathMu.RUnlock()
	if !addr.IsValid() { // Preserve existing LRU route selection on the cold path.
		for _, wire := range wires {
			s.sendToSession(wire)
		}
		return nil
	}
	if port > 0 && port != s.server.bindPort {
		pc, err := s.server.sockPool.Get(port)
		if err != nil {
			for _, wire := range wires {
				s.sendToSession(wire)
			}
			return nil
		}
		pc.refs.Add(1)
		dst := make([]netip.AddrPort, len(wires))
		for i := range dst {
			dst[i] = addr
		}
		n, _ := writeUDPBatch(pc.conn, wires, dst)
		if pc.refs.Add(-1) == 0 && int(pc.pool.total.Load()) > pc.pool.limit {
			pc.pool.reclaimOverflow()
		}
		s.server.sendViaPort.Add(uint64(n))
		for _, wire := range wires[n:] {
			if _, err := pc.WriteToUDPAddrPort(wire, addr); err == nil {
				s.server.sendViaPort.Add(1)
			}
		}
		return nil
	}
	dst := make([]netip.AddrPort, len(wires))
	for i := range dst {
		dst[i] = addr
	}
	n, _ := writeUDPBatch(s.server.conn, wires, dst)
	s.server.sendViaMain.Add(uint64(n))
	for _, wire := range wires[n:] {
		s.server.replyFromOrigPort(0, addr, wire)
	}
	return nil
}

// sendBatch selects the same n:n tuples as Send and groups frames by source
// socket. Repair preserves each selected destination port and never resends a
// prefix that sendmmsg already accepted.
func (d *SpreadDialer) sendBatch(wires [][]byte) error {
	type selected struct {
		wire []byte
		port int
	}
	groups := make(map[int][]selected)
	for _, wire := range wires {
		idx, port := d.Next()
		if idx < 0 {
			return ErrNoRoute
		}
		groups[idx] = append(groups[idx], selected{wire, port})
	}
	var firstErr error
	for idx, group := range groups {
		d.destMu.RLock()
		addr := d.serverAddr
		d.destMu.RUnlock()
		data := make([][]byte, len(group))
		dst := make([]netip.AddrPort, len(group))
		for i, p := range group {
			data[i] = p.wire
			dst[i] = netip.AddrPortFrom(addr, uint16(p.port))
		}
		sock := d.socks[idx]
		sock.mu.RLock()
		conn := sock.conn
		n := 0
		if conn != nil {
			n, _ = writeUDPBatch(conn, data, dst)
		}
		sock.mu.RUnlock()
		for _, p := range group[n:] {
			if err := d.sendAtPort(idx, p.port, p.wire); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}
