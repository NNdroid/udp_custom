package tunnel

import (
	"encoding/binary"
	"math/bits"
	"sort"
	"sync"
	"time"
)

const sackPayloadSize = 66 // receive credit (2), up to 512 admission bits (64)

// idleRetryDelay is how long the retransmit loop sleeps when nothing is
// outstanding. It bounds how long a submission on an empty window waits before
// being noticed, and it is the ceiling on the loop's idle polling rate.
const idleRetryDelay = time.Millisecond * 10

// sendFlow is guarded by the session's unackedMu. Outstanding wire buffers
// remain owned until delivery ACK, including selectively acknowledged frames.
type sendFlow struct {
	max, cwnd, credit int
	ssthresh          int
	growth            int
	lastLoss          time.Time
	// Window size before the most recent undoable loss() halving. Non-zero means
	// undoLoss can revert that event.
	lastLossCut int
	feedbackNo  uint64
	lastProbe   time.Time
	fastRepairs int
	paceMu      sync.Mutex
	nextSend    time.Time

	// Westwood-style delivery-rate estimate, in frames per second. Loss-based
	// AIMD misreads a lossy-but-uncongested path: every random wireless drop
	// halves the window even though the bottleneck queue is empty, and the
	// session never climbs back. loss() consults this estimate and the
	// min-RTT baseline to tell the two regimes apart — see loss.
	rate    float64
	rateAt  time.Time
	rateAcc int
	// minRTT is a slowly-drifting floor over observed RTT samples: it snaps
	// down to every new minimum and creeps up at 1/64 so a path change is
	// tracked within a few seconds. Zero until the first sample.
	minRTT time.Duration
}

const (
	// rateWindow is the sampling interval for the delivery-rate EWMA. Shorter
	// windows track bursts that a BDP-sized window cannot sustain anyway.
	rateWindow = 100 * time.Millisecond
	// rateIdle invalidates the estimate: without ACKs for this long the
	// measured rate no longer describes the path's current state, and a loss
	// right after an idle period must fall back to the safe halving.
	rateIdle = 2 * time.Second
	// rateAlpha is the EWMA weight of each new per-window sample.
	rateAlpha = 0.25
	// minRTTDrift is the denominator of the slow upward drift applied to the
	// RTT floor between genuine new minima: fast enough to follow a path
	// change within a few RTTs of traffic, slow enough that jittery samples
	// cannot lift the floor away from the real minimum.
	minRTTDrift = 64
	// congestedFactor is the SRTT inflation that marks a loss as congestion:
	// below it the bottleneck queue is (near) empty and the drop was random
	// wireless loss, above it the queue is being built up by this flow.
	congestedFactor = 2
)

// initialCwnd is the flight size a fresh session starts with. It used to be 64
// frames, which capped upload at 64*record/RTT (about 7 Mbps at 100 ms RTT)
// and took ~450 RTTs to climb to the window cap; TCP opens connections with a
// much larger window for exactly this reason. Web traffic is bursty, so the
// window spends most of its life below ssthresh and grows additively anyway,
// which means the extra in-flight frames cost nothing but room in `unacked`.
const initialCwnd = 256

func newSendFlow(maximum int, automatic bool) *sendFlow {
	if automatic {
		maximum = deliveryWindow
	}
	maximum = min(max(maximum, 1), deliveryWindow)
	return &sendFlow{max: maximum, cwnd: min(initialCwnd, maximum), credit: deliveryWindow, ssthresh: maximum}
}

func (f *sendFlow) window() int { return min(f.cwnd, f.credit) }

// observeRTT maintains the min-RTT baseline from one RTT sample. It snaps to
// every new minimum and drifts up slowly otherwise, so the congestion test in
// loss() reflects the path's current empty-queue latency, not a stale early
// outlier.
func (f *sendFlow) observeRTT(sample time.Duration) {
	if sample <= 0 {
		return
	}
	if f.minRTT <= 0 || sample < f.minRTT {
		f.minRTT = sample
		return
	}
	f.minRTT += (sample - f.minRTT) / minRTTDrift
}

// sampleRate folds n newly acknowledged frames into the delivery-rate EWMA.
// The rate is what Westwood restores the window to on non-congestion loss, so
// it must describe sustainable throughput, not a single ACK burst: samples
// integrate over at least rateWindow.
func (f *sendFlow) sampleRate(n int, now time.Time) {
	if n <= 0 {
		return
	}
	if f.rateAt.IsZero() {
		f.rateAt = now
		f.rateAcc = n
		return
	}
	elapsed := now.Sub(f.rateAt)
	if elapsed > rateIdle {
		// Stale: start a fresh window rather than diluting the estimate.
		f.rate = 0
		f.rateAt = now
		f.rateAcc = n
		return
	}
	f.rateAcc += n
	if elapsed < rateWindow {
		return
	}
	inst := float64(f.rateAcc) / elapsed.Seconds()
	if f.rate <= 0 {
		f.rate = inst
	} else {
		f.rate += (inst - f.rate) * rateAlpha
	}
	f.rateAt = now
	f.rateAcc = 0
}

func (f *sendFlow) acknowledged(n int) {
	f.sampleRate(n, time.Now())
	if f.cwnd < f.ssthresh {
		f.cwnd = min(f.max, f.cwnd+n)
		return
	}
	f.growth += n
	if f.growth >= f.cwnd {
		f.growth -= f.cwnd
		f.cwnd = min(f.max, f.cwnd+1)
	}
}

// loss halves the window once per RTT on CONGESTION loss. undoable marks a cut
// made on the evidence of an RTO firing, which is later proven wrong by
// undoLoss when the ACK turns out to have predated the retransmit: the timeout
// was jitter, not loss. SACK gaps are not marked, because three later
// admissions are stronger evidence than a bare timeout.
//
// Losses that arrive WITHOUT queue buildup are treated differently (Westwood
// style): on a lossy wireless path the bottleneck queue is empty — SRTT sits
// at its floor — so a halving would just abandon bandwidth nobody is fighting
// us for. There the window is restored to the measured BDP (delivery rate ×
// SRTT) instead, never above the current window. Losses with the SRTT at
// least congestedFactor above the min-RTT floor, or without a usable rate
// estimate, keep the classic halving.
func (f *sendFlow) loss(now time.Time, rtt time.Duration, undoable bool) {
	if rtt < 10*time.Millisecond {
		rtt = 10 * time.Millisecond
	}
	if !f.lastLoss.IsZero() && now.Sub(f.lastLoss) < rtt {
		return
	}
	f.lastLoss = now
	if undoable && f.cwnd > f.lastLossCut {
		f.lastLossCut = f.cwnd
	}
	if !f.congested(rtt) {
		if bdp := f.bdp(rtt); bdp >= 2 {
			f.ssthresh = max(2, min(f.cwnd, bdp))
			f.cwnd = min(f.max, f.ssthresh)
			f.growth = 0
			return
		}
	}
	f.ssthresh = max(2, f.cwnd/2)
	f.cwnd = min(f.max, f.ssthresh)
	f.growth = 0
}

// congested reports whether SRTT inflation marks this loss as congestion.
// Without a baseline yet the conservative answer is yes.
func (f *sendFlow) congested(rtt time.Duration) bool {
	return f.minRTT <= 0 || rtt >= f.minRTT*congestedFactor
}

// bdp converts the delivery-rate estimate into a frame count for the given
// RTT. A stale estimate returns 0: after rateIdle without ACKs the number
// describes a path that may no longer exist.
func (f *sendFlow) bdp(rtt time.Duration) int {
	if f.rate <= 0 || f.rateAt.IsZero() || time.Since(f.rateAt) > rateIdle {
		return 0
	}
	n := int(f.rate * rtt.Seconds())
	if n < 0 {
		return 0
	}
	return n
}

// undoLoss reverts the most recent undoable halving. A retransmit whose ACK
// lands inside one SRTT of the retransmit cannot have been answered by that
// retransmit, so the timeout that produced it was spurious. Without this, a
// jittery path whose RTO barely clears its own RTT halves the window on nearly
// every window of traffic and the session never climbs out of collapse.
//
// ssthresh is deliberately left at the halved value: the window is restored to
// where it was, but the flow stays in congestion avoidance, so the next genuine
// loss still halves once.
func (f *sendFlow) undoLoss() bool {
	cut := f.lastLossCut
	f.lastLossCut = 0
	if cut <= f.cwnd {
		return false
	}
	f.cwnd = min(f.max, cut)
	f.growth = 0
	return true
}

// undoIfSpurious retracts the last undoable halving when this ACK proves the
// RTO that caused it was noise: the ACK landed inside one smoothed RTT of the
// packet's most recent send, so it cannot be that send's answer. An earlier copy
// of the same frame got through, which means the timeout was jitter.
//
// Returns true only if it actually reverted a halving, so a caller undoing at
// most one event per ACK can stop looking.
func (f *sendFlow) undoIfSpurious(p *unackedPkt, srtt time.Duration) bool {
	if p == nil || p.retries == 0 || srtt <= 0 {
		return false
	}
	if time.Since(p.sentTime) >= srtt {
		return false
	}
	return f.undoLoss()
}

// Pace a small burst rather than creating one timer per datagram. All DATA,
// repair DATA and FEC share this budget; control feedback is never held here.
func (f *sendFlow) waitBurst(n, window int, rtt time.Duration, done <-chan struct{}) bool {
	if rtt <= 0 {
		return true
	}
	f.paceMu.Lock()
	now := time.Now()
	when := f.nextSend
	if when.Before(now) {
		when = now
	}
	f.nextSend = when.Add(time.Duration(n) * rtt / time.Duration(max(window, 1)))
	delay := when.Sub(now)
	f.paceMu.Unlock()
	if delay <= 0 {
		return true
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-done:
		return false
	}
}

func encodeSACK(credit uint16, bitmap uint64, extra ...uint64) []byte {
	words := [8]uint64{bitmap}
	copy(words[1:], extra)
	n := len(words)
	for n > 0 && words[n-1] == 0 {
		n--
	}
	p := make([]byte, 2+n*8)
	binary.BigEndian.PutUint16(p, credit)
	for i := 0; i < n; i++ {
		binary.BigEndian.PutUint64(p[2+i*8:], words[i])
	}
	return p
}

// updateSACK rejects feedback outside the sent sequence range. Authenticated
// but reordered control records cannot regress receive credit.
func updateSACK(flow *sendFlow, outstanding map[uint64]*unackedPkt, f *UDPCFrame, highest uint64, rtt time.Duration) (wire []byte, valid bool) {
	if flow == nil || len(f.Data) < 2 || len(f.Data) > sackPayloadSize || (len(f.Data)-2)%8 != 0 || f.Ack > highest || f.PacketNo <= flow.feedbackNo {
		return nil, false
	}
	var words [8]uint64
	count := 0
	for i := 0; i < (len(f.Data)-2)/8; i++ {
		words[i] = binary.BigEndian.Uint64(f.Data[2+i*8:])
		if words[i] != 0 && highest-f.Ack < uint64(i*64+bits.Len64(words[i])) {
			return nil, false
		}
		count += bits.OnesCount64(words[i])
	}
	credit := int(binary.BigEndian.Uint16(f.Data))
	if credit > deliveryWindow {
		return nil, false
	}
	flow.feedbackNo = f.PacketNo
	flow.credit = credit
	for word, bitsLeft := range words {
		for bitsLeft != 0 {
			bit := bits.TrailingZeros64(bitsLeft)
			if p := outstanding[f.Ack+uint64(word*64+bit)+1]; p != nil {
				p.sacked = true
			}
			bitsLeft &= bitsLeft - 1
		}
	}
	// Three later admissions are evidence of a gap, not a single reordered
	// datagram. Give FEC and natural reordering a quarter RTT to fill it.
	if count < 3 {
		return nil, true
	}
	seq := f.Ack + 1
	p := outstanding[seq]
	now := time.Now()
	guard := max(5*time.Millisecond, rtt/4)
	if p == nil || p.sacked || now.Sub(p.sentTime) < guard || p.retries >= clientMaxRetries {
		return nil, true
	}
	p.retries++
	p.sentTime = now
	// Advance the same backoff ladder retryDue does: a fast repair burns one
	// retry like anything else, so leaving rto alone would consume the whole
	// 15-retry budget at the guard cadence and abandon a live path in seconds.
	p.rto = min(p.rto*3/2, rttMaxRTO)
	flow.fastRepairs++
	flow.loss(now, rtt, false)
	return p.wire, true
}

type retryFrame struct {
	seq  uint64
	wire []byte
}

func notifyRetry(ch chan struct{}) {
	if ch != nil {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// retryBurstMax bounds how many frames one wake repairs. It used to be 16,
// which made a 256-frame stall need ~16 wakes at >=1 ms each before recovery
// resumed; 64 drains a full window in one or two.
const retryBurstMax = 64

// retryDue repairs the frames whose RTO expired, and reports how long to wait
// before the next wake — in ONE pass over the outstanding map. The loop used to
// do up to four scans plus four lock round trips per wake (retryDue,
// nextRetryDelay, and two nested creditProbeInterval passes), mostly
// re-reading a map nothing had changed in. It also returns whether a credit
// probe is due, so the loop never re-locks to discover that.
func retryDue(outstanding map[uint64]*unackedPkt, now time.Time, maximumRTO time.Duration, flow *sendFlow, rtt time.Duration) ([][]byte, bool, time.Duration, bool) {
	// Most wakeups only register a fresh transmission or feedback. Do not
	// allocate a sorting buffer until a packet actually needs repair.
	var due []retryFrame
	next := idleRetryDelay
	for seq, p := range outstanding {
		if p.queued || p.sacked {
			continue
		}
		remaining := p.rto - now.Sub(p.sentTime)
		if remaining >= 0 {
			if remaining < next {
				next = remaining
			}
			continue
		}
		if p.retries >= clientMaxRetries {
			return nil, true, 0, false
		}
		due = append(due, retryFrame{seq, p.wire})
	}
	interval, probe := creditProbeInterval(flow, outstanding)
	if probe {
		if d := interval - now.Sub(flow.lastProbe); d < next {
			next = d
		}
		flow.lastProbe = now
	}
	sort.Slice(due, func(i, j int) bool { return due[i].seq < due[j].seq })
	if len(due) > retryBurstMax {
		due = due[:retryBurstMax]
	}
	wires := make([][]byte, 0, len(due))
	for _, d := range due {
		p := outstanding[d.seq]
		p.retries++
		p.sentTime = now
		p.rto = min(p.rto*3/2, maximumRTO)
		if p.rto < next { // this frame's own backed-off deadline
			next = p.rto
		}
		wires = append(wires, p.wire)
	}
	if len(wires) > 0 && flow != nil {
		// An RTO firing is weak evidence: on a path whose RTO only barely clears
		// its own RTT the timeout is usually jitter. Mark the cut undoable so
		// handleAck can retract it once it proves the ACK predated the retransmit.
		flow.loss(now, rtt, true)
	}
	return wires, false, max(time.Millisecond, next), probe && len(outstanding) > 0
}
