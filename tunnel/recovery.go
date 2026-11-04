package tunnel

import (
	"encoding/binary"
	"math/bits"
	"sort"
	"sync"
	"time"
)

const sackPayloadSize = 66 // receive credit (2), up to 512 admission bits (64)

// sackBitmapBits is the SACK bitmap horizon: one admission bit per sequence
// above the cumulative Ack, eight 64-bit words. The repair scan in updateSACK
// covers the same horizon, as does the delivery-side bitmap snapshot.
const sackBitmapBits = uint64(8 * 64)

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
	// Window size before the most recent undoable loss() cut. loss() records
	// it unconditionally per undoable cut and clears it on every completed
	// non-undoable cut, so undoLoss can only ever revert THE most recent
	// cut — never a stale, higher value from further back. Non-zero means
	// undoLoss can revert that event.
	lastLossCut int
	feedbackNo  uint64
	lastProbe   time.Time
	// fastRepairs is a diagnostic counter of fast-repair retransmissions; the
	// weak-net pipeline test reads it to tell repair paths apart.
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
	// westwood gates the delivery-rate loss discrimination above. When false
	// every loss takes the classic AIMD halving (pre-Westwood behaviour).
	westwood bool
	// restartTo asks the next ACK to re-enter slow start, and how far to climb
	// exponentially before falling back to congestion avoidance. It is set by
	// a loss that was diagnosed as NOT queue buildup — or as nothing at all
	// because there is no RTT baseline yet. Without it a cut recovers one frame
	// per RTT, which at 50 ms RTT is 20 frames per second: a single loss on a
	// fresh session looks exactly like a stalled page.
	restartTo int
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

// initialCwnd is the flight size a fresh session starts with.
//
// 256 frames is fine — but only because it is PACED. It used to be sent
// unpaced: waitBurst returned immediately while the RTT estimator had no
// sample, so a fresh session dumped the whole window (about 300 KB) into one
// instant. That burst overruns an ordinary receive buffer, and the resulting
// loss lands exactly when it hurts most — before the first delivery-rate
// sample exists, so the flow cannot tell random loss from congestion and takes
// the classic halving. The window then crawled back one frame per RTT, which
// is what made a fresh bulk transfer stall at single-digit Mbps.
//
// Keeping the window large keeps the first flight useful (a web response and
// the first few RTTs of a bulk transfer never wait for slow start); pacing the
// opening window is what makes it safe. See bootstrapPaceRTT.
const initialCwnd = 256

// bootstrapPaceRTT is the RTT used to pace the very first window, before the
// estimator has any sample — and an unknown RTT is not a reason to skip pacing.
// It is deliberately short: spreading the opening window over a full guessed
// RTT would delay a small transfer by that guess, while 20 ms keeps the burst
// rate (~15 Mbps) low enough that no receive buffer is overrun and fast enough
// not to be felt.
const bootstrapPaceRTT = 20 * time.Millisecond

func newSendFlow(maximum int, automatic bool, westwood bool, wide bool) *sendFlow {
	ceiling := deliveryWindow
	if wide {
		ceiling = deliveryWindowWide
	}
	if automatic {
		maximum = ceiling
	}
	maximum = min(max(maximum, 1), ceiling)
	return &sendFlow{max: maximum, cwnd: min(initialCwnd, maximum), credit: ceiling, ssthresh: maximum, westwood: westwood}
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
	if f.restartTo > 0 {
		// The last cut was defensive (or made blind, before any RTT sample):
		// climb back exponentially to where the window already worked, then
		// resume congestion avoidance from there.
		f.ssthresh = max(f.cwnd, min(f.max, f.restartTo))
		f.restartTo = 0
	}
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
// Three cases, told apart by the RTT baseline and the delivery-rate estimate:
//
//   - No baseline yet (the opening burst). A drop here says nothing about the
//     queue, so cut but re-probe at once ("blind").
//   - SRTT sitting at its floor with Westwood enabled (a lossy path whose
//     bottleneck queue is empty). Trim by at most a quarter and re-probe: a
//     halving would abandon bandwidth nobody is fighting us for ("trim").
//   - SRTT inflated at least congestedFactor above the floor, i.e. a queue we
//     built. Classic AIMD halving, and no fast restart ("halve").
//
// The 1/4 dead band and the 1/4 cut floor are load-bearing, not cosmetic. The
// delivery rate is measured while our own window is the limiter, so rate*RTT
// is ALWAYS slightly below cwnd (EWMA lag + the loss fraction itself). Cutting
// to it on every loss therefore shrank the window a little on every event
// while congestion avoidance added one frame per RTT: cwnd ratcheted from 256
// down to single digits over a few seconds, throughput fell with it, and the
// falling rate pulled the next target down again. A path with one unlucky
// opening burst never recovered.
func (f *sendFlow) loss(now time.Time, rtt time.Duration, undoable bool) {
	if rtt < 10*time.Millisecond {
		rtt = 10 * time.Millisecond
	}
	if !f.lastLoss.IsZero() && now.Sub(f.lastLoss) < rtt {
		return
	}
	f.lastLoss = now
	pre := f.cwnd
	if undoable {
		// Record THIS cut's starting point unconditionally. The old
		// `cwnd > lastLossCut` guard kept a stale, higher value from an earlier
		// undoable cut, and a later non-undoable cut left it intact — an undo
		// then bounced the window ABOVE its pre-cut level and wiped the
		// legitimate reduction in between. undoLoss may only ever revert the
		// most recent cut.
		f.lastLossCut = pre
	}
	floor := max(2, f.cwnd-f.cwnd/4)
	target := max(2, f.cwnd/2)
	restartTo := 0
	switch {
	case f.minRTT <= 0:
		// No RTT baseline yet. congested() answers "yes" here purely out of
		// caution, but a loss during the opening burst is far more likely to be
		// a full receive buffer at line rate than a queue we built. Cut, then
		// re-probe immediately: without the restart the window recovers one
		// frame per RTT, which is slower than the connection that dropped it.
		restartTo = pre
	case f.westwood && !f.congested(rtt):
		// SRTT at its floor: the bottleneck queue is empty, so the drop was
		// random rather than a queue we built. Trim by at most a quarter, and
		// hold entirely when the measured BDP is already within that quarter.
		bdp := f.bdp(rtt)
		if bdp >= floor {
			return
		}
		if bdp >= 2 {
			target = max(bdp, floor)
		} else {
			target = floor
		}
		restartTo = f.max
	}
	f.ssthresh = max(2, min(f.cwnd, target))
	f.cwnd = min(f.max, f.ssthresh)
	f.growth = 0
	f.restartTo = restartTo
	if !undoable {
		// A definitive cut invalidates any earlier undoable cut point: with the
		// window already reduced for real there is nothing legitimate left to
		// undo.
		f.lastLossCut = 0
	}
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
//
// An unknown RTT is NOT a reason to skip pacing: that turned the opening
// window into one unpaced burst (see initialCwnd). It is paced against a
// deliberately short bootstrap RTT instead.
func (f *sendFlow) waitBurst(n, window int, rtt time.Duration, done <-chan struct{}) bool {
	if rtt <= 0 {
		rtt = bootstrapPaceRTT
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
// sackFastRepairMax bounds how many holes ONE SACK feedback may repair. The
// head-of-line-only repair this replaces needed one SACK round trip per hole,
// so a burst that punched five consecutive gaps trickled back at half an RTT
// per frame — exactly the loss shape a weak network throws hardest.
const sackFastRepairMax = 3

// updateSACK processes one SACK feedback frame: it admits the advertised
// out-of-order frames as selectively acknowledged and returns up to
// sackFastRepairMax wire buffers for the oldest still-missing frames inside
// the feedback horizon. Rejected (stale/corrupt) feedback reports valid=false
// and repairs nothing.
func updateSACK(flow *sendFlow, outstanding map[uint64]*unackedPkt, f *UDPCFrame, highest uint64, rtt time.Duration) (wires [][]byte, valid bool) {
	// highest == 0 means nothing was sent yet (Seq starts at 1); callers derive
	// it as sendSeq-1, which would underflow the horizon math below.
	if flow == nil || highest == 0 || len(f.Data) < 2 || len(f.Data) > sackPayloadSize || (len(f.Data)-2)%8 != 0 || f.Ack > highest || f.PacketNo <= flow.feedbackNo {
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
	// Clamp, never reject: credit beyond our ceiling is either a wide peer on
	// a wider window (harmless — window() already min()s against the flow
	// cap) or a corrupt frame. Rejecting the whole SACK over it would silently
	// disable fast repair, which is how mixed versions used to stall.
	if credit > deliveryWindowWide {
		credit = deliveryWindowWide
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
	now := time.Now()
	guard := max(5*time.Millisecond, rtt/4)
	// Repair the OLDEST holes first, up to sackFastRepairMax. The candidate
	// scan covers the same horizon the bitmap does (one admission bit per
	// sequence above f.Ack).
	var due []retryFrame
	for seq := f.Ack + 1; seq <= f.Ack+sackBitmapBits && seq <= highest; seq++ {
		p := outstanding[seq]
		if p == nil || p.sacked || p.queued {
			// queued = still sitting in the transmit queue, not yet on the
			// wire: repairing it here would double-send and burn retry budget
			// on a frame that was never lost.
			continue
		}
		if now.Sub(p.sentTime) < guard || p.retries >= clientMaxRetries {
			continue
		}
		due = append(due, retryFrame{seq, p.wire})
		if len(due) >= sackFastRepairMax {
			break
		}
	}
	if len(due) == 0 {
		return nil, true
	}
	wires = make([][]byte, 0, len(due))
	for _, d := range due {
		p := outstanding[d.seq]
		p.retries++
		p.sentTime = now
		// Advance the same backoff ladder retryDue does. This does not change
		// the fast-repair guard itself (that stays at rtt/4): it keeps the RTO
		// path from stacking another retransmission of the same frame on top
		// of the fast repair while the hole is still unfilled.
		p.rto = min(p.rto*3/2, rttMaxRTO)
		wires = append(wires, p.wire)
	}
	flow.fastRepairs += len(wires)
	flow.loss(now, rtt, false)
	return wires, true
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
