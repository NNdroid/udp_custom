package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"
)

// MTU probing (see MTU_PROBE_DESIGN.md).
//
// The client drives the probe: it sends an authenticated CMD_MTU_PROBE whose
// PAYLOAD LENGTH is the record size under test, and the server echoes it byte
// for byte. One successful round trip therefore proves BOTH directions can
// carry that size. The client walks a descending ladder. If a severely lossy
// path answers none of the probes, the client now falls back conservatively
// instead of assuming the largest configured record size.
//
// The converged size is published to the server with CMD_MTU_COMMIT, because
// the server cannot know whether its own reply arrived. The commit opens the
// server's upstream gate: until then the server holds target->client traffic,
// so no oversized frame can ever be encoded and stranded (a retransmission
// reuses its exact encoded bytes and cannot be re-chunked).
const (
	mtuProbeCacheTTL = 10 * time.Minute

	// weakNetworkMtuFallback is used only when NO rung of the ladder produced
	// an echo. Because the ladder already walked down to mtuProbeFloor, a zero
	// result means even the never-fragment size was dropped — so the fallback
	// must be that same floor. Falling back to a size we just observed failing
	// would strand every large frame on a path that cannot carry it.
	weakNetworkMtuFallback = mtuProbeFloor

	// mtuCommitSends is how many times the commit record is sent back to
	// back. It rides the path that just carried a full-size probe, so two
	// copies cover loss without adding latency to session setup.
	mtuCommitSends = 2

	// mtuCommitWait bounds how long the SERVER holds its upstream pump when
	// neither a commit nor client data arrives. The client now sends an
	// immediate floor commit, so this only matters for peers that never probe
	// (old clients).
	mtuCommitWait = 2 * time.Second

	// mtuReprobeInterval is how often an idle session re-checks its record
	// cap. The cost is one small probe per interval on a quiet session.
	mtuReprobeInterval = 30 * time.Second
)

// Probe timing. Weak public UDP links can easily exceed 300 ms during loss and
// queueing; 600 ms avoids treating ordinary jitter as an MTU black hole while
// keeping the worst-case ladder bounded.
//
// Both stay mutable for tests, which is also why they are atomic: a test swaps
// them to fast values and restores them in its own Cleanup, and by then an
// earlier test's client may still be walking the ladder. Plain vars there are a
// data race, caught by CI's race jobs.
const (
	defaultProbeTimeout  = 600 * time.Millisecond
	defaultProbeAttempts = 2
)

var (
	mtuProbeTimeout  atomic.Int64 // nanoseconds
	mtuProbeAttempts atomic.Int32
)

func init() {
	mtuProbeTimeout.Store(int64(defaultProbeTimeout))
	mtuProbeAttempts.Store(defaultProbeAttempts)
}

// mtuProbeFloor is the largest record that can never be fragmented on an IPv4
// path: 576 (IPv4 minimum reassembly) - 20 (IP) - 8 (UDP). It is the last rung
// of the ladder, the value used when no rung answers, and the conservative
// upper bound the client commits before probing so the server's budget is capped
// from the first byte.
const mtuProbeFloor = 548

// mtuProbeLadder is the descending candidate list of record sizes. The 1392
// rung exists because a WireGuard-class path (MTU 1420) can carry exactly 1392
// bytes and nothing more: without it such a path would converge at 1200 and
// spend ~13% of every record's capacity on nothing. The final entry is
// mtuProbeFloor.
var mtuProbeLadder = []int{1450, 1392, 1200, 1000, 800, mtuProbeFloor}

func mtuLadderFor(ceiling int) []int {
	ladder := make([]int, 0, len(mtuProbeLadder)+1)
	ladder = append(ladder, ceiling)
	for _, v := range mtuProbeLadder {
		if v < ceiling {
			ladder = append(ladder, v)
		}
	}
	return ladder
}

func mtuProbeEnabled(p *bool) bool { return p == nil || *p }

// conservativeMtuFallback is used only when no probe reply survives. It must
// never increase an operator-supplied ceiling.
func conservativeMtuFallback(ceiling int) int {
	if ceiling <= weakNetworkMtuFallback {
		return ceiling
	}
	return weakNetworkMtuFallback
}

// mtuProbeCache memoizes the converged size per Client. generation ties the
// result to the current SpreadDialer socket generation: rebuilding a socket can
// change route, NAT mapping, interface, or path MTU, so the old result must not
// survive that transition.
type mtuProbeCache struct {
	mu         sync.Mutex
	n          int
	at         time.Time
	generation uint64
}

func (m *mtuProbeCache) getFor(generation uint64) int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.generation != generation {
		return 0
	}
	if m.n > 0 && time.Since(m.at) < mtuProbeCacheTTL {
		return m.n
	}
	return 0
}

func (m *mtuProbeCache) storeFor(n int, generation uint64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.n = n
	m.at = time.Now()
	m.generation = generation
}

// get/store keep the small internal test surface backward-compatible. New
// production code always uses the generation-aware variants above.
func (m *mtuProbeCache) get() int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	generation := m.generation
	m.mu.Unlock()
	return m.getFor(generation)
}

func (m *mtuProbeCache) store(n int) {
	if m == nil {
		return
	}
	m.mu.Lock()
	generation := m.generation
	m.mu.Unlock()
	m.storeFor(n, generation)
}

// mtuInitialCap is the conservative record cap committed before the ladder
// starts: the never-fragment floor, never above the operator's ceiling.
func mtuInitialCap(maxPkt int) int {
	if maxPkt <= mtuProbeFloor {
		return maxPkt
	}
	return mtuProbeFloor
}

// mtuStartCap is the cap a session sends AT with before the probe converges.
// Probing starts at the floor because a record sent above the path's capacity
// is stranded for good — a retransmission reuses its exact encoded bytes. With
// probing disabled the operator pinned the cap, so use it verbatim.
func mtuStartCap(maxPkt int, probe bool) int {
	if !probe {
		return maxPkt
	}
	return mtuInitialCap(maxPkt)
}

// convergeFrameBudget pins the session's send cap to the largest record the
// path can carry. It runs AFTER the handshake, CONCURRENTLY with the DATA
// pumps: the session already sends at the floor, so the cap only ever RAISES
// here. Raising is safe under traffic (frames not yet encoded simply get more
// room); the idle re-probe may also lower it, and raise it back the same way.
func (c *Client) convergeFrameBudget(ctx context.Context, sess *clientSession) {
	// The dial context must not reach the probe: a DialTunnel caller whose
	// context covers only the dial (the usual WithTimeout+defer-cancel
	// pattern) would cancel it right after establishment, fail every rung,
	// and strand the session at the no-answer floor for its whole lifetime.
	// The probe's lifetime is the SESSION's, so only sess.closeChan may abort
	// it (see probeOnce).
	ctx = context.WithoutCancel(ctx)

	if !mtuProbeEnabled(c.cfg.MtuProbe) {
		// Probing disabled means the operator pinned the cap. Publish it right
		// away so the server does not spend its mtuCommitWait budget guessing:
		// the server caps its budget to the committed value, which is exactly
		// what the operator asked for.
		sendMtuCommit(sess, c.maxPkt)
		return
	}

	// Commit the never-fragment floor BEFORE walking the ladder. This opens the
	// server's upstream gate at the first round trip instead of letting it sit
	// on mtuCommitWait: on a cold cache the ladder can take up to
	// len(ladder)*attempts*timeout (6 seconds), so an old gate would let the
	// server encode frames well above what the path can carry, and a
	// retransmission reuses its exact bytes so those frames can never be
	// re-chunked. The floor is a strict upper bound on capability, so it is
	// always safe to publish and the converged value only ever tightens it.
	sess.sendCap.Store(int32(mtuInitialCap(c.maxPkt)))
	sendMtuCommit(sess, mtuInitialCap(c.maxPkt))

	generation := c.dialer.Generation()
	n := c.probeCache.getFor(generation)
	if n == 0 {
		n = probePath(ctx, sess)
		if n > 0 {
			c.probeCache.storeFor(n, generation)
			c.logInfo("[Client] 📏 [mtu] path probe converged at %d-byte records (ceiling %d, needs IPv4 MTU >= %d)",
				n, c.maxPkt, n+ipv4DatagramOverhead)
		} else {
			n = conservativeMtuFallback(c.maxPkt)
			c.logWarn("[Client] 📏 [mtu] path probe received no replies; using conservative %d-byte fallback (configured ceiling %d)", n, c.maxPkt)
		}
	} else {
		c.logDebug("[Client] 📏 [mtu] using cached probe result: %d-byte records (socket generation %d)", n, generation)
	}
	n = clampMtuCap(n, c.maxPkt)
	if n != int(sess.sendCap.Load()) {
		sess.sendCap.Store(int32(n))
		sendMtuCommit(sess, n)
	}

	// The converged cap would otherwise be frozen for the session's lifetime, so
	// an MTU drop mid-session (VPN flap, cellular handover) kept the session
	// sending oversized records until it reconnected. Re-check it while idle.
	go sess.reprobeIdle()
}

// clampMtuCap keeps a converged size inside the usable range.
func clampMtuCap(n, maxPkt int) int {
	if n < mtuInitialCap(maxPkt) {
		return mtuInitialCap(maxPkt)
	}
	if n > maxPkt {
		return maxPkt
	}
	return n
}

// lowerSendCap applies a shrunken record cap. It is used only by the idle
// re-probe, which is the one caller that may observe the path degrading after
// traffic has already started: a shrink can never strand an in-flight frame
// (its bytes were already sized by the larger cap). The raise direction is
// raiseSendCap below, which the same idle re-probe uses to recover a cap that
// was lowered by a transient loss burst.
func (s *clientSession) lowerSendCap(n int) {
	for {
		cur := int(s.sendCap.Load())
		if n >= cur {
			return
		}
		if s.sendCap.CompareAndSwap(int32(cur), int32(n)) {
			return
		}
	}
}

// raiseSendCap grows the record cap back. The idle re-probe uses it to recover
// from a shrink: the new size must have just round-tripped (a verified probe),
// which is the same evidence the setup probe requires, and the pump loops read
// the cap per record, so growing it only gives not-yet-encoded frames more
// room — exactly the safety argument that lets the setup probe raise the cap
// under live traffic.
func (s *clientSession) raiseSendCap(n int) {
	for {
		cur := int(s.sendCap.Load())
		if n <= cur {
			return
		}
		if s.sendCap.CompareAndSwap(int32(cur), int32(n)) {
			return
		}
	}
}

// reprobeIdle re-checks the path's record capacity while the session sits
// idle. It probes only the current cap, so an active flow is never perturbed,
// and it may shrink the cap when the current size stops round-tripping — or
// raise it back one rung at a time when a previously unreachable size starts
// working again (a shrink from a transient loss burst must not be permanent).
func (s *clientSession) reprobeIdle() {
	c := s.client
	if !mtuProbeEnabled(c.cfg.MtuProbe) {
		return
	}
	ladder := mtuLadderFor(c.maxPkt)
	ticker := time.NewTicker(mtuReprobeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.closeChan:
			return
		case <-ticker.C:
		}
		if s.isClosed() {
			return
		}
		s.reprobeIdleTick(ladder)
	}
}

// reprobeIdleTick runs one idle re-probe cycle. Split from reprobeIdle so the
// ladder walk is testable without waiting on the 30-second ticker.
func (s *clientSession) reprobeIdleTick(ladder []int) {
	c := s.client
	// Probe only when the session has been quiet: an active flow already
	// tells us the path works, and probing one would just add noise.
	if time.Since(s.lastActivity()) < mtuReprobeInterval/2 {
		return
	}
	floor := mtuInitialCap(c.maxPkt)
	cur := int(s.sendCap.Load())
	if cur > floor {
		if probeOnce(context.Background(), s, cur) {
			// The current size still carries. Opportunistically verify the
			// next rung up: a cap lowered by a transient loss burst must be
			// able to recover once the path heals, instead of sticking for
			// the rest of the session.
			s.tryRaiseOneRung(ladder, cur)
			return
		}
		// The current size no longer round-trips. Walk down from the largest
		// rung STRICTLY below it. (The ladder is descending, so "first entry
		// below cur" — not "break on the first entry at or above cur", which
		// would find nothing and slam the session straight to the floor.)
		below := largestRungBelow(ladder, cur)
		for below > 0 && below > floor {
			if probeOnce(context.Background(), s, below) {
				break
			}
			below = largestRungBelow(ladder, below)
		}
		target := below
		if target <= 0 {
			target = floor
		}
		if target < cur {
			s.lowerSendCap(target)
			sendMtuCommit(s, target)
			c.logWarn("[Client] [Session 0x%08X] 📏 [mtu] idle re-probe: path no longer carries %d-byte records; dropping to %d",
				s.sid, cur, target)
		}
		return
	}
	// Already at the floor. The floor may be the no-answer fallback rather
	// than a verified property of the path, so probe one rung up: a session
	// that probed during a total blackout recovers instead of being stuck at
	// 548-byte records forever.
	s.tryRaiseOneRung(ladder, cur)
}

// tryRaiseOneRung probes the next ladder rung ABOVE cur and, when it round
// trips, raises the session cap and republishes it to the server. The probe
// echo proves BOTH directions can carry the new size, so the commit is as
// verified as the setup probe's.
func (s *clientSession) tryRaiseOneRung(ladder []int, cur int) {
	c := s.client
	next := nextLadderRungAbove(ladder, cur)
	if next <= 0 || next > c.maxPkt {
		return
	}
	if !probeOnce(context.Background(), s, next) {
		return
	}
	s.raiseSendCap(next)
	sendMtuCommit(s, next)
	c.logInfo("[Client] [Session 0x%08X] 📏 [mtu] idle re-probe: path now carries %d-byte records; raising from %d",
		s.sid, next, cur)
}

// largestRungBelow returns the largest ladder entry strictly below cur, or 0
// when cur is at or below the last rung. The ladder is DESCENDING.
func largestRungBelow(ladder []int, cur int) int {
	for _, v := range ladder {
		if v < cur {
			return v
		}
	}
	return 0
}

// nextLadderRungAbove returns the smallest ladder entry strictly above cur,
// or 0 when cur is at or above the ceiling rung. The ladder is DESCENDING.
func nextLadderRungAbove(ladder []int, cur int) int {
	prev := 0
	for _, v := range ladder {
		if v <= cur {
			return prev
		}
		prev = v
	}
	return prev
}

// probePath walks the ladder and returns the largest size that survived a
// round trip, or 0 when none did (caller selects the conservative fallback).
func probePath(ctx context.Context, sess *clientSession) int {
	for _, size := range mtuLadderFor(sess.client.maxPkt) {
		// The ladder runs concurrently with the pumps now, so a session that
		// died while the first rungs were unanswered would otherwise spend the
		// remaining ~6 seconds probing a peer that is already gone.
		if sess.isClosed() {
			return 0
		}
		for attempt := 0; attempt < int(mtuProbeAttempts.Load()); attempt++ {
			if probeOnce(ctx, sess, size) {
				return size
			}
			if ctx.Err() != nil {
				return 0
			}
		}
	}
	return 0
}

func probeOnce(ctx context.Context, sess *clientSession, size int) bool {
	// One probe at a time: probeOnce publishes its reply channel in the shared
	// sess.probeReply slot, so two overlapping probes would hand each other's
	// echoes to the wrong waiter. The setup probe and the idle re-probe share
	// this guard.
	sess.probeMu.Lock()
	defer sess.probeMu.Unlock()
	payloadCap := size - UDPC_HDR_SIZE - UDPC_TRAILER_SIZE
	if payloadCap < mtuProbeIDSize || payloadCap > mtuProbeMaxPayload {
		return false
	}
	payload := make([]byte, payloadCap)
	if _, err := rand.Read(payload[:mtuProbeIDSize]); err != nil {
		return false
	}

	ch := make(chan []byte, 1)
	sess.probeReply.Store(&ch)
	defer func() { sess.probeReply.Store(nil) }()

	frame := &UDPCFrame{
		Magic:     sess.client.magic,
		Version:   UDPC_VERSION,
		Cmd:       CMD_MTU_PROBE,
		SessionID: sess.sid,
		Data:      payload,
	}
	if !sess.sendControl(frame, sess.client.dialer.Send) {
		return false
	}

	deadline := time.NewTimer(time.Duration(mtuProbeTimeout.Load()))
	defer deadline.Stop()
	for {
		select {
		case got := <-ch:
			// Only an echo of OUR probe counts. Anything else in the channel
			// is a stale echo from an earlier attempt that outlived its
			// deadline and was handed to this probe's slot: keep waiting
			// rather than burning the attempt on it.
			if len(got) == len(payload) && string(got[:mtuProbeIDSize]) == string(payload[:mtuProbeIDSize]) {
				return true
			}
			continue
		case <-deadline.C:
			return false
		case <-sess.closeChan:
			// The session died mid-ladder: stop probing a peer that is gone
			// instead of spending the remaining rungs' worth of timeouts.
			return false
		case <-ctx.Done():
			return false
		}
	}
}

func sendMtuCommit(sess *clientSession, size int) {
	if size <= 0 || size > maxPktCeiling {
		return
	}
	payload := make([]byte, mtuCommitSize)
	binary.BigEndian.PutUint16(payload, uint16(size))
	frame := &UDPCFrame{
		Magic:     sess.client.magic,
		Version:   UDPC_VERSION,
		Cmd:       CMD_MTU_COMMIT,
		SessionID: sess.sid,
		Data:      payload,
	}
	for i := 0; i < mtuCommitSends; i++ {
		if !sess.sendControl(frame, sess.client.dialer.Send) {
			return
		}
	}
}
