package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"sync"
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

	// 1200-byte UDP records stay below common tunnel/PPPoE/CGNAT trouble zones
	// while preserving useful payload efficiency. An explicitly configured
	// ceiling below this is always respected.
	weakNetworkMtuFallback = 1200

	// mtuCommitSends is how many times the commit record is sent back to
	// back. It rides the path that just carried a full-size probe, so two
	// copies cover loss without adding latency to session setup.
	mtuCommitSends = 2

	// mtuCommitWait bounds how long the SERVER holds its upstream pump when
	// neither a commit nor client data arrives. It only ever delays
	// server-speaks-first targets for peers that never probe (old clients).
	mtuCommitWait = 2 * time.Second
)

// Probe timing. Weak public UDP links can easily exceed 300 ms during loss and
// queueing; 600 ms avoids treating ordinary jitter as an MTU black hole while
// keeping the worst-case ladder bounded. Vars remain mutable for tests.
var (
	mtuProbeTimeout  = 600 * time.Millisecond
	mtuProbeAttempts = 2
)

// mtuProbeLadder is the descending candidate list of record sizes. The last
// entry is 548 = 576 (IPv4 minimum reassembly) - 20 (IP) - 8 (UDP): the
// largest record that can never be fragmented on an IPv4 path.
var mtuProbeLadder = []int{1450, 1200, 1000, 800, 548}

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

// convergeFrameBudget pins the session's send cap to the largest record the
// path can carry. It runs AFTER the handshake and BEFORE DATA pumps start.
func (c *Client) convergeFrameBudget(ctx context.Context, sess *clientSession) {
	sess.sendCap = c.maxPkt
	if !mtuProbeEnabled(c.cfg.MtuProbe) {
		return
	}
	generation := c.dialer.Generation()
	n := c.probeCache.getFor(generation)
	if n == 0 {
		n = probePath(ctx, sess)
		if n > 0 {
			c.probeCache.storeFor(n, generation)
			c.logInfo("[Client] 📏 [mtu] path probe converged at %d-byte records (ceiling %d)", n, c.maxPkt)
		} else {
			n = conservativeMtuFallback(c.maxPkt)
			c.logWarn("[Client] 📏 [mtu] path probe received no replies; using conservative %d-byte fallback (configured ceiling %d)", n, c.maxPkt)
		}
	} else {
		c.logDebug("[Client] 📏 [mtu] using cached probe result: %d-byte records (socket generation %d)", n, generation)
	}
	if n < sess.sendCap {
		sess.sendCap = n
	}
	sendMtuCommit(sess, sess.sendCap)
}

// probePath walks the ladder and returns the largest size that survived a
// round trip, or 0 when none did (caller selects the conservative fallback).
func probePath(ctx context.Context, sess *clientSession) int {
	for _, size := range mtuLadderFor(sess.client.maxPkt) {
		for attempt := 0; attempt < mtuProbeAttempts; attempt++ {
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

	deadline := time.NewTimer(mtuProbeTimeout)
	defer deadline.Stop()
	select {
	case got := <-ch:
		return len(got) == len(payload) && string(got[:mtuProbeIDSize]) == string(payload[:mtuProbeIDSize])
	case <-deadline.C:
		return false
	case <-ctx.Done():
		return false
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
