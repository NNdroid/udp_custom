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
// carry that size. The client walks a descending ladder — the common case is
// a hit on the first step, so probing costs a single round trip and no extra
// latency; a hostile or old peer that never answers costs the ladder walk and
// ends in the configured max_pkt, i.e. today's behaviour.
//
// The converged size is published to the server with CMD_MTU_COMMIT, because
// the server cannot know whether its own reply arrived. The commit opens the
// server's upstream gate: until then the server holds target->client traffic,
// so no oversized frame can ever be encoded and stranded (a retransmission
// reuses its exact encoded bytes and cannot be re-chunked).
const (
	// mtuProbeCacheTTL ... plus the two knobs below are vars so tests can
	// shrink the ladder walk; production values are the documented defaults.
	mtuProbeCacheTTL = 10 * time.Minute

	// mtuCommitSends is how many times the commit record is sent back to
	// back. It rides the path that just carried a full-size probe, so two
	// copies cover loss without adding latency to session setup.
	mtuCommitSends = 2

	// mtuCommitWait bounds how long the SERVER holds its upstream pump when
	// neither a commit nor client data arrives. It only ever delays
	// server-speaks-first targets for peers that never probe (old clients).
	mtuCommitWait = 2 * time.Second
)

// Probe timing. Vars (not consts) so the test suite can shrink the worst-case
// ladder walk from ~3s to milliseconds.
var (
	mtuProbeTimeout  = 300 * time.Millisecond
	mtuProbeAttempts = 2
)

// mtuProbeLadder is the descending candidate list of record sizes. The last
// entry is 548 = 576 (IPv4 minimum reassembly) - 20 (IP) - 8 (UDP): the
// largest record that can never be fragmented on an IPv4 path.
var mtuProbeLadder = []int{1450, 1200, 1000, 800, 548}

// mtuLadderFor returns the sizes to try for a given ceiling: the ceiling
// itself first (so an operator-configured max_pkt below 1450 is probed
// directly), then every ladder step strictly below it.
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

// mtuProbeEnabled resolves the tri-state switch: nil (field absent) means
// enabled, so the zero value of a config literal keeps probing on.
func mtuProbeEnabled(p *bool) bool { return p == nil || *p }

// mtuProbeCache memoizes the converged size per Client (one server address per
// client, one path per server). A nil cache (bare-literal Client) simply
// disables caching.
type mtuProbeCache struct {
	mu sync.Mutex
	n  int
	at time.Time
}

func (m *mtuProbeCache) get() int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.n > 0 && time.Since(m.at) < mtuProbeCacheTTL {
		return m.n
	}
	return 0
}

func (m *mtuProbeCache) store(n int) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.n = n
	m.at = time.Now()
}

// convergeFrameBudget pins the session's send cap to the largest record the
// path can carry. It runs AFTER the handshake (it needs the session keys) and
// BEFORE the session's pump loops start, so no DATA frame is ever encoded at a
// size the path cannot carry. The result is immutable for the session's
// lifetime; re-probing only affects later sessions.
func (c *Client) convergeFrameBudget(ctx context.Context, sess *clientSession) {
	sess.sendCap = c.maxPkt
	if !mtuProbeEnabled(c.cfg.MtuProbe) {
		return
	}
	n := c.probeCache.get()
	if n == 0 {
		n = probePath(ctx, sess)
		if n > 0 {
			c.probeCache.store(n)
			c.logInfo("[Client] 📏 [mtu] path probe converged at %d-byte records (ceiling %d)", n, c.maxPkt)
		} else {
			n = c.maxPkt
			c.logDebug("[Client] 📏 [mtu] path probe found no answer: falling back to max_pkt=%d", c.maxPkt)
		}
	} else {
		c.logDebug("[Client] 📏 [mtu] using cached probe result: %d-byte records", n)
	}
	if n < sess.sendCap {
		sess.sendCap = n
	}
	sendMtuCommit(sess, sess.sendCap)
}

// probePath walks the ladder and returns the largest size that survived a
// round trip, or 0 when none did (caller falls back to the configured cap).
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

// probeOnce sends one probe of the given record size and waits for the echo.
func probeOnce(ctx context.Context, sess *clientSession, size int) bool {
	payloadCap := size - UDPC_HDR_SIZE - UDPC_TRAILER_SIZE
	if payloadCap < mtuProbeIDSize || payloadCap > mtuProbeMaxPayload {
		return false
	}
	payload := make([]byte, payloadCap)
	if _, err := rand.Read(payload[:mtuProbeIDSize]); err != nil {
		return false
	}

	// Dispatch hands the prober a COPY of the echo payload on this channel;
	// it is created per probe so a late echo cannot satisfy the next size.
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

// sendMtuCommit publishes the converged record size to the server. The server
// cannot derive it alone (it never learns whether its echo arrived), and it
// needs the value to cap its own sends and to open the upstream gate.
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
