package tunnel

import (
	"sync"
	"time"
)

// rttEstimator implements an RFC 6298 RTT/timeout estimator (Jacobson/Karels)
// with Karn's rule: only samples RTT for packets that were never retransmitted.
//
// Pure in-memory, safe for concurrent use, and wire-protocol agnostic — the
// client side (myssh) carries an identical copy so both ends adapt independently
// without changing the frame format.
type rttEstimator struct {
	mu      sync.Mutex
	srtt    time.Duration // smoothed RTT
	rttvar  time.Duration // RTT variance
	rto     time.Duration // current retransmission timeout
	hasData bool          // whether at least one sample has been taken
	minRTT  time.Duration // lower clamp on the computed RTO
	maxRTT  time.Duration // upper clamp on the computed RTO
}

// Default estimator bounds, shared by client and server.
//
// minRTO is the RFC 6298 floor, not the 200 ms value Linux ships with. The RTO
// is srtt+4*rttvar, so on a healthy 1 ms LAN the estimator computes about 1 ms
// and the old 200 ms floor clamped it UP by two orders of magnitude: every lost
// datagram waited 200 ms before its first repair, and the 1.5x backoff ladder
// (200/300/450/675/1012/1518 ms) burned all 15 retries in roughly a minute. A
// 1 ms floor makes that ladder sub-second, which is what lets a dead path fail
// fast and reconnect instead of limping. maxRTO still caps the worst case, so a
// genuinely dead link cannot spin the retransmit loop.
const (
	rttInitialGuess = 200 * time.Millisecond // RTO before the first sample lands
	rttMinRTO       = 1 * time.Millisecond   // RFC 6298 floor
	rttMaxRTO       = 10 * time.Second       // backoff cap; also the give-up point
)

// newRTTEstimator builds an estimator. `initial` is used before any sample is
// collected (acts as the first RTO). `minRTT`/`maxRTT` clamp the computed RTO.
func newRTTEstimator(initial, minRTT, maxRTT time.Duration) *rttEstimator {
	return &rttEstimator{
		srtt:    initial,
		rttvar:  initial / 2,
		rto:     initial,
		hasData: false,
		minRTT:  minRTT,
		maxRTT:  maxRTT,
	}
}

// newDefaultRTTEstimator is the estimator both ends build a session with.
func newDefaultRTTEstimator() *rttEstimator {
	return newRTTEstimator(rttInitialGuess, rttMinRTO, rttMaxRTO)
}

// Sample feeds one RTT measurement (usually now - firstSent of an ACKed packet).
// Per Karn's rule, callers must only pass samples for never-retransmitted packets.
func (e *rttEstimator) Sample(rtt time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Defensive: a non-positive RTT is a clock anomaly / misuse and must not
	// corrupt the estimator state.
	if rtt <= 0 {
		return
	}

	if !e.hasData {
		// First sample: RFC 6298 step 2.2.
		e.srtt = rtt
		e.rttvar = rtt / 2
		e.hasData = true
	} else {
		// Subsequent samples: RFC 6298 step 2.3 (alpha=1/8, beta=1/4).
		errVal := rtt - e.srtt
		e.srtt += errVal / 8
		e.rttvar += (absDuration(errVal) - e.rttvar) / 4
	}

	e.rto = e.srtt + 4*e.rttvar
	if e.rto < e.minRTT {
		e.rto = e.minRTT
	}
	if e.rto > e.maxRTT {
		e.rto = e.maxRTT
	}
}

// RTO returns the current retransmission timeout.
func (e *rttEstimator) RTO() time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.rto
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// SRTT is zero until a real, non-retransmitted sample arrives.
func (e *rttEstimator) SRTT() time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.hasData {
		return 0
	}
	return e.srtt
}
