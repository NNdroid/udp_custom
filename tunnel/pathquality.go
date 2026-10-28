package tunnel

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// PathScorer biases destination-port selection toward healthier remote ports.
// Implementations must be safe for concurrent use and must never block the
// send path: Weight is called once per outgoing datagram.
type PathScorer interface {
	// Weight returns the relative selection weight for a port in [0, 1].
	// 1 means as good as an unobserved port; 0 means never select it.
	Weight(port int) float64
	// Observe records one outcome for a port. lost=true means a packet on
	// that path needed retransmission (the original never arrived).
	Observe(port int, lost bool)
}

// Fixed-point layout for lock-free loss estimates: lossBits is the EWMA loss
// in [0, 2^pathQualityFracBits], i.e. value = bits >> pathQualityFracBits.
const (
	pathQualityFracBits = 20
	// pathQualityAlphaShift is the EWMA denominator (1/32): the receive side
	// produces plenty of samples, so convergence beats smoothing here.
	pathQualityAlphaShift = 5
	// pathQualityFloor is the minimum Weight a known-bad port keeps, so it
	// still receives probe traffic and can recover instead of going dark.
	pathQualityFloor = 0.02
	// pathQualityRecovery is the silence interval after which a port's loss
	// estimate halves. A port nobody sends to (because it scored badly) must
	// not stay condemned forever: the floor keeps probing it, and if those
	// probes stop being lost the estimate decays away through observations.
	// The halving additionally covers ports the floor never reaches (e.g. the
	// scorer was disabled for a while).
	pathQualityRecovery = 30 * time.Second
)

// pathQuality is the client-side, receive-driven scorer. It keys on the
// REMOTE port the server replies from, which — by the origdst mirror — is the
// same port the client addressed, so a score identifies the (local socket,
// remote port) NAT mapping the traffic actually flowed through.
//
// The signal is deliberately conservative: only frames the SERVER
// retransmitted (a duplicate sequence) count as lost. Reordered-but-fresh
// frames count as healthy, because reorder is a scheduling artifact, not
// evidence the datagram dropped. One caveat: the server also retransmits when
// our ACK was lost, and ACKs leave on randomly chosen ports, so a fraction of
// uplink ACK loss is misattributed to whatever port the retransmitted DATA
// arrived on. That is noise, not bias — it spreads uniformly across ports and
// washes out of the EWMA.
type pathQuality struct {
	// scores maps port -> estimate. sync.Map because Weight runs on every
	// send while Observe runs on every received DATA frame: the fast path is
	// a load plus two atomic loads, no lock, no allocation.
	scores sync.Map // map[int]*portScore
}

type portScore struct {
	// loss is the EWMA of the lost indicator in fixed point, updated by a
	// CAS loop so concurrent receivers cannot lose updates.
	loss atomic.Int64
	// at is the unix-nano timestamp of the last observation, used to decay
	// stale estimates toward healthy in Weight.
	at atomic.Int64
}

func newPathQuality() *pathQuality { return &pathQuality{} }

func (q *pathQuality) Observe(port int, lost bool) {
	if port <= 0 {
		return
	}
	v, _ := q.scores.LoadOrStore(port, &portScore{})
	ps := v.(*portScore)
	sample := int64(0)
	if lost {
		sample = 1 << pathQualityFracBits
	}
	for {
		old := ps.loss.Load()
		newBits := old + (sample-old)>>pathQualityAlphaShift
		if ps.loss.CompareAndSwap(old, newBits) {
			break
		}
	}
	ps.at.Store(time.Now().UnixNano())
}

func (q *pathQuality) Weight(port int) float64 {
	v, ok := q.scores.Load(port)
	if !ok {
		return 1
	}
	ps := v.(*portScore)
	loss := float64(ps.loss.Load()) / (1 << pathQualityFracBits)
	// Stale estimates decay by half per recovery interval so an old bad
	// streak cannot pin a port that is healthy again now.
	if age := time.Since(time.Unix(0, ps.at.Load())); age > pathQualityRecovery {
		loss *= math.Pow(0.5, float64(age/pathQualityRecovery))
	}
	if loss <= 0 {
		return 1
	}
	if loss >= 1 {
		return pathQualityFloor
	}
	return pathQualityFloor + (1-pathQualityFloor)*(1-loss)
}

// snapshot copies the current per-port loss estimates for diagnostics
// (debug logging on session close, embedder dashboards).
func (q *pathQuality) snapshot() map[int]float64 {
	out := make(map[int]float64)
	q.scores.Range(func(k, v any) bool {
		ps := v.(*portScore)
		out[k.(int)] = float64(ps.loss.Load()) / (1 << pathQualityFracBits)
		return true
	})
	return out
}
