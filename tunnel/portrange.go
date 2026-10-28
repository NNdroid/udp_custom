package tunnel

import (
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// SelectorMode controls how PortSelector.Next distributes destination ports.
type SelectorMode int

const (
	// SelectorRandom deals ports from a shuffle bag: the whole candidate set
	// is Fisher-Yates shuffled, consumed one port per packet in sequence, and
	// reshuffled once exhausted. Every round therefore hits every port exactly
	// once (perfect short-term coverage, unlike iid sampling's P*ln(P)
	// coupon-collector tail), while independent reshuffles between rounds keep
	// the sequence unpredictable.
	SelectorRandom SelectorMode = iota
	// SelectorRoundRobin steps through the port list in sorted order, wrapping around.
	SelectorRoundRobin
)

// shuffleBagMaxPorts caps how large a candidate set a per-socket shuffle bag
// may hold. A full-range spread (paths=0) wider than this falls back to plain
// iid sampling: a bag of 65k ports x 32 sockets would cost megabytes of
// per-socket memory for no practical gain — long-run uniformity is identical.
const shuffleBagMaxPorts = 4096

// ParseServerAddrWithRange parses a server address that may carry a UDP
// destination-port range, e.g.:
//
//	"1.1.1.1:25000-25499"
//	"1.1.1.1:36712"   (single port, still valid)
//	"[::1]:1024-2000" (IPv6 with brackets)
//
// It returns the host and the sorted, de-duplicated, adjacent-merged list of
// ports. The SERVER keeps listening on a SINGLE internal UDP port and relies on
// a firewall rule (nftables/iptables DNAT) to redirect the whole range onto
// that port.
//
// The range is a CLIENT-side contract: the client sends every packet to a
// (different) port inside the range, which spreads the (dst-IP, dst-port)
// tuples and defeats per-destination-port UDP rate limiting on the path.
//
// The SERVER does need one accommodation even though it still binds a single
// port. Because DNAT collapses the whole range onto that port, an arriving
// datagram carries no hint of which port the client actually addressed. The
// server therefore enables IP_RECVORIGDSTADDR to recover the pre-DNAT
// destination and replies through a socket bound to it. See origdst_linux.go
// and sendTo in server.go. Without this, every reply leaves from the listening
// port and a client behind anything stricter than full-cone NAT drops it.
func ParseServerAddrWithRange(raw string) (host string, ports []int, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil, fmt.Errorf("empty server address")
	}
	h, portSpec, splitErr := net.SplitHostPort(raw)
	if splitErr != nil {
		return "", nil, fmt.Errorf("invalid address %q: %w", raw, splitErr)
	}
	ports, err = ParsePortRangeSpec(portSpec)
	if err != nil {
		return "", nil, fmt.Errorf("invalid port spec in %q: %w", raw, err)
	}
	return h, ports, nil
}

// ParsePortRangeSpec expands a comma-separated port spec into a sorted,
// de-duplicated list of ports. Each segment is either a single port ("36712")
// or an inclusive range ("1024-23000"). Example: "1024-23000,25000-30000".
func ParsePortRangeSpec(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("empty port spec")
	}
	seen := make(map[int]struct{})
	var ports []int
	for _, seg := range strings.Split(spec, ",") {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			return nil, fmt.Errorf("empty segment in port spec %q", spec)
		}
		if i := strings.Index(seg, "-"); i >= 0 {
			lo, err1 := strconv.Atoi(strings.TrimSpace(seg[:i]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(seg[i+1:]))
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("invalid port range %q", seg)
			}
			if lo < 1 || hi > 65535 {
				return nil, fmt.Errorf("port out of range [1,65535] in %q", seg)
			}
			if lo > hi {
				return nil, fmt.Errorf("range start %d greater than end %d in %q", lo, hi, seg)
			}
			for p := lo; p <= hi; p++ {
				if _, ok := seen[p]; !ok {
					seen[p] = struct{}{}
					ports = append(ports, p)
				}
			}
		} else {
			p, err := strconv.Atoi(seg)
			if err != nil {
				return nil, fmt.Errorf("invalid port %q", seg)
			}
			if p < 1 || p > 65535 {
				return nil, fmt.Errorf("port %d out of range [1,65535]", p)
			}
			if _, ok := seen[p]; !ok {
				seen[p] = struct{}{}
				ports = append(ports, p)
			}
		}
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("no ports parsed from %q", spec)
	}
	sort.Ints(ports)
	return ports, nil
}

// FormatPortList renders an expanded port list back into a compact,
// adjacent-merged, comma-separated spec, e.g. "1024-23000,25000-30000".
func FormatPortList(ports []int) string {
	pr, err := NewPortRange(ports)
	if err != nil {
		return ""
	}
	return pr.String()
}

// portInterval is a [lo,hi] inclusive range of ports.
type portInterval struct {
	lo, hi int
}

// PortInterval is one inclusive [Lo,Hi] range of ports, as returned by
// PortRange.Intervals.
type PortInterval struct {
	Lo, Hi int
}

// PortRange is a parsed, de-duplicated, sorted, adjacent-merged set of UDP
// destination ports. It is the compact representation backing PortSelector.
type PortRange struct {
	intervals []portInterval
	total     int
}

// Intervals returns the merged, sorted [Lo,Hi] intervals of the range.
func (pr *PortRange) Intervals() []PortInterval {
	if pr == nil {
		return nil
	}
	out := make([]PortInterval, 0, len(pr.intervals))
	for _, iv := range pr.intervals {
		out = append(out, PortInterval{Lo: iv.lo, Hi: iv.hi})
	}
	return out
}

// NewPortRange builds a PortRange from an expanded port list, merging adjacent
// ports into intervals.
func NewPortRange(ports []int) (*PortRange, error) {
	if len(ports) == 0 {
		return nil, fmt.Errorf("no ports provided")
	}
	sorted := make([]int, len(ports))
	copy(sorted, ports)
	sort.Ints(sorted)
	if sorted[0] < 1 || sorted[len(sorted)-1] > 65535 {
		return nil, fmt.Errorf("port out of range (must be 1-65535)")
	}
	var ivs []portInterval
	lo, hi := sorted[0], sorted[0]
	for _, p := range sorted[1:] {
		if p == hi {
			continue
		}
		if p == hi+1 {
			hi = p
			continue
		}
		ivs = append(ivs, portInterval{lo, hi})
		lo, hi = p, p
	}
	ivs = append(ivs, portInterval{lo, hi})
	pr := &PortRange{intervals: ivs}
	for _, iv := range ivs {
		pr.total += iv.hi - iv.lo + 1
	}
	return pr, nil
}

// Total returns how many ports are in the range.
func (pr *PortRange) Total() int { return pr.total }

// Contains reports whether port is part of the range. Intervals are sorted and
// non-overlapping, so a binary search over them is exact.
func (pr *PortRange) Contains(port int) bool {
	lo, hi := 0, len(pr.intervals)-1
	for lo <= hi {
		mid := int(uint(lo+hi) >> 1)
		iv := pr.intervals[mid]
		switch {
		case port < iv.lo:
			hi = mid - 1
		case port > iv.hi:
			lo = mid + 1
		default:
			return true
		}
	}
	return false
}

// PortAt returns the i-th port in flattened sorted order (0 <= i < Total()).
func (pr *PortRange) PortAt(i int) int {
	if pr.total == 0 {
		return 0
	}
	if i < 0 {
		i = 0
	}
	if i >= pr.total {
		i = pr.total - 1
	}
	for _, iv := range pr.intervals {
		n := iv.hi - iv.lo + 1
		if i < n {
			return iv.lo + i
		}
		i -= n
	}
	return pr.intervals[len(pr.intervals)-1].hi
}

// String renders the range back as a comma-separated, colon-ranged spec,
// e.g. "1024-23000,25000-30000".
func (pr *PortRange) String() string {
	if len(pr.intervals) == 0 {
		return ""
	}
	parts := make([]string, 0, len(pr.intervals))
	for _, iv := range pr.intervals {
		if iv.lo == iv.hi {
			parts = append(parts, strconv.Itoa(iv.lo))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", iv.lo, iv.hi))
		}
	}
	return strings.Join(parts, ",")
}

// PortSelector spreads outgoing packets across the port range. It is intended
// to be used on the CLIENT: call Next() once per packet to obtain the
// destination port, then WriteTo the server using that port. This is the
// "any port per packet" contract that defeats per-destination-port UDP
// rate limiting.
type PortSelector struct {
	pr   *PortRange
	mode SelectorMode
	rr   atomic.Uint64
	rng  *rand.Rand
	mu   sync.Mutex

	// Shuffle-bag state for SelectorRandom when the range fits in memory.
	// bag holds every port of the range in shuffled order; bagPos marks the
	// next entry. nil = iid fallback (round-robin mode or oversized range).
	bag    []uint16
	bagPos int
}

// NewPortSelector creates a selector over pr. The RNG seed is drawn from
// crypto/rand so the random spread does not start from a predictable sequence.
func NewPortSelector(pr *PortRange, mode SelectorMode) *PortSelector {
	s := &PortSelector{
		pr:   pr,
		mode: mode,
		rng:  rand.New(rand.NewSource(randomSeed())),
	}
	if mode == SelectorRandom && pr != nil && pr.total > 0 && pr.total <= shuffleBagMaxPorts {
		s.fillBag()
	}
	return s
}

var fallbackSeed atomic.Uint64

func randomSeed() int64 {
	var seed [8]byte
	if _, err := crand.Read(seed[:]); err == nil {
		return int64(binary.LittleEndian.Uint64(seed[:]))
	}
	// Preserve availability if the OS RNG fails while ensuring concurrently
	// created selectors do not all receive the same zero seed.
	return time.Now().UnixNano() ^ int64(fallbackSeed.Add(1))
}

// fillBag expands the range into the shuffle bag (called once, under no lock,
// before the selector is published).
func (s *PortSelector) fillBag() {
	bag := make([]uint16, 0, s.pr.total)
	for _, iv := range s.pr.intervals {
		for p := iv.lo; p <= iv.hi; p++ {
			bag = append(bag, uint16(p))
		}
	}
	s.rng.Shuffle(len(bag), func(i, j int) { bag[i], bag[j] = bag[j], bag[i] })
	s.bag = bag
}

// Next returns the destination port for the next outgoing packet. It is cheap
// and safe for concurrent use. Random mode deals from a shuffle bag: each
// round covers every port exactly once, then reshuffles; oversized ranges
// fall back to an independent uniform draw per call. RoundRobin mode cycles
// through all ports in order.
//
// IMPORTANT: this must be called per packet, NOT once at connect time. The whole
// point is to vary the destination port on every datagram so the path's
// per-(dst-IP,dst-port) rate limiter sees many distinct tuples.
func (s *PortSelector) Next() int {
	if s.pr == nil || s.pr.total == 0 {
		return 0
	}
	if s.mode == SelectorRoundRobin {
		i := s.rr.Add(1) - 1
		return s.pr.PortAt(int(i % uint64(s.pr.total)))
	}
	return s.nextUniform()
}

// nextUniform draws the next candidate under the selector's RNG lock. With a
// shuffle bag it pops the next entry, reshuffling when the bag is exhausted;
// without one (oversized range) it is a plain iid draw.
func (s *PortSelector) nextUniform() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bag == nil {
		return s.pr.PortAt(s.rng.Intn(s.pr.total))
	}
	if s.bagPos >= len(s.bag) {
		s.rng.Shuffle(len(s.bag), func(i, j int) { s.bag[i], s.bag[j] = s.bag[j], s.bag[i] })
		s.bagPos = 0
	}
	port := int(s.bag[s.bagPos])
	s.bagPos++
	return port
}

// NextWeighted biases port choice with a PathScorer using rejection sampling:
// draw a uniform candidate, accept it with probability Weight(port), retry a
// bounded number of times, then accept the last draw regardless. This is O(1)
// per call, allocation-free, and keeps the selector's own RNG (no shared
// state with other sockets). The result is not an exactly proportional sample
// of the weighted distribution, but it concentrates traffic on healthy ports
// with the right asymptotics and always keeps the scorer's floor share of
// probe traffic flowing to bad ports. The attempt bound is high enough that
// even a range where most ports score badly still routes the overwhelming
// majority of packets to the healthy minority.
//
// Candidates come from the same shuffle bag as Next (when the range fits):
// draws within a round are without replacement, so rejection sampling never
// re-tries the same bad port twice in one pass and the bag keeps draining
// evenly across rounds.
func (s *PortSelector) NextWeighted(scorer PathScorer) int {
	if s.pr == nil || s.pr.total == 0 {
		return 0
	}
	if scorer == nil {
		return s.Next()
	}
	const maxAttempts = 16
	port := s.nextUniform()
	w := scorer.Weight(port)
	if w >= 1 {
		return port
	}
	for i := 1; i < maxAttempts; i++ {
		s.mu.Lock()
		accept := s.rng.Float64() < w
		s.mu.Unlock()
		if accept {
			return port
		}
		port = s.nextUniform()
		w = scorer.Weight(port)
	}
	return port
}

// portRangeOf parses a port-range spec (either bare "lo-hi" or "host:lo-hi")
// into a *PortRange, returning nil when it cannot be parsed.
// PortRangeOf is the exported form used by the CLI shell to parse the
// config-file port_range into a runtime PortRange.
func PortRangeOf(spec string) *PortRange {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil
	}
	ports, err := ParsePortRangeSpec(spec)
	if err != nil {
		if _, hp, e2 := ParseServerAddrWithRange(spec); e2 == nil {
			ports = hp
		} else {
			return nil
		}
	}
	pr, err := NewPortRange(ports)
	if err != nil {
		return nil
	}
	return pr
}
