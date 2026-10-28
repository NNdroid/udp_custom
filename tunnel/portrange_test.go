package tunnel

import (
	"testing"
)

func TestPortRangeContains(t *testing.T) {
	ports, err := ParsePortRangeSpec("1024-1025,23000,25000-25002,36712")
	if err != nil {
		t.Fatalf("ParsePortRangeSpec: %v", err)
	}
	pr, err := NewPortRange(ports)
	if err != nil {
		t.Fatalf("NewPortRange: %v", err)
	}

	in := []int{1024, 1025, 23000, 25000, 25001, 25002, 36712}
	for _, p := range in {
		if !pr.Contains(p) {
			t.Errorf("Contains(%d) = false, want true (range %s)", p, pr)
		}
	}
	out := []int{0, 1, 1023, 1026, 22999, 23001, 24999, 25003, 36711, 36713, 65535}
	for _, p := range out {
		if pr.Contains(p) {
			t.Errorf("Contains(%d) = true, want false (range %s)", p, pr)
		}
	}

	// Contains must agree with PortAt over the whole flattened range.
	for i := 0; i < pr.Total(); i++ {
		if p := pr.PortAt(i); !pr.Contains(p) {
			t.Fatalf("PortAt(%d)=%d not reported by Contains", i, p)
		}
	}
}

// TestShuffleBagCoversAllPortsEachRound pins the shuffle-bag contract of
// SelectorRandom: the first Total() draws must hit every port exactly once
// (perfect short-term coverage, unlike iid sampling's coupon-collector tail),
// and the second round must cover them again without duplicates.
func TestShuffleBagCoversAllPortsEachRound(t *testing.T) {
	ports, err := ParsePortRangeSpec("100-107,200,300-301")
	if err != nil {
		t.Fatalf("ParsePortRangeSpec: %v", err)
	}
	pr, err := NewPortRange(ports)
	if err != nil {
		t.Fatalf("NewPortRange: %v", err)
	}
	sel := NewPortSelector(pr, SelectorRandom)
	total := pr.Total()

	for round := 0; round < 3; round++ {
		seen := make(map[int]int, total)
		for i := 0; i < total; i++ {
			p := sel.Next()
			if !pr.Contains(p) {
				t.Fatalf("round %d draw %d: port %d outside range", round, i, p)
			}
			seen[p]++
			if n := seen[p]; n > 1 {
				t.Fatalf("round %d: port %d drawn %d times before round completed", round, p, n)
			}
		}
		if len(seen) != total {
			t.Fatalf("round %d: covered %d ports, want %d", round, len(seen), total)
		}
	}
}

// TestShuffleBagReshuffleAvoidsIdenticalSequences checks that consecutive
// rounds are independently shuffled (otherwise the mode degrades to
// round-robin in disguise, a predictable cycle).
func TestShuffleBagReshuffleAvoidsIdenticalSequences(t *testing.T) {
	pr, err := NewPortRange([]int{10, 11, 12, 13, 14, 15, 16, 17})
	if err != nil {
		t.Fatalf("NewPortRange: %v", err)
	}
	sel := NewPortSelector(pr, SelectorRandom)
	total := pr.Total()

	draw := func(n int) []int {
		out := make([]int, n)
		for i := range out {
			out[i] = sel.Next()
		}
		return out
	}
	first := draw(total)
	second := draw(total)
	same := true
	for i := range first {
		if first[i] != second[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("two consecutive rounds drew identical sequences")
	}
}

// TestShuffleBagFallbackForOversizedRange verifies the iid fallback: a range
// above shuffleBagMaxPorts must not allocate a bag and must still return
// in-range ports.
func TestShuffleBagFallbackForOversizedRange(t *testing.T) {
	ports := make([]int, 0, shuffleBagMaxPorts+100)
	for p := 10000; p < 10000+shuffleBagMaxPorts+100; p++ {
		ports = append(ports, p)
	}
	pr, err := NewPortRange(ports)
	if err != nil {
		t.Fatalf("NewPortRange: %v", err)
	}
	sel := NewPortSelector(pr, SelectorRandom)
	if sel.bag != nil {
		t.Fatalf("bag allocated for %d-port range, want nil (iid fallback)", pr.Total())
	}
	for i := 0; i < 100; i++ {
		if p := sel.Next(); !pr.Contains(p) {
			t.Fatalf("draw %d: port %d outside range", i, p)
		}
	}
}

// TestShuffleBagWeightedStillInBagMode pins that weighted selection draws its
// candidates from the bag too (no-replacement within a round) and stays
// in-range even with a scorer rejecting everything.
func TestShuffleBagWeightedStillInBagMode(t *testing.T) {
	pr, err := NewPortRange([]int{50, 51, 52, 53})
	if err != nil {
		t.Fatalf("NewPortRange: %v", err)
	}
	sel := NewPortSelector(pr, SelectorRandom)
	if sel.bag == nil {
		t.Fatal("expected bag mode for small range")
	}
	scorer := zeroWeightScorer{}
	for i := 0; i < 4*pr.Total(); i++ {
		if p := sel.NextWeighted(scorer); !pr.Contains(p) {
			t.Fatalf("draw %d: port %d outside range", i, p)
		}
	}
}

// zeroWeightScorer rejects every port, forcing NextWeighted down its full
// rejection-sampling path to the final fallback draw.
type zeroWeightScorer struct{}

func (zeroWeightScorer) Weight(int) float64 { return 0 }
func (zeroWeightScorer) Observe(int, bool)  {}
