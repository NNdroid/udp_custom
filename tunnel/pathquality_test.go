package tunnel

import (
	"math"
	"sync"
	"testing"
	"time"
)

func TestPathQualityObserveAndWeight(t *testing.T) {
	q := newPathQuality()
	if w := q.Weight(40000); w != 1 {
		t.Fatalf("unobserved port weight = %v, want 1", w)
	}

	// A healthy port keeps full weight.
	for i := 0; i < 100; i++ {
		q.Observe(40000, false)
	}
	if w := q.Weight(40000); w != 1 {
		t.Fatalf("healthy port weight = %v, want 1", w)
	}

	// A port that keeps needing retransmission drops toward the floor but
	// never below it: it must keep receiving probe traffic.
	for i := 0; i < 200; i++ {
		q.Observe(40001, true)
	}
	w := q.Weight(40001)
	if w < pathQualityFloor || w > 0.2 {
		t.Fatalf("bad port weight = %v, want in [%v, 0.2]", w, pathQualityFloor)
	}

	// The estimate is a rate, not a counter: mixed outcomes land between.
	for i := 0; i < 100; i++ {
		q.Observe(40002, i%2 == 0)
	}
	if w := q.Weight(40002); w >= 1 || w <= pathQualityFloor {
		t.Fatalf("50%% loss port weight = %v, want strictly between %v and 1", w, pathQualityFloor)
	}

	// Zero (locally synthesized) ports are never recorded.
	q.Observe(0, true)
	if _, ok := q.scores.Load(0); ok {
		t.Fatal("port 0 must not be scored")
	}
}

func TestPathQualityStaleRecovery(t *testing.T) {
	q := newPathQuality()
	for i := 0; i < 300; i++ {
		q.Observe(41000, true)
	}
	bad := q.Weight(41000)

	// Backdate the last observation by several recovery intervals: the
	// estimate must halve per interval, pulling the weight back up.
	v, _ := q.scores.Load(41000)
	ps := v.(*portScore)
	ps.at.Store(time.Now().Add(-6 * pathQualityRecovery).UnixNano())
	recovered := q.Weight(41000)
	if recovered <= bad {
		t.Fatalf("stale port weight %v did not recover above %v", recovered, bad)
	}
	// 6 halvings of a ~1.0 loss leaves ~1.6%: essentially healthy.
	want := math.Pow(0.5, 6)
	loss := 1 - (recovered-pathQualityFloor)/(1-pathQualityFloor)
	if loss < want*0.4 || loss > want*2 {
		t.Fatalf("recovered normalized loss = %v, want near %v", loss, want)
	}
}

func TestPathQualityConcurrentObserve(t *testing.T) {
	q := newPathQuality()
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				q.Observe(42000+g, i%3 == 0)
				_ = q.Weight(42000 + g)
			}
		}(g)
	}
	wg.Wait()
	// CAS updates must not lose samples: 1/3 loss in, ~1/3 out.
	w := q.Weight(42000)
	loss := (1 - w) / (1 - pathQualityFloor)
	if loss < 0.2 || loss > 0.45 {
		t.Fatalf("concurrent EWMA loss = %v, want near 0.33", loss)
	}
}

func TestPortSelectorNextWeighted(t *testing.T) {
	ports := make([]int, 0, 8)
	for p := 25000; p <= 25007; p++ {
		ports = append(ports, p)
	}
	pr, err := NewPortRange(ports)
	if err != nil {
		t.Fatal(err)
	}
	sel := NewPortSelector(pr, SelectorRandom)

	// No scorer: falls back to uniform Next.
	if p := sel.NextWeighted(nil); p < 25000 || p > 25007 {
		t.Fatalf("nil scorer port %d outside range", p)
	}

	// Everything is terrible except 25003: it must dominate the draws.
	q := newPathQuality()
	for p := 25000; p <= 25007; p++ {
		for i := 0; i < 200; i++ {
			q.Observe(p, p != 25003)
		}
	}
	good, total := 0, 4000
	for i := 0; i < total; i++ {
		if sel.NextWeighted(q) == 25003 {
			good++
		}
	}
	// The good port (weight 1) is accepted on first draw whenever drawn
	// (1/8 chance); bad ports are rejected ~98% per attempt. With 3 retries
	// the good port should take the overwhelming majority of selections.
	if good < total*70/100 {
		t.Fatalf("good port selected %d/%d, want >= 70%%", good, total)
	}

	// The floor keeps probe traffic flowing to bad ports: they must not
	// vanish entirely.
	if good == total {
		t.Fatal("bad ports received zero selections; probe floor is broken")
	}
}

func TestFECLossMemoPutGetTTL(t *testing.T) {
	m := &fecLossMemo{}
	if _, ok := m.get(); ok {
		t.Fatal("empty memo must miss")
	}
	m.put(0.07)
	if v, ok := m.get(); !ok || math.Abs(v-0.07) > 1e-9 {
		t.Fatalf("memo get = %v, %v; want 0.07, true", v, ok)
	}
	m.mu.Lock()
	m.at = time.Now().Add(-2 * fecLossMemoTTL)
	m.mu.Unlock()
	if _, ok := m.get(); ok {
		t.Fatal("expired memo must miss")
	}
}

func TestFECSenderSeedAndMemoSnapshot(t *testing.T) {
	s := newFECSender(func(fecParityShard) {})
	if _, ok := s.memoSnapshot(); ok {
		t.Fatal("fresh sender must not produce a memo (no sample size)")
	}

	// Seeding sets the local estimate at full weight: parity decisions from
	// block 0 onward reflect the remembered path quality.
	s.seedLoss(0.08)
	if got := s.adaptive.local.loss(); math.Abs(got-0.08) > 1e-9 {
		t.Fatalf("seeded local loss = %v, want 0.08", got)
	}
	// Combined estimate must not undershoot the seed before real samples
	// arrive (remote estimator still at 0).
	if got := s.adaptive.loss(); got < 0.08-1e-9 {
		t.Fatalf("combined loss = %v, want >= seed 0.08", got)
	}
	// Parity for the seeded rate: 8% lands in the parity-3 bucket.
	if p := fecParityForLoss(s.adaptive.loss()); p < 3 {
		t.Fatalf("parity for seeded 8%% loss = %d, want >= 3", p)
	}
}

func TestDeliveryOfferObserved(t *testing.T) {
	done := make(chan struct{})
	d := newOrderedDelivery(16, done, func([]byte) error { return nil }, func(error) {}, func(uint64) {})
	defer close(done)

	if fresh, ok := d.offerObserved(0, nil); fresh || ok {
		t.Fatalf("seq 0: fresh=%v ok=%v, want false false", fresh, ok)
	}
	fresh, ok := d.offerObserved(1, []byte("a"))
	if !fresh || !ok {
		t.Fatalf("first frame: fresh=%v ok=%v, want true true", fresh, ok)
	}
	fresh, ok = d.offerObserved(1, []byte("a"))
	if fresh || !ok {
		t.Fatalf("delivered duplicate: fresh=%v ok=%v, want false true", fresh, ok)
	}
	fresh, ok = d.offerObserved(1, []byte("a"))
	if fresh || !ok {
		t.Fatalf("pending duplicate: fresh=%v ok=%v, want false true", fresh, ok)
	}
	// Out-of-order but NEW data counts as fresh: reorder is not loss.
	fresh, ok = d.offerObserved(3, []byte("c"))
	if !fresh || !ok {
		t.Fatalf("gap frame: fresh=%v ok=%v, want true true", fresh, ok)
	}
}
