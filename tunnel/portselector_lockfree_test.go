package tunnel

import (
	"sync"
	"testing"
)

func TestPortSelectorRandomConcurrentRange(t *testing.T) {
	ports, err := ParsePortRangeSpec("25000-25499")
	if err != nil {
		t.Fatal(err)
	}
	pr, err := NewPortRange(ports)
	if err != nil {
		t.Fatal(err)
	}
	sel := NewPortSelector(pr, SelectorRandom)

	const workers = 32
	const iterations = 10000
	var wg sync.WaitGroup
	errCh := make(chan int, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				p := sel.Next()
				if !pr.Contains(p) {
					errCh <- p
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)
	if p, ok := <-errCh; ok {
		t.Fatalf("selector returned port %d outside configured range", p)
	}
}

func BenchmarkPortSelectorRandomParallel(b *testing.B) {
	sel := NewPortSelector(benchPortRange(b), SelectorRandom)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = sel.Next()
		}
	})
}
