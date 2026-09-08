package tunnel

import (
	"sync"
	"sync/atomic"
)

// eventBus decouples event production (hot receive/send paths) from
// embedder-supplied handlers. Producers never block and never panic on slow
// consumers: when the queue is full the event is DROPPED and counted —
// handlers must therefore treat events as notifications, not as a reliable
// stream (counters in Stats remain the authoritative record).
type eventBus[T any] struct {
	ch      chan T
	stop    chan struct{}
	dropped uint64 // events discarded because the queue was full
	stopped atomic.Bool
	wg      sync.WaitGroup
}

func newEventBus[T any](capacity int) *eventBus[T] {
	return &eventBus[T]{ch: make(chan T, capacity), stop: make(chan struct{})}
}

// setHandler starts (once) the single consumer goroutine that hands events to
// h. Calling it again just swaps h; nil stops delivery (events still drain).
func (b *eventBus[T]) setHandler(h func(T)) {
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		for {
			select {
			case ev := <-b.ch:
				if h == nil {
					continue
				}
				safeEventCall(h, ev)
			case <-b.stop:
				return
			}
		}
	}()
}

func (b *eventBus[T]) emit(ev T) {
	if b.stopped.Load() {
		return
	}
	select {
	case b.ch <- ev:
	default:
		atomic.AddUint64(&b.dropped, 1)
	}
}

func (b *eventBus[T]) droppedCount() uint64 { return atomic.LoadUint64(&b.dropped) }

func (b *eventBus[T]) close() {
	b.stopped.Store(true)
	close(b.stop)
}

// safeEventCall isolates embedder-handler panics: a panicking callback must
// never take down the tunnel.
func safeEventCall[T any](h func(T), ev T) {
	defer func() {
		_ = recover() // an embedder bug must not kill the tunnel
	}()
	h(ev)
}
