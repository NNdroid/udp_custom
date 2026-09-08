package tunnel

import (
	"bytes"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSynCacheIdempotentLookup(t *testing.T) {
	c := newSynCache()
	now := time.Now()
	var nonce [16]byte
	copy(nonce[:], "nonce-nonce-nonce")
	key := synCacheKey{nonce: nonce}

	if got := c.Lookup(key, now); got != nil {
		t.Fatal("cache must start empty")
	}

	ack := []byte("encoded-ack-frame-1")
	c.Remember(key, ack, now)

	if got := c.Lookup(key, now); !bytes.Equal(got, ack) {
		t.Fatalf("Lookup after Remember = %v, want the cached ack", got)
	}
	// Remembering the same nonce again must not overwrite / duplicate.
	c.Remember(key, []byte("other"), now.Add(time.Second))
	if got := c.Lookup(key, now.Add(time.Second)); !bytes.Equal(got, ack) {
		t.Fatal("re-Remember of the same nonce must be a no-op")
	}
	if c.Len() != 1 {
		t.Fatalf("Len = %d, want 1", c.Len())
	}
}

func TestSynCacheTTLExpiry(t *testing.T) {
	c := newSynCache()
	now := time.Now()
	var nonce [16]byte
	nonce[0] = 1
	key := synCacheKey{nonce: nonce}

	c.Remember(key, []byte("ack"), now)
	if got := c.Lookup(key, now.Add(synCacheTTL+time.Second)); got != nil {
		t.Fatal("entry must expire after synCacheTTL")
	}
	if c.Len() != 0 {
		t.Fatalf("expired entry must be gone, Len=%d", c.Len())
	}
}

func TestSynCacheEvictionBound(t *testing.T) {
	c := newSynCache()
	now := time.Now()
	for i := 0; i < synCacheMax+100; i++ {
		var nonce [16]byte
		nonce[0] = byte(i)
		nonce[1] = byte(i >> 8)
		c.Remember(synCacheKey{nonce: nonce}, []byte("ack"), now)
	}
	if c.Len() > synCacheMax {
		t.Fatalf("cache grew past synCacheMax: %d", c.Len())
	}
}

func TestSynCacheAcquireHasSingleConcurrentOwner(t *testing.T) {
	c := newSynCache()
	now := time.Now()
	var nonce [16]byte
	copy(nonce[:], "same-syn-nonce!!")
	key := synCacheKey{nonce: nonce}

	const workers = 64
	var owners int32
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ack, owner := c.Acquire(key, now)
			if ack != nil {
				t.Error("in-progress reservation unexpectedly returned an ACK")
			}
			if owner {
				atomic.AddInt32(&owners, 1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := atomic.LoadInt32(&owners); got != 1 {
		t.Fatalf("concurrent owners = %d, want exactly 1", got)
	}

	c.Complete(key, []byte("ack"))
	ack, owner := c.Acquire(key, now.Add(time.Second))
	if owner || !bytes.Equal(ack, []byte("ack")) {
		t.Fatalf("completed Acquire = (%q, %v), want cached ACK", ack, owner)
	}
}

func TestSynCacheAbortReleasesReservation(t *testing.T) {
	c := newSynCache()
	var nonce [16]byte
	key := synCacheKey{nonce: nonce}
	if _, owner := c.Acquire(key, time.Now()); !owner {
		t.Fatal("first acquire should own reservation")
	}
	c.Abort(key)
	if _, owner := c.Acquire(key, time.Now()); !owner {
		t.Fatal("aborted reservation should be acquirable")
	}
}

func TestSynCacheSeparatesSameNonceAcrossPSKs(t *testing.T) {
	c := newSynCache()
	var nonce [clientNonceSize]byte
	copy(nonce[:], "shared-nonce-v2!")
	a := makeSynCacheKey(nonce, DerivePSKHandshakeKeys("psk-a", nonce).SynMAC)
	b := makeSynCacheKey(nonce, DerivePSKHandshakeKeys("psk-b", nonce).SynMAC)
	if a == b {
		t.Fatal("distinct PSKs produced the same cache identity")
	}
	now := time.Now()
	if _, owner := c.Acquire(a, now); !owner {
		t.Fatal("first PSK did not acquire its nonce")
	}
	if _, owner := c.Acquire(b, now); !owner {
		t.Fatal("second PSK was blocked by another credential's nonce")
	}
	c.Complete(a, []byte("ack-a"))
	c.Complete(b, []byte("ack-b"))
	if got := c.Lookup(a, now); !bytes.Equal(got, []byte("ack-a")) {
		t.Fatalf("PSK A cache returned %q", got)
	}
	if got := c.Lookup(b, now); !bytes.Equal(got, []byte("ack-b")) {
		t.Fatalf("PSK B cache returned %q", got)
	}
}

func TestSynLimiterBurstAndRefill(t *testing.T) {
	l := newSynLimiter(1, 3) // 1 token/sec, burst 3
	t0 := time.Now()

	for i := 0; i < 3; i++ {
		if !l.Allow("1.2.3.4", t0) {
			t.Fatalf("allow #%d within burst must succeed", i+1)
		}
	}
	if l.Allow("1.2.3.4", t0) {
		t.Fatal("4th immediate SYN must be rate-limited")
	}
	// Another source IP is unaffected.
	if !l.Allow("5.6.7.8", t0) {
		t.Fatal("a different source IP must have its own budget")
	}
	// After 2 seconds, 2 tokens refilled → two SYNs pass, the third is limited.
	if !l.Allow("1.2.3.4", t0.Add(2*time.Second)) {
		t.Fatal("first SYN after refill must succeed")
	}
	if !l.Allow("1.2.3.4", t0.Add(2*time.Second)) {
		t.Fatal("second SYN after refill must succeed")
	}
	if l.Allow("1.2.3.4", t0.Add(2*time.Second)) {
		t.Fatal("refilled budget exhausted; third SYN must be limited")
	}
}

// Lookup and Remember are production shapes kept test-only: the live receive
// path uses Acquire/Complete/Abort, but these direct forms make TTL/eviction
// behavior easy to assert.
func (c *synCache) Lookup(key synCacheKey, now time.Time) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	rec, ok := c.entries[key]
	if !ok {
		return nil
	}
	if now.Sub(rec.createdAt) > synCacheTTL {
		delete(c.entries, key)
		return nil
	}
	return rec.ackFrame
}

func (c *synCache) Remember(key synCacheKey, ackFrame []byte, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries[key]; ok {
		return
	}
	c.makeSpaceLocked(now)
	c.entries[key] = synRecord{ackFrame: append([]byte(nil), ackFrame...), createdAt: now}
	c.fifo = append(c.fifo, synFIFOEntry{key: key, createdAt: now})
}
