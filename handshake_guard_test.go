package main

import (
	"bytes"
	"testing"
	"time"
)

func TestSynCacheIdempotentLookup(t *testing.T) {
	c := newSynCache()
	now := time.Now()
	var nonce [16]byte
	copy(nonce[:], "nonce-nonce-nonce")

	if got := c.Lookup(nonce, now); got != nil {
		t.Fatal("cache must start empty")
	}

	ack := []byte("encoded-ack-frame-1")
	c.Remember(nonce, ack, now)

	if got := c.Lookup(nonce, now); !bytes.Equal(got, ack) {
		t.Fatalf("Lookup after Remember = %v, want the cached ack", got)
	}
	// Remembering the same nonce again must not overwrite / duplicate.
	c.Remember(nonce, []byte("other"), now.Add(time.Second))
	if got := c.Lookup(nonce, now.Add(time.Second)); !bytes.Equal(got, ack) {
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

	c.Remember(nonce, []byte("ack"), now)
	if got := c.Lookup(nonce, now.Add(synCacheTTL+time.Second)); got != nil {
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
		c.Remember(nonce, []byte("ack"), now)
	}
	if c.Len() > synCacheMax {
		t.Fatalf("cache grew past synCacheMax: %d", c.Len())
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
