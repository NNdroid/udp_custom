package main

import "testing"

func TestReplayFilterAcceptAndSeen(t *testing.T) {
	rf := &ReplayFilter{}
	if rf.Seen(5) {
		t.Fatal("nothing accepted yet, Seen(5) must be false")
	}
	if !rf.Accept(5) {
		t.Fatal("first Accept(5) must succeed")
	}
	if rf.Accept(5) {
		t.Fatal("second Accept(5) must fail")
	}
	if !rf.Seen(5) {
		t.Fatal("Seen(5) must be true after Accept(5)")
	}
	if rf.Seen(6) {
		t.Fatal("Seen(6) must be false (newer than maxSeq)")
	}
	// Transactional one-shot form agrees.
	if !rf.CheckAndAdd(5) {
		t.Fatal("CheckAndAdd(5) must report duplicate")
	}
	if rf.CheckAndAdd(6) {
		t.Fatal("CheckAndAdd(6) must accept a fresh sequence")
	}
}

// Seq 0 is reserved for handshake frames and never a valid DATA sequence.
func TestReplayFilterSeqZeroReserved(t *testing.T) {
	rf := &ReplayFilter{}
	if !rf.Seen(0) {
		t.Fatal("Seen(0) must be true (always rejected)")
	}
	if rf.Accept(0) {
		t.Fatal("Accept(0) must fail")
	}
}

func TestReplayFilterWindowShift(t *testing.T) {
	rf := &ReplayFilter{}
	// Walk the window forward by more than its width.
	for seq := uint32(1); seq <= 3000; seq++ {
		if rf.CheckAndAdd(seq) {
			t.Fatalf("seq %d unexpectedly reported duplicate", seq)
		}
	}
	// 1..951 fell out of the 2048 window (3000-2048=952).
	if rf.Seen(1) {
		t.Fatal("seq 1 should have fallen out of the window")
	}
	// Still inside the window: seen.
	if !rf.Seen(1000) {
		t.Fatal("seq 1000 must still be inside the window")
	}
	if !rf.CheckAndAdd(1000) {
		t.Fatal("CheckAndAdd(1000) must report duplicate")
	}
}

// Regression for P2: the window must behave correctly across uint32 wrap.
func TestReplayFilterWrapAround(t *testing.T) {
	rf := &ReplayFilter{}
	const start = 0xFFFFFF00
	if !rf.Accept(start) {
		t.Fatal("first Accept at high sequence must succeed")
	}
	// Cross the wrap boundary: ...FFFFFFFE, 0, 1, 2 ...
	seq := uint32(start)
	for i := 0; i < 2100; i++ {
		seq++
		if seq == 0 {
			continue // 0 is reserved; never accepted
		}
		if rf.CheckAndAdd(seq) {
			t.Fatalf("seq %d (after wrap) unexpectedly duplicate", seq)
		}
	}
	// start is 2100 behind the new maxSeq (0xFFFFFF00+2100=0xFFFFFD34-ish
	// wrapped) — within the 2048 window only if we skipped 0. Recompute: we
	// accepted 2099 sequences after start, so behind = 2099 < 2048 is FALSE.
	// Instead verify a sequence 100 past the wrap is still seen.
	rf2 := &ReplayFilter{}
	if !rf2.Accept(0xFFFFFFFE) {
		t.Fatal("accept 0xFFFFFFFE")
	}
	if !rf2.Accept(1) { // wraps to 1
		t.Fatal("accept 1 after wrap")
	}
	if !rf2.Accept(2) {
		t.Fatal("accept 2 after wrap")
	}
	if !rf2.Seen(0xFFFFFFFE) {
		t.Fatal("0xFFFFFFFE must still be seen after wrapping to 1-2")
	}
	if !rf2.Seen(1) {
		t.Fatal("seq 1 must be seen")
	}
	if rf2.Seen(0xFFFFFFFD) {
		t.Fatal("0xFFFFFFFD is behind 0xFFFFFFFE and never accepted; window edge must not claim it seen")
	}
}

// The window shift across wrap must not clobber still-relevant entries.
func TestReplayFilterWrapWindowKeepsOldEntries(t *testing.T) {
	rf := &ReplayFilter{}
	// Anchor just before the wrap and step across it.
	anchor := uint32(0xFFFFFFFF - 100)
	if !rf.Accept(anchor) {
		t.Fatal("accept anchor")
	}
	cur := anchor
	for i := 0; i < 150; i++ {
		cur++
		if cur == 0 {
			continue
		}
		rf.Accept(cur)
	}
	// cur wrapped; anchor is ~150 behind → still inside the 2048 window.
	if !rf.Seen(anchor) {
		t.Fatalf("anchor %d should still be inside the window after wrap", anchor)
	}
}

// isBeforeWrapSafe must implement RFC-1982-style comparison.
//
// Note on the exact half-space boundary (a-b == 2^31): the standard int32-cast
// method TCP uses reports "before" in one direction and "before" in the other
// too (both casts land on MinInt32) — the boundary is genuinely ambiguous and
// unreachable in practice (sequences 2^31 apart). We only assert behavior
// strictly inside either half.
func TestIsBeforeWrapSafe(t *testing.T) {
	cases := []struct {
		a, b uint32
		want bool
	}{
		{1, 2, true},
		{2, 1, false},
		{5, 5, false},
		{0xFFFFFFFF, 1, true},  // 0xFFFFFFFF is before 1 (it wraps into it)
		{1, 0xFFFFFFFF, false}, // 1 is newer
		{0x80000001, 0, true},  // just past half-space behind
		{0, 0x7FFFFFFF, true},  // 2^31-1 ahead: still "a before b"
		{0x7FFFFFFF, 0, false}, // and symmetrically not the reverse
	}
	for _, c := range cases {
		if got := isBeforeWrapSafe(c.a, c.b); got != c.want {
			t.Fatalf("isBeforeWrapSafe(%d, %d) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
