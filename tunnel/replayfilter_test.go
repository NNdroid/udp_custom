package tunnel

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
	for seq := uint64(1); seq <= 3000; seq++ {
		if rf.CheckAndAdd(seq) {
			t.Fatalf("seq %d unexpectedly reported duplicate", seq)
		}
	}
	// 1..951 fell out of the 2048-bit bitmap. They remain rejected: treating
	// too-old packet numbers as fresh would reopen the replay window.
	if !rf.Seen(1) {
		t.Fatal("seq 1 is too old and must remain rejected")
	}
	// Still inside the window: seen.
	if !rf.Seen(1000) {
		t.Fatal("seq 1000 must still be inside the window")
	}
	if !rf.CheckAndAdd(1000) {
		t.Fatal("CheckAndAdd(1000) must report duplicate")
	}
}

func TestReplayFilterRejectsTooOldPacket(t *testing.T) {
	rf := &ReplayFilter{}
	if !rf.Accept(1) || !rf.Accept(4096) {
		t.Fatal("fresh packet numbers must be accepted")
	}
	if !rf.Seen(1) || rf.Accept(1) {
		t.Fatal("packet older than the window must always be rejected")
	}
}

func TestReplayFilterSupportsPacketNumbersAboveUint32(t *testing.T) {
	rf := &ReplayFilter{}
	base := uint64(1) << 40
	if !rf.Accept(base) || !rf.Accept(base+2) || !rf.Accept(base+1) {
		t.Fatal("64-bit out-of-order packet numbers must be accepted once")
	}
	if rf.Accept(base + 1) {
		t.Fatal("64-bit duplicate must be rejected")
	}
}

func TestReplayFilterRemoveAllowsRetransmission(t *testing.T) {
	rf := &ReplayFilter{}
	if !rf.Accept(10) {
		t.Fatal("first packet must be accepted")
	}
	rf.Remove(10)
	if !rf.Accept(10) {
		t.Fatal("rolled-back packet must be accepted again")
	}
}
