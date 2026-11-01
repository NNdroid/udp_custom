package tunnel

import (
	"bytes"
	"testing"
	"testing/synctest"
	"time"
)

func TestSACKRepairsOnlyGapAndRejectsStaleFeedback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now()
		flow := newSendFlow(256, false, true, false)
		out := make(map[uint64]*unackedPkt)
		for i := uint64(1); i <= 4; i++ {
			out[i] = &unackedPkt{wire: []byte{byte(i)}, sentTime: now, rto: 200 * time.Millisecond}
		}
		time.Sleep(10 * time.Millisecond)
		frame := &UDPCFrame{Cmd: CMD_SACK, PacketNo: 2, Data: encodeSACK(32, 0b1110)}
		wires, valid := updateSACK(flow, out, frame, 4, 20*time.Millisecond)
		if !valid || len(wires) != 1 || !bytes.Equal(wires[0], []byte{1}) {
			t.Fatalf("repair=%v valid=%v", wires, valid)
		}
		for i := uint64(2); i <= 4; i++ {
			if !out[i].sacked || out[i].retries != 0 {
				t.Fatalf("retransmitted admitted frame %d", i)
			}
		}
		frame.PacketNo = 1
		frame.Data = encodeSACK(0, 0)
		if _, valid := updateSACK(flow, out, frame, 4, 0); valid || flow.credit != 32 {
			t.Fatal("stale feedback regressed receive credit")
		}
		frame.PacketNo = 3
		frame.Ack = 1000
		if _, valid := updateSACK(flow, out, frame, 4, 0); valid {
			t.Fatal("accepted unsent cumulative ACK")
		}
		time.Sleep(500 * time.Millisecond)
		due, abandoned, _, _ := retryDue(out, time.Now(), time.Second, flow, 0)
		if abandoned || len(due) != 1 || due[0][0] != 1 {
			t.Fatalf("timeout repairs=%v abandoned=%v", due, abandoned)
		}
	})
}

func TestAdaptiveWindowLimitsAndLoss(t *testing.T) {
	f := newSendFlow(256, true, true, false)
	for i := 0; i < 32; i++ {
		f.acknowledged(64)
	}
	if f.cwnd != deliveryWindow {
		t.Fatalf("window=%d", f.cwnd)
	}
	f.loss(time.Now(), time.Millisecond, false)
	if f.cwnd != deliveryWindow/2 {
		t.Fatalf("loss window=%d", f.cwnd)
	}
	f.credit = 0
	if f.window() != 0 {
		t.Fatal("zero receive credit ignored")
	}
	f = newSendFlow(16, false, true, false)
	f.acknowledged(1000)
	if f.cwnd != 16 {
		t.Fatal("explicit cap ignored")
	}
}

func TestUndoLossRetractsSpuriousTimeout(t *testing.T) {
	f := newSendFlow(deliveryWindow, true, true, false)
	for i := 0; i < 32; i++ {
		f.acknowledged(64)
	}
	before := f.cwnd

	// A retransmit whose ACK beats the retransmit's own round trip is evidence
	// the timeout was jitter, not loss: the window has to come back up.
	f.loss(time.Now(), time.Second, true)
	if f.cwnd != before/2 {
		t.Fatalf("undoable loss window=%d, want %d", f.cwnd, before/2)
	}
	retried := &unackedPkt{retries: 1, sentTime: time.Now()}
	if !f.undoIfSpurious(retried, time.Second) {
		t.Fatal("fresh retransmit ACK was not recognised as spurious")
	}
	if f.cwnd != before {
		t.Fatalf("undo restored window=%d, want %d", f.cwnd, before)
	}

	// Nothing left to undo, and none of the non-spurious shapes may revert it.
	if f.undoIfSpurious(retried, time.Second) {
		t.Fatal("undoed twice for one timeout")
	}
	if f.undoIfSpurious(&unackedPkt{retries: 0, sentTime: time.Now()}, time.Second) {
		t.Fatal("untouched packet triggered an undo")
	}
	if f.undoIfSpurious(&unackedPkt{retries: 1, sentTime: time.Now().Add(-2 * time.Second)}, time.Second) {
		t.Fatal("an ACK a full RTT late was treated as spurious")
	}
	if f.undoIfSpurious(retried, 0) {
		t.Fatal("zero RTT estimate must not classify anything as spurious")
	}
	if f.cwnd != before {
		t.Fatalf("window drifted to %d, want %d", f.cwnd, before)
	}

	// A SACK-driven cut is stronger evidence and stays put.
	f.lastLoss = time.Time{}
	f.loss(time.Now(), time.Second, false)
	if f.undoIfSpurious(retried, time.Second) {
		t.Fatal("non-undoable loss was retracted")
	}
	if f.cwnd != before/2 {
		t.Fatalf("window=%d, want %d", f.cwnd, before/2)
	}
}

func TestSACKCoversFullReceiveWindowAndLostCreditUpdate(t *testing.T) {
	f := newSendFlow(256, true, true, false)
	out := map[uint64]*unackedPkt{512: {wire: []byte("last")}}
	frame := &UDPCFrame{PacketNo: 1, Data: encodeSACK(1, 0, 0, 0, 0, 0, 0, 0, uint64(1)<<63)}
	if _, valid := updateSACK(f, out, frame, 512, 0); !valid || !out[512].sacked {
		t.Fatal("high window position was not selectively acknowledged")
	}
	f.credit = 0
	if _, probe := creditProbeInterval(f, map[uint64]*unackedPkt{}); !probe {
		t.Fatal("lost window update strands sender after outstanding queue drains")
	}
	frame.PacketNo = 2
	frame.Data = encodeSACK(deliveryWindow, 0)
	if _, valid := updateSACK(f, out, frame, 512, 0); !valid || f.window() == 0 {
		t.Fatal("credit probe did not reopen window")
	}
}

func TestSACKMalformedFeedbackDoesNotChangeSender(t *testing.T) {
	for _, frame := range []*UDPCFrame{
		{PacketNo: 1, Data: []byte{0}},
		{PacketNo: 1, Data: make([]byte, 3)},
		{PacketNo: 1, Ack: 5, Data: encodeSACK(100, 0)},
		{PacketNo: 1, Data: encodeSACK(100, 1<<4)},
		// Oversize credit is deliberately NOT here: it is clamped and
		// accepted now (mixed-version safety). See
		// TestUpdateSACKClampsOversizeCredit for that contract.
	} {
		f := newSendFlow(256, true, true, false)
		out := map[uint64]*unackedPkt{1: {wire: []byte("retained")}}
		if _, valid := updateSACK(f, out, frame, 4, 0); valid {
			t.Fatal("accepted malformed feedback")
		}
		if f.feedbackNo != 0 || f.credit != deliveryWindow || out[1].sacked || out[1].retries != 0 {
			t.Fatal("malformed feedback changed sender state")
		}
	}
}

func BenchmarkFECSenderCleanPath(b *testing.B) {
	s := newFECSender(func(fecParityShard) {})
	defer s.close()
	s.blocks = fecBootstrapBlocks
	p := make([]byte, 1300)
	b.ReportAllocs()
	b.SetBytes(int64(len(p)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.add(uint64(i+1), p)
	}
}

// TestSendFlowWideWindowCeiling pins the negotiated flight cap: a wide
// session's automatic window is deliveryWindowWide, a baseline session's
// stays at deliveryWindow, and explicit maxima are still clamped down.
func TestSendFlowWideWindowCeiling(t *testing.T) {
	wide := newSendFlow(0, true, true, true)
	if wide.max != deliveryWindowWide || wide.credit != deliveryWindowWide {
		t.Fatalf("wide auto flow max=%d credit=%d, want %d", wide.max, wide.credit, deliveryWindowWide)
	}
	base := newSendFlow(0, true, true, false)
	if base.max != deliveryWindow || base.credit != deliveryWindow {
		t.Fatalf("baseline auto flow max=%d credit=%d, want %d", base.max, base.credit, deliveryWindow)
	}
	capped := newSendFlow(99999, false, true, true)
	if capped.max != deliveryWindowWide {
		t.Fatalf("explicit max=%d, want clamped %d", capped.max, deliveryWindowWide)
	}
}

// TestUpdateSACKClampsOversizeCredit is the mixed-version compatibility
// contract: credit beyond the wire baseline must be CLAMPED, never rejected.
// Rejecting used to discard the whole SACK — the silent fast-repair outage
// that made mixed deployments crawl.
func TestUpdateSACKClampsOversizeCredit(t *testing.T) {
	f := newSendFlow(256, true, true, true)
	out := make(map[uint64]*unackedPkt)
	now := time.Now()
	for i := uint64(1); i <= 4; i++ {
		out[i] = &unackedPkt{wire: []byte{byte(i)}, sentTime: now, rto: time.Second}
	}
	// Credit 50000 is garbage on any wire; it clamps to the wide ceiling.
	frame := &UDPCFrame{Cmd: CMD_SACK, PacketNo: 2, Data: encodeSACK(50000, 0b1110)}
	if _, valid := updateSACK(f, out, frame, 4, 20*time.Millisecond); !valid {
		t.Fatal("oversize credit rejected; want clamped acceptance")
	}
	if f.credit != deliveryWindowWide {
		t.Fatalf("credit = %d, want clamped %d", f.credit, deliveryWindowWide)
	}
	// Wide-but-sane credit passes through untouched (the old code rejected
	// anything above deliveryWindow).
	frame.PacketNo = 3
	frame.Data = encodeSACK(1000, 0b1110)
	if _, valid := updateSACK(f, out, frame, 4, 20*time.Millisecond); !valid {
		t.Fatal("wide credit 1000 rejected; want accepted")
	}
	if f.credit != 1000 {
		t.Fatalf("credit = %d, want 1000", f.credit)
	}
}

// TestUpdateSACKRepairsMultipleHoles covers burst-loss recovery: one SACK
// feedback repairs up to sackFastRepairMax oldest holes in sequence order,
// instead of trickling one repair per feedback round trip.
func TestUpdateSACKRepairsMultipleHoles(t *testing.T) {
	f := newSendFlow(256, true, true, true)
	out := make(map[uint64]*unackedPkt)
	old := time.Now().Add(-time.Second)
	for i := uint64(1); i <= 10; i++ {
		out[i] = &unackedPkt{wire: []byte{byte(i)}, sentTime: old, rto: time.Second}
	}
	// Admit 2, 4, 6 (bits 1, 3, 5): three gaps at 1, 3, 5 plus deeper holes.
	frame := &UDPCFrame{Cmd: CMD_SACK, PacketNo: 2, Data: encodeSACK(32, 1<<1|1<<3|1<<5)}
	wires, valid := updateSACK(f, out, frame, 10, 20*time.Millisecond)
	if !valid {
		t.Fatal("sack rejected")
	}
	if len(wires) != sackFastRepairMax {
		t.Fatalf("repaired %d frames, want %d", len(wires), sackFastRepairMax)
	}
	for i, want := range [][]byte{{1}, {3}, {5}} {
		if !bytes.Equal(wires[i], want) {
			t.Fatalf("repair %d = %v, want %v (oldest holes first)", i, wires[i], want)
		}
	}
	// The deeper holes must be untouched: repair budget is per-SACK.
	for _, seq := range []uint64{7, 8, 9, 10} {
		if out[seq].retries != 0 {
			t.Fatalf("seq %d repaired beyond the per-SACK budget", seq)
		}
	}
}

// TestUpdateSACKSkipsQueuedFrames: a frame still sitting in the transmit
// queue was never lost; repairing it would double-send and burn retry budget.
func TestUpdateSACKSkipsQueuedFrames(t *testing.T) {
	f := newSendFlow(256, true, true, true)
	out := make(map[uint64]*unackedPkt)
	old := time.Now().Add(-time.Second)
	for i := uint64(1); i <= 5; i++ {
		out[i] = &unackedPkt{wire: []byte{byte(i)}, sentTime: old, rto: time.Second}
	}
	out[1].queued = true // still in the transmit queue
	// Admit 2, 3, 5 (bits 1, 2, 4): the only repairable hole is 4 — hole 1 is
	// queued and must not be touched.
	frame := &UDPCFrame{Cmd: CMD_SACK, PacketNo: 2, Data: encodeSACK(32, 1<<1|1<<2|1<<4)}
	wires, valid := updateSACK(f, out, frame, 5, 20*time.Millisecond)
	if !valid {
		t.Fatal("sack rejected")
	}
	if len(wires) != 1 || !bytes.Equal(wires[0], []byte{4}) {
		t.Fatalf("repairs = %v, want only seq 4 (seq 1 is queued)", wires)
	}
	if out[1].retries != 0 || out[1].sacked {
		t.Fatalf("queued frame touched: retries=%d sacked=%v", out[1].retries, out[1].sacked)
	}
}
