package tunnel

import (
	"testing"
	"time"
)

// --- ③-2: Westwood delivery-rate restore + delay-gradient discrimination ---

func newTestFlow() *sendFlow {
	f := newSendFlow(512, false, true)
	f.cwnd = 256
	f.ssthresh = 512
	return f
}

// TestSendFlowWestwoodDisabledHalvesAlways covers the westwood=false config
// gate: with the discrimination turned off even floor-level SRTT loss takes
// the classic halving, restoring the pre-weaknet behaviour.
func TestSendFlowWestwoodDisabledHalvesAlways(t *testing.T) {
	f := newSendFlow(512, false, false)
	f.cwnd = 256
	f.ssthresh = 512
	f.minRTT = 50 * time.Millisecond
	f.rate = 1000
	f.rateAt = time.Now()

	// Same setup as TestSendFlowRandomLossRestoresBDP, but Westwood is off:
	// the BDP restore branch must be skipped and the window plain-halves.
	f.loss(time.Now(), 50*time.Millisecond, false)
	if f.cwnd != 128 {
		t.Fatalf("westwood=off random-loss cwnd = %d, want classic halving 128", f.cwnd)
	}
}

func TestSendFlowRandomLossRestoresBDP(t *testing.T) {
	f := newTestFlow()
	f.minRTT = 50 * time.Millisecond
	f.rate = 1000 // 1000 frames/s
	f.rateAt = time.Now()

	// Loss with the SRTT at the floor: no queue buildup, so the drop was
	// random wireless loss. BDP = 1000/s * 50ms = 50 frames — the window
	// shrinks to the BDP instead of blindly halving to 128.
	f.loss(time.Now(), 50*time.Millisecond, false)
	if f.cwnd != 50 {
		t.Fatalf("random-loss cwnd = %d, want BDP 50 (blind halving would give 128)", f.cwnd)
	}
	if f.ssthresh != 50 {
		t.Fatalf("ssthresh = %d, want 50", f.ssthresh)
	}
}

func TestSendFlowRandomLossNeverRaisesWindow(t *testing.T) {
	f := newTestFlow()
	f.cwnd = 40
	f.minRTT = 50 * time.Millisecond
	f.rate = 1000 // BDP 50 > cwnd 40
	f.rateAt = time.Now()

	// Westwood clamps at the current window: a loss must never be an excuse
	// to GROW, even when the measured BDP is larger.
	f.loss(time.Now(), 50*time.Millisecond, false)
	if f.cwnd != 40 {
		t.Fatalf("cwnd = %d, want unchanged 40 (no growth on loss)", f.cwnd)
	}
}

func TestSendFlowCongestedLossStillHalves(t *testing.T) {
	f := newTestFlow()
	f.minRTT = 50 * time.Millisecond
	f.rate = 1000
	f.rateAt = time.Now()

	// SRTT at 3x the floor: the queue is being built up — classic congestion.
	// The rate estimate must NOT rescue the window here.
	f.loss(time.Now(), 150*time.Millisecond, false)
	if f.cwnd != 128 {
		t.Fatalf("congested cwnd = %d, want halved 128", f.cwnd)
	}
	if f.ssthresh != 128 {
		t.Fatalf("congested ssthresh = %d, want 128", f.ssthresh)
	}
}

func TestSendFlowStaleRateFallsBackToHalving(t *testing.T) {
	f := newTestFlow()
	f.minRTT = 50 * time.Millisecond
	f.rate = 1000
	f.rateAt = time.Now().Add(-3 * time.Second) // older than rateIdle

	// Without recent ACKs the rate no longer describes the path; the safe
	// halving is the only defensible answer.
	f.loss(time.Now(), 50*time.Millisecond, false)
	if f.cwnd != 128 {
		t.Fatalf("stale-rate cwnd = %d, want halved 128", f.cwnd)
	}
}

func TestSendFlowNoBaselineHalves(t *testing.T) {
	f := newTestFlow()
	f.rate = 1000
	f.rateAt = time.Now()
	// minRTT unknown: the conservative answer is congestion.
	f.loss(time.Now(), 30*time.Millisecond, false)
	if f.cwnd != 128 {
		t.Fatalf("no-baseline cwnd = %d, want halved 128", f.cwnd)
	}
}

func TestSendFlowWestwoodUndoStillWorks(t *testing.T) {
	f := newTestFlow()
	f.minRTT = 50 * time.Millisecond
	f.rate = 1000
	f.rateAt = time.Now()

	// An undoable RTO cut that took the Westwood branch must still be
	// revertible by undoLoss — the spurious-timeout machinery is orthogonal
	// to which branch shrank the window.
	f.loss(time.Now(), 50*time.Millisecond, true)
	if f.cwnd != 50 {
		t.Fatalf("pre-undo cwnd = %d, want 50", f.cwnd)
	}
	if !f.undoLoss() {
		t.Fatal("undoLoss returned false")
	}
	if f.cwnd != 256 {
		t.Fatalf("post-undo cwnd = %d, want restored 256", f.cwnd)
	}
}

func TestSendFlowObserveRTTTracksFloor(t *testing.T) {
	f := newTestFlow()
	f.observeRTT(80 * time.Millisecond)
	f.observeRTT(40 * time.Millisecond)
	if f.minRTT != 40*time.Millisecond {
		t.Fatalf("minRTT = %v, want snap-down to 40ms", f.minRTT)
	}
	// Jittery samples drift the floor up slowly, not instantly.
	f.observeRTT(400 * time.Millisecond)
	want := 40*time.Millisecond + (400-40)*time.Millisecond/minRTTDrift
	if f.minRTT != want {
		t.Fatalf("minRTT after jitter = %v, want drifted %v", f.minRTT, want)
	}
}

func TestSendFlowSampleRate(t *testing.T) {
	f := newTestFlow()
	now := time.Now()
	f.sampleRate(10, now)
	f.sampleRate(10, now.Add(150*time.Millisecond))
	// 20 frames over 150ms -> ~133 f/s; BDP at 50ms ~= 6-7 frames.
	if f.rate < 100 || f.rate > 160 {
		t.Fatalf("rate = %v, want ~133", f.rate)
	}
	// Long idle resets the window instead of diluting the estimate.
	f.sampleRate(100, now.Add(10*time.Second))
	if f.rate != 0 || f.rateAcc != 100 {
		t.Fatalf("after idle: rate=%v acc=%d, want reset with acc=100", f.rate, f.rateAcc)
	}
}

// --- ③-1: negotiated extended parity ---

func TestFECParityForLossExtBuckets(t *testing.T) {
	cases := []struct {
		loss float64
		base int
		ext  int
	}{
		{0.001, 0, 0},
		{0.01, 1, 1},
		{0.04, 2, 2},
		{0.08, 3, 3},
		{0.15, 4, 4},
		{0.25, 4, 6},
		{0.40, 4, 8},
	}
	for _, c := range cases {
		if got := fecParityForLossExt(c.loss, false); got != c.base {
			t.Fatalf("base parity(%.2f) = %d, want %d", c.loss, got, c.base)
		}
		if got := fecParityForLossExt(c.loss, true); got != c.ext {
			t.Fatalf("ext parity(%.2f) = %d, want %d", c.loss, got, c.ext)
		}
	}
}

func TestFECExtRoundTrip(t *testing.T) {
	// RS(8,8): every parity shard encodes and decodes to itself.
	for idx := 0; idx < 8; idx++ {
		p := fecParityShard{BaseSeq: 100, DataShards: 8, ParityShards: 8, Index: idx,
			Data: make([]byte, fecLengthPrefixSize+16), Ext: true}
		var f UDPCFrame
		f.Cmd = CMD_FEC
		if !p.applyToFrame(&f) {
			t.Fatalf("applyToFrame rejected m=8 idx=%d", idx)
		}
		got, err := parseFECParityFrameExt(&f, true)
		if err != nil {
			t.Fatalf("parse ext m=8 idx=%d: %v", idx, err)
		}
		if got.DataShards != 8 || got.ParityShards != 8 || got.Index != idx {
			t.Fatalf("round trip m=8 idx=%d: got k=%d m=%d idx=%d", idx, got.DataShards, got.ParityShards, got.Index)
		}
	}
	// Legacy encoding is untouched: ext parse of a legacy frame (bits 2/3
	// zero) gives identical results.
	p := fecParityShard{BaseSeq: 5, DataShards: 4, ParityShards: 3, Index: 2,
		Data: make([]byte, fecLengthPrefixSize+4)}
	var f UDPCFrame
	f.Cmd = CMD_FEC
	if !p.applyToFrame(&f) {
		t.Fatal("legacy applyToFrame rejected")
	}
	got, err := parseFECParityFrameExt(&f, true)
	if err != nil || got.ParityShards != 3 || got.Index != 2 || got.DataShards != 4 {
		t.Fatalf("legacy frame via ext parse: %+v err=%v", got, err)
	}
}

func TestFECExtMetadataBounds(t *testing.T) {
	// m=9 is rejected even with ext negotiated (RS ceiling).
	p := fecParityShard{BaseSeq: 1, DataShards: 8, ParityShards: 9, Index: 0,
		Data: make([]byte, fecLengthPrefixSize), Ext: true}
	var f UDPCFrame
	if p.applyToFrame(&f) {
		t.Fatal("m=9 must be rejected")
	}
	// A legacy sender's frame with stray bits 2/3 (never sent by this code,
	// but defends the invariant) parses to the LOW bits only: the extension
	// is invisible to a peer that did not negotiate it.
	f2 := UDPCFrame{Cmd: CMD_FEC, Seq: 7, Data: make([]byte, fecLengthPrefixSize)}
	f2.Flags |= uint16(4-1) << fecParityShift // m=4
	f2.Flags |= uint16(1) << fecIndexShift    // idx=1
	f2.Flags |= fecParityExtFlag | fecIndexExtFlag
	got, err := parseFECParityFrameExt(&f2, false)
	if err != nil {
		t.Fatalf("legacy parse of stray bits: %v", err)
	}
	if got.ParityShards != 4 || got.Index != 1 {
		t.Fatalf("legacy parse saw extension bits: m=%d idx=%d", got.ParityShards, got.Index)
	}
	// With ext negotiated the same bits decode to the full values.
	got, err = parseFECParityFrameExt(&f2, true)
	if err != nil {
		t.Fatalf("ext parse: %v", err)
	}
	if got.ParityShards != 8 || got.Index != 5 {
		t.Fatalf("ext parse: m=%d idx=%d, want 8/5", got.ParityShards, got.Index)
	}
}
