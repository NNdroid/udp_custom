package tunnel

import (
	"bytes"
	"sync"
	"testing"
	"time"
)

func TestFECParityForLoss(t *testing.T) {
	tests := []struct {
		loss float64
		want int
	}{
		{0, 0},
		{0.0049, 0},
		{0.005, 1},
		{0.0249, 1},
		{0.025, 2},
		{0.0599, 2},
		{0.06, 3},
		{0.1199, 3},
		{0.12, 4},
		{0.30, 4},
	}
	for _, tc := range tests {
		if got := fecParityForLoss(tc.loss); got != tc.want {
			t.Fatalf("fecParityForLoss(%v)=%d, want %d", tc.loss, got, tc.want)
		}
	}
}

func TestFECDataPayloadCapKeepsParityWithinRecordBudget(t *testing.T) {
	for _, recordCap := range []int{1394, 1144, 492} {
		dataCap := fecDataPayloadCap(recordCap)
		// A parity shard is [2-byte original length | DATA payload | padding].
		// The block metadata is carried by authenticated UDPC header fields.
		if dataCap+fecLengthPrefixSize > recordCap {
			t.Fatalf("data cap %d cannot fit parity shard in record payload cap %d", dataCap, recordCap)
		}
	}
}

func TestFECParityFrameMetadataRoundTrip(t *testing.T) {
	want := fecParityShard{
		BaseSeq:      41,
		DataShards:   8,
		ParityShards: 3,
		Index:        2,
		Data:         []byte("1234567"),
	}
	frame := &UDPCFrame{Cmd: CMD_FEC, Flags: FLAG_FEC_FEEDBACK}
	if !want.applyToFrame(frame) {
		t.Fatal("applyToFrame rejected valid parity shard")
	}
	if frame.Flags&FLAG_FEC_FEEDBACK == 0 {
		t.Fatal("FEC metadata clobbered protocol-wide feedback flag")
	}
	got, err := parseFECParityFrame(frame)
	if err != nil {
		t.Fatalf("parseFECParityFrame: %v", err)
	}
	if got.BaseSeq != want.BaseSeq || got.DataShards != want.DataShards || got.ParityShards != want.ParityShards ||
		got.Index != want.Index || !bytes.Equal(got.Data, want.Data) {
		t.Fatalf("round trip mismatch: got %+v, want %+v", got, want)
	}
}

func TestFECRecoversTwoMissingDataShards(t *testing.T) {
	var parity []fecParityShard
	sender := newFECSender(func(p fecParityShard) { parity = append(parity, p) })
	defer sender.close()
	// 8% estimated loss selects three parity shards, enough to reconstruct two
	// independently lost DATA records in the same block.
	sender.adaptive.local.observeValue(0.08, 1)
	sender.blocks = fecBootstrapBlocks

	block := make([]fecSourceShard, fecDataShardsMax)
	for i := range block {
		block[i] = fecSourceShard{
			seq:     uint64(i + 1),
			payload: []byte{byte(i), byte(i + 10), byte(i + 20)},
		}
	}
	sender.emitBlock(block)
	if len(parity) != 3 {
		t.Fatalf("got %d parity shards, want 3", len(parity))
	}

	receiver := newFECReceiver()
	missing := map[uint64]bool{3: true, 6: true}
	for _, src := range block {
		if !missing[src.seq] {
			receiver.onData(src.seq, src.payload)
		}
	}

	recovered := make(map[uint64][]byte)
	for _, p := range parity {
		frame := &UDPCFrame{Cmd: CMD_FEC}
		if !p.applyToFrame(frame) {
			t.Fatal("failed to build parity frame")
		}
		for _, r := range receiver.onParityFrame(frame) {
			recovered[r.Seq] = r.Payload
		}
	}
	for seq := range missing {
		got, ok := recovered[seq]
		if !ok {
			t.Fatalf("sequence %d was not recovered", seq)
		}
		if !bytes.Equal(got, block[seq-1].payload) {
			t.Fatalf("sequence %d payload=%x, want %x", seq, got, block[seq-1].payload)
		}
	}
	if receiver.feedbackBasisPoints() == 0 {
		t.Fatal("FEC recovery did not contribute to receive-side loss feedback")
	}
}

func TestFECSenderFlushesPartialBlock(t *testing.T) {
	ch := make(chan fecParityShard, 4)
	sender := newFECSender(func(p fecParityShard) { ch <- p })
	defer sender.close()

	for i := 0; i < 3; i++ {
		sender.add(uint64(i+1), []byte{byte(i + 1)})
	}

	select {
	case p := <-ch:
		if p.DataShards != 3 {
			t.Fatalf("partial block data shards=%d, want 3", p.DataShards)
		}
		if p.BaseSeq != 1 {
			t.Fatalf("partial block base=%d, want 1", p.BaseSeq)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("partial FEC block was not flushed")
	}
}

func TestFECRemoteLossFeedbackRaisesParity(t *testing.T) {
	var mu sync.Mutex
	var count int
	sender := newFECSender(func(fecParityShard) {
		mu.Lock()
		count++
		mu.Unlock()
	})
	defer sender.close()
	sender.blocks = fecBootstrapBlocks
	// Remote reports are intentionally smoothed with alpha=0.25. The first 8%
	// sample therefore becomes ~2%, which should raise a clean path from zero
	// parity to one parity shard without overreacting to a single report.
	sender.observeRemoteBasisPoints(800)

	block := make([]fecSourceShard, fecDataShardsMax)
	for i := range block {
		block[i] = fecSourceShard{seq: uint64(i + 1), payload: []byte{byte(i)}}
	}
	sender.emitBlock(block)
	mu.Lock()
	got := count
	mu.Unlock()
	if got != 1 {
		t.Fatalf("smoothed remote loss feedback emitted %d parity shards, want 1", got)
	}
}
