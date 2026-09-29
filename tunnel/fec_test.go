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
		if dataCap+fecLengthPrefixSize+fecParityHeaderSize > recordCap {
			t.Fatalf("data cap %d cannot fit parity metadata in record payload cap %d", dataCap, recordCap)
		}
	}
}

func TestFECParityMarshalRoundTrip(t *testing.T) {
	want := fecParityShard{
		BaseSeq:      41,
		DataShards:   8,
		ParityShards: 3,
		Index:        2,
		ShardSize:    7,
		Data:         []byte("1234567"),
	}
	wire := want.marshalBinary()
	if len(wire) == 0 {
		t.Fatal("marshal returned empty payload")
	}
	got, err := parseFECParity(wire)
	if err != nil {
		t.Fatalf("parseFECParity: %v", err)
	}
	if got.BaseSeq != want.BaseSeq || got.DataShards != want.DataShards || got.ParityShards != want.ParityShards ||
		got.Index != want.Index || got.ShardSize != want.ShardSize || !bytes.Equal(got.Data, want.Data) {
		t.Fatalf("round trip mismatch: got %+v, want %+v", got, want)
	}
}

func TestFECRecoversTwoMissingDataShards(t *testing.T) {
	var parity []fecParityShard
	sender := newFECSender(func(p fecParityShard) { parity = append(parity, p) })
	defer sender.close()
	// 8%% estimated loss selects three parity shards, enough to reconstruct two
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
		for _, r := range receiver.onParity(p.marshalBinary()) {
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
	sender.observeRemoteBasisPoints(800) // 8%% reported receive loss => 3 parity

	block := make([]fecSourceShard, fecDataShardsMax)
	for i := range block {
		block[i] = fecSourceShard{seq: uint64(i + 1), payload: []byte{byte(i)}}
	}
	sender.emitBlock(block)
	mu.Lock()
	got := count
	mu.Unlock()
	if got != 3 {
		t.Fatalf("remote loss feedback emitted %d parity shards, want 3", got)
	}
}
