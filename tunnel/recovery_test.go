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
		flow := newSendFlow(256, false)
		out := make(map[uint64]*unackedPkt)
		for i := uint64(1); i <= 4; i++ {
			out[i] = &unackedPkt{wire: []byte{byte(i)}, sentTime: now, rto: 200 * time.Millisecond}
		}
		time.Sleep(10 * time.Millisecond)
		frame := &UDPCFrame{Cmd: CMD_SACK, PacketNo: 2, Data: encodeSACK(32, 0b1110)}
		wire, valid := updateSACK(flow, out, frame, 4, 20*time.Millisecond)
		if !valid || !bytes.Equal(wire, []byte{1}) {
			t.Fatalf("repair=%v valid=%v", wire, valid)
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
		due, abandoned := retryDue(out, time.Now(), time.Second, flow, 0)
		if abandoned || len(due) != 1 || due[0][0] != 1 {
			t.Fatalf("timeout repairs=%v abandoned=%v", due, abandoned)
		}
	})
}

func TestAdaptiveWindowLimitsAndLoss(t *testing.T) {
	f := newSendFlow(256, true)
	for i := 0; i < 32; i++ {
		f.acknowledged(64)
	}
	if f.cwnd != deliveryWindow {
		t.Fatalf("window=%d", f.cwnd)
	}
	f.loss(time.Now(), time.Millisecond)
	if f.cwnd != deliveryWindow/2 {
		t.Fatalf("loss window=%d", f.cwnd)
	}
	f.credit = 0
	if f.window() != 0 {
		t.Fatal("zero receive credit ignored")
	}
	f = newSendFlow(16, false)
	f.acknowledged(1000)
	if f.cwnd != 16 {
		t.Fatal("explicit cap ignored")
	}
}

func TestSACKCoversFullReceiveWindowAndLostCreditUpdate(t *testing.T) {
	f := newSendFlow(256, true)
	out := map[uint64]*unackedPkt{512: {wire: []byte("last")}}
	frame := &UDPCFrame{PacketNo: 1, Data: encodeSACK(1, 0, 0, 0, 0, 0, 0, 0, uint64(1)<<63)}
	if _, valid := updateSACK(f, out, frame, 512, 0); !valid || !out[512].sacked {
		t.Fatal("high window position was not selectively acknowledged")
	}
	f.credit = 0
	if !needsCreditProbe(f, map[uint64]*unackedPkt{}, time.Now()) {
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
		{PacketNo: 1, Data: encodeSACK(deliveryWindow+1, 0)},
	} {
		f := newSendFlow(256, true)
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
