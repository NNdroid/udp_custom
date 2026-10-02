package tunnel

import (
	"encoding/binary"
	"math/bits"
	"sort"
	"sync"
	"time"
)

const sackPayloadSize = 66 // receive credit (2), up to 512 admission bits (64)

// sendFlow is guarded by the session's unackedMu. Outstanding wire buffers
// remain owned until delivery ACK, including selectively acknowledged frames.
type sendFlow struct {
	max, cwnd, credit int
	ssthresh          int
	growth            int
	lastLoss          time.Time
	feedbackNo        uint64
	lastProbe         time.Time
	fastRepairs       int
	paceMu            sync.Mutex
	nextSend          time.Time
}

func newSendFlow(maximum int, automatic bool) *sendFlow {
	if automatic {
		maximum = deliveryWindow
	}
	maximum = min(max(maximum, 1), deliveryWindow)
	return &sendFlow{max: maximum, cwnd: min(64, maximum), credit: deliveryWindow, ssthresh: maximum}
}

func (f *sendFlow) window() int { return min(f.cwnd, f.credit) }

func (f *sendFlow) acknowledged(n int) {
	if f.cwnd < f.ssthresh {
		f.cwnd = min(f.max, f.cwnd+n)
		return
	}
	f.growth += n
	if f.growth >= f.cwnd {
		f.growth -= f.cwnd
		f.cwnd = min(f.max, f.cwnd+1)
	}
}

func (f *sendFlow) loss(now time.Time, rtt time.Duration) {
	if rtt < 10*time.Millisecond {
		rtt = 10 * time.Millisecond
	}
	if !f.lastLoss.IsZero() && now.Sub(f.lastLoss) < rtt {
		return
	}
	f.lastLoss = now
	f.ssthresh = max(2, f.cwnd/2)
	f.cwnd = min(f.max, f.ssthresh)
	f.growth = 0
}

// Pace a small burst rather than creating one timer per datagram. All DATA,
// repair DATA and FEC share this budget; control feedback is never held here.
func (f *sendFlow) waitBurst(n, window int, rtt time.Duration, done <-chan struct{}) bool {
	if rtt <= 0 {
		return true
	}
	f.paceMu.Lock()
	now := time.Now()
	when := f.nextSend
	if when.Before(now) {
		when = now
	}
	f.nextSend = when.Add(time.Duration(n) * rtt / time.Duration(max(window, 1)))
	delay := when.Sub(now)
	f.paceMu.Unlock()
	if delay <= 0 {
		return true
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-done:
		return false
	}
}

func encodeSACK(credit uint16, bitmap uint64, extra ...uint64) []byte {
	words := [8]uint64{bitmap}
	copy(words[1:], extra)
	n := len(words)
	for n > 0 && words[n-1] == 0 {
		n--
	}
	p := make([]byte, 2+n*8)
	binary.BigEndian.PutUint16(p, credit)
	for i := 0; i < n; i++ {
		binary.BigEndian.PutUint64(p[2+i*8:], words[i])
	}
	return p
}

// updateSACK rejects feedback outside the sent sequence range. Authenticated
// but reordered control records cannot regress receive credit.
func updateSACK(flow *sendFlow, outstanding map[uint64]*unackedPkt, f *UDPCFrame, highest uint64, rtt time.Duration) (wire []byte, valid bool) {
	if flow == nil || len(f.Data) < 2 || len(f.Data) > sackPayloadSize || (len(f.Data)-2)%8 != 0 || f.Ack > highest || f.PacketNo <= flow.feedbackNo {
		return nil, false
	}
	var words [8]uint64
	count := 0
	for i := 0; i < (len(f.Data)-2)/8; i++ {
		words[i] = binary.BigEndian.Uint64(f.Data[2+i*8:])
		if words[i] != 0 && highest-f.Ack < uint64(i*64+bits.Len64(words[i])) {
			return nil, false
		}
		count += bits.OnesCount64(words[i])
	}
	credit := int(binary.BigEndian.Uint16(f.Data))
	if credit > deliveryWindow {
		return nil, false
	}
	flow.feedbackNo = f.PacketNo
	flow.credit = credit
	for word, bitsLeft := range words {
		for bitsLeft != 0 {
			bit := bits.TrailingZeros64(bitsLeft)
			if p := outstanding[f.Ack+uint64(word*64+bit)+1]; p != nil {
				p.sacked = true
			}
			bitsLeft &= bitsLeft - 1
		}
	}
	// Three later admissions are evidence of a gap, not a single reordered
	// datagram. Give FEC and natural reordering a quarter RTT to fill it.
	if count < 3 {
		return nil, true
	}
	seq := f.Ack + 1
	p := outstanding[seq]
	now := time.Now()
	guard := max(5*time.Millisecond, rtt/4)
	if p == nil || p.sacked || now.Sub(p.sentTime) < guard || p.retries >= clientMaxRetries {
		return nil, true
	}
	p.retries++
	p.sentTime = now
	flow.fastRepairs++
	flow.loss(now, rtt)
	return p.wire, true
}

type retryFrame struct {
	seq  uint64
	wire []byte
}

func nextRetryDelay(outstanding map[uint64]*unackedPkt, flow *sendFlow, now time.Time) time.Duration {
	delay := time.Second
	interval, probe := creditProbeInterval(flow, outstanding)
	for _, p := range outstanding {
		if p.sacked {
			continue
		}
		if p.queued {
			continue
		}
		delay = min(delay, p.rto-now.Sub(p.sentTime))
	}
	if probe {
		delay = min(delay, interval-now.Sub(flow.lastProbe))
	}
	return max(time.Millisecond, delay)
}

func notifyRetry(ch chan struct{}) {
	if ch != nil {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// retryDue bounds retransmission bursts and sends in sequence order. SACKed
// frames still reside in the receiver's bounded queue, so need no repair.
func retryDue(outstanding map[uint64]*unackedPkt, now time.Time, maximumRTO time.Duration, flow *sendFlow, rtt time.Duration) ([][]byte, bool) {
	// Most wakeups only register a fresh transmission or feedback. Do not
	// allocate a sorting buffer until a packet actually needs repair.
	var due []retryFrame
	for seq, p := range outstanding {
		if p.queued || p.sacked || now.Sub(p.sentTime) < p.rto {
			continue
		}
		if p.retries >= clientMaxRetries {
			return nil, true
		}
		due = append(due, retryFrame{seq, p.wire})
	}
	sort.Slice(due, func(i, j int) bool { return due[i].seq < due[j].seq })
	if len(due) > 16 {
		due = due[:16]
	}
	wires := make([][]byte, 0, len(due))
	for _, d := range due {
		p := outstanding[d.seq]
		p.retries++
		p.sentTime = now
		p.rto = min(p.rto*3/2, maximumRTO)
		wires = append(wires, d.wire)
	}
	if len(wires) > 0 && flow != nil {
		flow.loss(now, rtt)
	}
	return wires, false
}
