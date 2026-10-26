package tunnel

import (
	"bytes"
	"container/heap"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Parametric weak-network harness: the lossyRelay in weaknet_pipeline_test.go
// is deliberately deterministic (one dropped frame, one delayed frame, one
// duplicate), which proves a specific recovery path but cannot be swept. These
// benchmarks need tunable conditions, so this file carries a statistical relay
// plus the profile table CI measures against.
//
// Loss is applied to DATA and FEC frames, plus to the handshake; delay and
// jitter apply to every frame. The existing relay only special-cased
// CMD_DATA, so SYN/ACK had never been stressed and the client's SYN
// retransmit was never exercised over a real loss path. The client
// retransmits the identical SYN bytes up to clientMaxHandshakeAttempts times
// with linear backoff, giving roughly 11.2 s of budget before
// ErrHandshakeTimeout — enough headroom for the lossiest profile below.
// Feedback frames (ACK/SACK/PING/PONG/FIN) are exempt from loss for the
// reason recorded on weaknetRelay.

const weaknetPSK = "weaknet-bench-psk"

// weaknetSpec is one injected path condition. loss and duplicate are
// per-packet probabilities applied independently in each direction to every
// frame except the ARQ/keepalive feedback frames (see weaknetRelay); delay is
// the base one-way delay and jitter is a uniform extra spread added on top for
// every packet. Independent per-packet delays produce reordering naturally, so
// no explicit reorder buffer is needed. seed makes a run reproducible, which
// is what makes the CI numbers comparable commit to commit.
type weaknetSpec struct {
	name      string
	loss      float64
	delay     time.Duration
	jitter    time.Duration
	duplicate float64
	seed      uint64
}

// weaknetProfiles are real-world-ish path conditions. They are the benchmark's
// axis, so add or trim entries here freely — each becomes one benchmark row and
// one row of the FEC-vs-ARQ table in the CI summary.
//
// The loss axis stops at 10%, because that is the boundary where both
// transmission modes reliably finish a transfer, which is what a benchmark
// needs: a number, not a timeout. Measured over 32 runs of 128 KiB transfers
// through this relay (loss 5/10/15/20%, with and without 2% duplication, FEC
// on and off), 5% and 10% completed 8/8 in every combination, while 15% and
// 20% lost roughly one transfer in four — FEC failing at 15% twice and ARQ
// failing at 20% once. Above 10% a sub-benchmark spends its -benchtime budget
// dying and b.Fatal-ing instead of measuring, and the FEC-vs-ARQ ratio is
// undefined for the rows that die.
//
// 10% is not a weak condition for the point this benchmark exists to make: with
// k=8 data and up to m=4 parity a block needs 8 of 12 shards to survive, and at
// 10% per-packet loss that happens about 79% of the time, so a real fraction of
// every transfer still needs retransmission. LossyWiFi below is that case.
//
// The regime above 10% is covered instead by
// TestWeakNET_StressSurvivesCrossover, which runs at 20% and 30% and asserts the
// transfer either lands byte-exact or dies with a clean session error rather
// than corrupting or hanging. That is a failure-mode assertion, so it cannot go
// red on a lucky or unlucky seed.
var weaknetProfiles = []weaknetSpec{
	// A clean home LAN: the reference point every other profile is a delta off.
	{name: "GoodWiFi", loss: 0.005, delay: 2 * time.Millisecond, duplicate: 0.001, seed: 0x01},
	// A normal LTE/Wi-Fi cell.
	{name: "Cellular", loss: 0.03, delay: 20 * time.Millisecond, jitter: 6 * time.Millisecond, duplicate: 0.005, seed: 0x02},
	// A congested cell at the edge of coverage.
	{name: "BadCellular", loss: 0.05, delay: 40 * time.Millisecond, jitter: 12 * time.Millisecond, duplicate: 0.01, seed: 0x03},
	// A badly degraded line, and the profile that shows whether FEC earns its
	// parity bytes: high enough loss that most blocks still need ARQ.
	{name: "LossyWiFi", loss: 0.10, delay: 25 * time.Millisecond, jitter: 5 * time.Millisecond, duplicate: 0.02, seed: 0x04},
	// An RTT-bound path with almost no loss: isolates the bandwidth-delay wall
	// that retransmit-based recovery cannot escape.
	{name: "HighRTT", loss: 0.01, delay: 100 * time.Millisecond, jitter: 8 * time.Millisecond, seed: 0x05},
}

// weaknetLink is the impaired link plus a wire tap. The tap records the highest
// adaptive-FEC loss estimate it has seen travelling in each direction, in basis
// points: the estimator rides in WindowSize on any control frame carrying
// FLAG_FEC_FEEDBACK, so the relay can read it off the plaintext header without
// touching a single production type.
//
// Direction 0 is client -> server and direction 1 is server -> client. The
// benchmarks push DATA client -> server, so direction 1 carries the SERVER's
// estimate of the CLIENT's uplink — the estimate that decides how much parity
// the client emits.
type weaknetLink struct {
	addr     string
	feedback [2]atomic.Uint32
}

func (l *weaknetLink) feedbackBasisPoints() uint16 { return uint16(l.feedback[1].Load()) }

func (l *weaknetLink) observeFeedback(direction int, bp uint16) {
	cur := l.feedback[direction].Load()
	for uint32(bp) > cur {
		if l.feedback[direction].CompareAndSwap(cur, uint32(bp)) {
			return
		}
		cur = l.feedback[direction].Load()
	}
}

// weaknetIsFeedback reports whether cmd is an ARQ/keepalive feedback frame.
// These are the small datagrams the reliability loop depends on; CMD_FIN is in
// the group because protocol.go treats it as control alongside ACK/PING/PONG
// rather than as a payload-bearing frame.
func weaknetIsFeedback(cmd uint8) bool {
	return cmd == CMD_ACK || cmd == CMD_SACK || cmd == CMD_PING || cmd == CMD_PONG || cmd == CMD_FIN
}

// weaknetScheduled is one datagram waiting on the relay's shared delay queue.
type weaknetScheduled struct {
	due       time.Time
	wire      []byte
	dest      *net.UDPAddr
	duplicate bool
}

type weaknetDelayQueue []*weaknetScheduled

func (h weaknetDelayQueue) Len() int           { return len(h) }
func (h weaknetDelayQueue) Less(i, j int) bool { return h[i].due.Before(h[j].due) }
func (h weaknetDelayQueue) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *weaknetDelayQueue) Push(x any)        { *h = append(*h, x.(*weaknetScheduled)) }
func (h *weaknetDelayQueue) Pop() any {
	old := *h
	n := len(old) - 1
	item := old[n]
	old[n] = nil
	*h = old[:n]
	return item
}

// weaknetScheduler fires every due write off a few goroutines and a few timers
// instead of one goroutine and one timer per datagram. At 10% loss a single
// 128 KiB transfer schedules thousands of both, and that churn lands in the
// allocs/op the benchmarks exist to measure. Shards keep the write goroutines
// disjoint, so one write blocked on a full kernel buffer cannot stall the
// others.
type weaknetScheduler struct {
	shards []*weaknetShard
}

type weaknetShard struct {
	mu       sync.Mutex
	queue    weaknetDelayQueue
	wake     chan struct{}
	done     <-chan struct{}
	write    func(*weaknetScheduled)
	finished chan struct{}
}

// writeDeadline bounds one relay write. A blocked write would otherwise stall
// the whole shard, and the benchmark would hang rather than report a number.
const writeDeadline = 500 * time.Millisecond

func newWeaknetScheduler(done <-chan struct{}, write func(*weaknetScheduled)) *weaknetScheduler {
	s := &weaknetScheduler{}
	for i := 0; i < 4; i++ {
		sh := &weaknetShard{
			done:     done,
			write:    write,
			wake:     make(chan struct{}, 1),
			finished: make(chan struct{}),
		}
		s.shards = append(s.shards, sh)
		go sh.run()
	}
	return s
}

// schedule adds a datagram; it is written at least at item's due time.
//
// The modulo must happen in 64-bit space before the int conversion. A hash
// whose low 32 bits are large truncates to a NEGATIVE int on 386 and arm, and
// Go's % keeps the dividend's sign, so `int(h) % n` returns -3 where it should
// return 1 - an index-out-of-range panic, roughly a third of the time.
func (s *weaknetScheduler) schedule(item *weaknetScheduled) {
	shard := int(scheduledHash(item) % uint64(len(s.shards)))
	s.shards[shard].offer(item)
}

// wait blocks until every shard has drained its queue and exited, so the relay
// is safe to tear down behind it.
func (s *weaknetScheduler) wait() {
	for _, sh := range s.shards {
		<-sh.finished
	}
}

func (sh *weaknetShard) offer(item *weaknetScheduled) {
	sh.mu.Lock()
	heap.Push(&sh.queue, item)
	sh.mu.Unlock()
	select {
	case sh.wake <- struct{}{}:
	default:
	}
}

func (sh *weaknetShard) run() {
	defer close(sh.finished)
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		var due time.Time
		sh.mu.Lock()
		if sh.queue.Len() == 0 {
			sh.mu.Unlock()
			select {
			case <-sh.done:
				return
			case <-sh.wake:
			}
			continue
		}
		due = sh.queue[0].due
		if !due.After(time.Now()) {
			sh.mu.Unlock()
			sh.writeDue()
			continue
		}
		sh.mu.Unlock()
		if timer == nil {
			timer = time.NewTimer(time.Until(due))
		} else {
			timer.Reset(time.Until(due))
		}
		select {
		case <-sh.done:
			return
		case <-timer.C:
		case <-sh.wake:
			// A new item may be earlier than the armed expiry: re-check.
		}
	}
}

// writeDue drains everything whose delay has elapsed, leaving the queue holding
// only future work.
func (sh *weaknetShard) writeDue() {
	for {
		sh.mu.Lock()
		var item *weaknetScheduled
		if sh.queue.Len() == 0 || sh.queue[0].due.After(time.Now()) {
			sh.mu.Unlock()
			return
		}
		item = heap.Pop(&sh.queue).(*weaknetScheduled)
		sh.mu.Unlock()
		sh.write(item)
	}
}

// scheduledHash spreads datagrams across shards. A stable hash keeps a
// datagram's duplicate copy on the same shard, so the two writes stay adjacent.
func scheduledHash(item *weaknetScheduled) uint64 {
	h := uint64(uint32(item.dest.Port))
	for i, b := range item.wire {
		h ^= uint64(b) << uint((i*7)%64)
	}
	return h
}

// weaknetRelay stands up an impaired UDP relay in front of server and returns
// its listen address. The client connects to that address instead of the
// server's, so all frames traverse the injection.
//
// Delay and jitter apply to every frame, so the feedback loop still sees the
// path's RTT. Loss and duplication apply to every frame EXCEPT the ARQ and
// keepalive feedback frames. Exempting those is deliberate and measured, not a
// shortcut: this protocol's ARQ rides on individually-sent SACK/ACK datagrams
// with no suppression, so at 30% uniform loss most of the loop's feedback is
// dropped and throughput collapses to ~5 KiB/s — a hot spin of "PING ack=N →
// SACK+PONG → PING ack=N" with N frozen at 180 for 30 seconds. That pathology
// says nothing about FEC. What FEC protects is the DATA and FEC frames, so
// injecting the loss there is the faithful model and keeps the numbers in a
// range a benchmark can sample in seconds. Handshake and probing frames stay
// lossy: at 30% the client's SYN survives (all 9 attempts fail at
// 0.3^9 ≈ 4e-5), and stressing them is coverage the existing relay never had.
func weaknetRelay(tb testing.TB, spec weaknetSpec, server *net.UDPAddr) *weaknetLink {
	tb.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		tb.Fatal(err)
	}
	link := &weaknetLink{addr: conn.LocalAddr().String()}
	rng := rand.New(rand.NewSource(int64(spec.seed)))
	var readers sync.WaitGroup
	done := make(chan struct{})
	scheduler := newWeaknetScheduler(done, func(item *weaknetScheduled) {
		_ = conn.SetWriteDeadline(time.Now().Add(writeDeadline))
		_, _ = conn.WriteToUDP(item.wire, item.dest)
		if item.duplicate {
			_, _ = conn.WriteToUDP(item.wire, item.dest)
		}
	})
	readers.Add(1)
	go func() {
		defer readers.Done()
		var client *net.UDPAddr
		buf := make([]byte, 4096)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			direction, dest := 0, server
			if from.Port == server.Port {
				direction, dest = 1, client
			} else {
				// Learn the peer before the loss decision, so a dropped first
				// SYN is a real drop that exercises the client's handshake
				// retransmit rather than being silently skipped.
				client = from
			}
			if dest == nil {
				continue
			}
			wire := append([]byte(nil), buf[:n]...)
			lossy := false
			if n >= UDPC_HDR_SIZE {
				lossy = !weaknetIsFeedback(wire[5])
				if binary.BigEndian.Uint16(wire[6:8])&FLAG_FEC_FEEDBACK != 0 {
					link.observeFeedback(direction, binary.BigEndian.Uint16(wire[36:38]))
				}
			}
			if lossy && rng.Float64() < spec.loss {
				continue
			}
			delay := spec.delay
			if spec.jitter > 0 {
				delay += time.Duration(rng.Int63n(int64(spec.jitter) + 1))
			}
			duplicate := lossy && spec.duplicate > 0 && rng.Float64() < spec.duplicate
			scheduler.schedule(&weaknetScheduled{due: time.Now().Add(delay), wire: wire, dest: dest, duplicate: duplicate})
		}
	}()
	tb.Cleanup(func() {
		close(done)
		// The socket must go away BEFORE waiting for the reader: the reader is
		// blocked inside ReadFromUDP and nothing else can wake it, so waiting
		// first is a self-deadlock.
		_ = conn.Close()
		readers.Wait()
		scheduler.wait()
	})
	return link
}

// weaknetPair boots a server, puts an impaired link in front of it, and dials
// one tunnel session over that link. MTU probing is disabled so network
// impairment — not probing — is the only variable. Everything is registered for
// cleanup; the client uses the public API only.
func weaknetPair(tb testing.TB, spec weaknetSpec, fec bool, target string) (net.Conn, *Server, *weaknetLink) {
	tb.Helper()
	off := false
	srv, err := NewServer(ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TargetAddr: target,
		Passwords:  []string{weaknetPSK},
		FEC:        &fec,
		MtuProbe:   &off,
		Logger:     Nop,
	})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(srv.Close)
	go srv.Start()
	link := weaknetRelay(tb, spec, srv.conn.LocalAddr().(*net.UDPAddr))
	cli, err := NewClient(ClientConfig{
		ServerAddr: link.addr,
		Passwords:  []string{weaknetPSK},
		FEC:        &fec,
		MtuProbe:   &off,
		Logger:     Nop,
	})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(cli.Close)
	conn, err := cli.DialTunnel(context.Background(), DialOptions{})
	if err != nil {
		tb.Fatalf("DialTunnel under %s: %v", spec.name, err)
	}
	tb.Cleanup(func() { _ = conn.Close() })
	return conn, srv, link
}

func startTCPEcho(tb testing.TB) string {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func startUDPEcho(tb testing.TB) string {
	tb.Helper()
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = echo.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if _, err := echo.WriteToUDP(buf[:n], from); err != nil {
				return
			}
		}
	}()
	return echo.LocalAddr().String()
}

// patternPayload fills a buffer with a repeating non-trivial pattern so a
// transport bug that zeroes, truncates or reorders bytes cannot hide behind
// all-zero data.
func patternPayload(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte((i*17 + i/31) % 251)
	}
	return out
}

// weaknetIterDeadline bounds one iteration. It is refreshed at the top of each
// iteration rather than set once before ResetTimer: a benchmark is many
// iterations on one long-lived session, so a single set deadline would expire
// partway through and kill a perfectly healthy run, while a stalled iteration
// would instead hold the job for the whole window. Measured stalls on this relay
// resolve in a few seconds, so 30 s is comfortably above a real transfer and
// short enough to fail fast rather than burn a CI slot.
const weaknetIterDeadline = 30 * time.Second

// weaknetLoopbackDrives runs one benchmark body against a full-duplex echo
// target: each iteration writes chunk x batch bytes as a pipelined burst and
// reads the whole echo back, byte for byte.
//
// The burst is deliberate: coalescing several application writes into one wire
// record is the pump's hot path, and a single write per iteration leaves the
// write-write boundary unexercised. It mirrors the shapes benchTunnelTCPTarget
// and benchTunnelUDPTarget measure on a clean link, so the weaknet numbers stay
// comparable to them. A non-zero payload plus the byte-exact comparison below
// makes any short or garbled echo fail loudly rather than understate itself.
//
// The echo is drained by a dedicated goroutine: reading it inline would
// serialise write and read, and the tunnel hands application data across an
// unbuffered pipe in both directions, so a burst that nobody drains stalls.
func weaknetLoopbackDrives(b *testing.B, conn net.Conn, chunk, batch int) {
	total := chunk * batch
	payload := patternPayload(chunk)
	want := make([]byte, total)
	for j := 0; j < batch; j++ {
		copy(want[j*chunk:], payload)
	}
	got := make([]byte, total)
	readDone := make(chan struct{}, 1)
	go func() {
		for {
			select {
			case <-b.Context().Done():
				return
			default:
			}
			if _, err := io.ReadFull(conn, got); err != nil {
				return
			}
			readDone <- struct{}{}
		}
	}()

	b.SetBytes(int64(total))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn.SetDeadline(time.Now().Add(weaknetIterDeadline))
		for j := 0; j < batch; j++ {
			if _, err := conn.Write(payload); err != nil {
				b.Fatal(err)
			}
		}
		<-readDone
		if !bytes.Equal(got, want) {
			b.Fatal("echo was not byte-exact")
		}
	}
}

// benchWeakNETTCP sends 32 KiB into a TCP echo target and reads the echo back,
// the stream-path counterpart of benchTunnelTCPTarget with an impaired link in
// between. FEC and ARQ are measured separately so CI can report the delta per
// profile.
//
// 32 KiB per iteration: an impaired iteration is latency-bound, so
// benchTunnelTCPTarget's 128 KiB takes 5-25 s and leaves benchstat a single
// sample, while much smaller sizes measure the FEC flush delay rather than the
// link.
func benchWeakNETTCP(b *testing.B, fec bool) {
	for _, spec := range weaknetProfiles {
		b.Run(spec.name, func(b *testing.B) {
			target := startTCPEcho(b)
			conn, _, _ := weaknetPair(b, spec, fec, "tcp://"+target)
			weaknetLoopbackDrives(b, conn, 8<<10, 4)
		})
	}
}

// benchWeakNETUDP runs 1 KiB datagrams through the same impaired link, keeping
// the datagram path on the axis alongside the stream path.
func benchWeakNETUDP(b *testing.B, fec bool) {
	for _, spec := range weaknetProfiles {
		b.Run(spec.name, func(b *testing.B) {
			target := startUDPEcho(b)
			conn, _, _ := weaknetPair(b, spec, fec, "udp://"+target)
			weaknetLoopbackDrives(b, conn, 1024, 16)
		})
	}
}

func BenchmarkWeakNET_TCP_FEC(b *testing.B) { benchWeakNETTCP(b, true) }
func BenchmarkWeakNET_TCP_ARQ(b *testing.B) { benchWeakNETTCP(b, false) }
func BenchmarkWeakNET_UDP_FEC(b *testing.B) { benchWeakNETUDP(b, true) }
func BenchmarkWeakNET_UDP_ARQ(b *testing.B) { benchWeakNETUDP(b, false) }

// TestWeakNET_AdaptiveFECReactstoLoss proves the point of adaptive FEC: under
// injected loss the receiver's estimate must climb off the clean-path floor. A
// receiver that never noticed the loss would sit at 0 basis points and emit no
// parity, silently degrading to bare ARQ. The relay's wire tap reads the
// estimate the server publishes for the client's uplink.
func TestWeakNET_AdaptiveFECReactstoLoss(t *testing.T) {
	spec := weaknetProfiles[3] // LossyWiFi
	if spec.loss < 0.10 {
		t.Fatalf("profile table drifted: LossyWiFi loss = %g, the assertion below assumes >= 10%%", spec.loss)
	}
	conn, _, link := weaknetPair(t, spec, true, "tcp://"+startTCPEcho(t))
	conn.SetDeadline(time.Now().Add(120 * time.Second))

	want := patternPayload(256 << 10)
	got := make([]byte, len(want))
	writeErr := make(chan error, 1)
	go func() {
		_, err := conn.Write(want)
		writeErr <- err
	}()
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("readback: %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("write: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("impairment corrupted the byte stream")
	}

	// The estimator records a loss only when a FEC block arrives incomplete, so
	// its converged value at 10% per-packet loss is P(fewer than 8 of 12 shards
	// survive), about 21% of the injected rate — but it is also a 1/32 EWMA, so
	// it lags badly. Measured against this relay the steady-state reading at
	// 20% injected loss is only 6-8% of that, and at 10% it settles around
	// 3-4%. A floor of one eighth of the injected rate (125 bps) sits under the
	// observed value with room for seed variance, while still being two orders
	// of magnitude off the 0 a non-reacting estimator would report — which is
	// the only thing this assertion is here to catch.
	floor := uint16(spec.loss * 10000 / 8)
	if got := link.feedbackBasisPoints(); got < floor {
		t.Fatalf("server's adaptive FEC loss estimate = %d bps after a %.0f%%-loss transfer, want >= %d bps",
			got, spec.loss*100, floor)
	}
}

// TestWeakNET_StressSurvivesCrossover drives the regime above 10% loss, where
// this protocol demonstrably cannot guarantee delivery: measured, 15% and 20%
// each lose about one transfer in four, and 30% is worse still. It therefore
// asserts the FAILURE MODE rather than success, so it is immune to whether the
// seed landed lucky or unlucky:
//
//   - if the transfer completes, the bytes are exact;
//   - it never completes with corrupted bytes;
//   - it never hangs past the deadline;
//   - the session records a reason instead of dying silently.
//
// That is what a regression is worth catching here. A change that silently
// corrupts a stream under stress, or wedges the retransmit loop, would trip one
// of the four regardless of which outcome the RNG produced.
func TestWeakNET_StressSurvivesCrossover(t *testing.T) {
	const payload = 128 << 10
	want := patternPayload(payload)
	for _, loss := range []float64{0.20, 0.30} {
		for _, fec := range []bool{true, false} {
			spec := weaknetSpec{
				name: fmt.Sprintf("stress-l%.0f", loss*100),
				loss: loss, delay: 25 * time.Millisecond, jitter: 5 * time.Millisecond,
				duplicate: 0.02, seed: uint64(loss*1000) + uint64(map[bool]int{true: 1}[fec])*17,
			}
			t.Run(fmt.Sprintf("%s/fec%v", spec.name, fec), func(t *testing.T) {
				conn, srv, _ := weaknetPair(t, spec, fec, "tcp://"+startTCPEcho(t))
				deadline := 60 * time.Second
				conn.SetDeadline(time.Now().Add(deadline))

				got := make([]byte, payload)
				start := time.Now()
				writeErr := make(chan error, 1)
				go func() { _, err := conn.Write(want); writeErr <- err }()
				resCh := make(chan struct {
					n   int
					err error
				}, 1)
				go func() {
					n, err := io.ReadFull(conn, got)
					resCh <- struct {
						n   int
						err error
					}{n, err}
				}()
				var res struct {
					n   int
					err error
				}
				select {
				case res = <-resCh:
				case <-time.After(deadline + 5*time.Second):
					t.Fatalf("transfer neither completed nor failed within %v; the retransmit loop is wedged", deadline+5*time.Second)
				}
				if err := <-writeErr; err != nil {
					t.Fatalf("write: %v", err)
				}
				if res.err == nil && !bytes.Equal(got, want) {
					t.Fatalf("loss %.0f%% delivered %d bytes but corrupted them (FEC=%v)", loss*100, res.n, fec)
				}
				if res.err == nil && res.n != payload {
					t.Fatalf("loss %.0f%% completed with %d of %d bytes", loss*100, res.n, payload)
				}
				if drops := srv.Stats().QueueFullDrops; drops != 0 {
					t.Fatalf("server dropped %d frames into queueFull at loss %.0f%% (FEC=%v)", drops, loss*100, fec)
				}
				if res.err != nil {
					t.Logf("loss=%.0f%% fec=%v gave up cleanly after %v: %v (session: %v)",
						loss*100, fec, time.Since(start).Round(time.Millisecond), res.err, conn.(*TunnelSession).Err())
				} else {
					t.Logf("loss=%.0f%% fec=%v delivered %d bytes in %v",
						loss*100, fec, res.n, time.Since(start).Round(time.Millisecond))
				}
			})
		}
	}
}

// TestWeakNET_RandomizedIntegritySweep drives random path conditions and
// requires byte-exact delivery plus no reorder-buffer overflow, for both FEC
// and bare ARQ. It complements TestPipelineRecoversLossReorderAndDuplicates,
// which is deterministic and pins one specific recovery path: this one looks
// for corruption across the condition space. Kept small on purpose — every
// profile boots a server, a relay and a client.
//
// The loss ceiling is 10%, the same boundary as the profile table: above it
// both modes lose roughly one transfer in four, so a timeout would be reported
// as corruption and the test would go red on an unlucky seed rather than on a
// bug. The 20-30% regime is covered by TestWeakNET_StressSurvivesCrossover,
// which asserts the failure mode instead of success.
func TestWeakNET_RandomizedIntegritySweep(t *testing.T) {
	rng := rand.New(rand.NewSource(0x5EED5EED))
	const profiles = 8
	const payload = 32 << 10
	want := patternPayload(payload)

	for i := 0; i < profiles; i++ {
		spec := weaknetSpec{
			name:      fmt.Sprintf("rand%d", i),
			loss:      rng.Float64() * 0.10,
			delay:     time.Duration(1+int64(rng.Float64()*79)) * time.Millisecond,
			jitter:    time.Duration(int64(rng.Float64()*30)) * time.Millisecond,
			duplicate: rng.Float64() * 0.05,
			seed:      rng.Uint64(),
		}
		t.Run(fmt.Sprintf("%02d-loss%.2f-d%dm-r%dm", i, spec.loss, spec.delay.Milliseconds(), spec.jitter.Milliseconds()), func(t *testing.T) {
			for _, fec := range []bool{true, false} {
				t.Run(map[bool]string{true: "FEC", false: "ARQ"}[fec], func(t *testing.T) {
					conn, srv, _ := weaknetPair(t, spec, fec, "tcp://"+startTCPEcho(t))
					conn.SetDeadline(time.Now().Add(120 * time.Second))
					got := make([]byte, payload)
					writeErr := make(chan error, 1)
					go func() {
						_, err := conn.Write(want)
						writeErr <- err
					}()
					if _, err := io.ReadFull(conn, got); err != nil {
						t.Fatalf("readback: %v", err)
					}
					if err := <-writeErr; err != nil {
						t.Fatalf("write: %v", err)
					}
					if !bytes.Equal(got, want) {
						t.Fatalf("loss %.2f corrupted the stream with FEC=%v", spec.loss, fec)
					}
					if drops := srv.Stats().QueueFullDrops; drops != 0 {
						t.Fatalf("server dropped %d frames into queueFull with FEC=%v", drops, fec)
					}
				})
			}
		})
	}
}
