package tunnel

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"runtime/pprof"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// latency_probe_test.go measures interactive (web-like) latency through the
// tunnel: serial small request/response round trips, the multi-port spread of
// the default configuration, session setup cost and the loss-recovery tail.
// It exists because bulk throughput numbers hide the thing users feel most —
// how long a page takes to open.

// rangeRelay emulates the production DNAT+origdst topology on loopback: it
// listens on every port of a contiguous range and forwards each to the single
// server port, mirroring the reply back FROM THE SAME PORT (exactly what
// `replyFromOrigPort` does behind a real DNAT). delay is per direction, lossPct
// drops random datagrams both ways.
type rangeRelay struct {
	lo, hi  int
	conns   []*net.UDPConn
	ups     []*net.UDPConn
	down    []*delayedLink
	up      []*delayedLink
	client  []atomic.Value // *net.UDPAddr, per port
	delay   time.Duration
	lossPct int
	closed  atomic.Bool
	fwdUp   atomic.Int64 // datagrams relayed server -> client
	fwdDown atomic.Int64 // datagrams relayed client -> server
}

// delayedLink is a FIFO delay line with optional random loss. Every datagram
// enters with a due time and leaves in ARRIVAL ORDER from a single goroutine.
//
// The earlier version scheduled one time.AfterFunc per datagram, so the delay
// was also a randomiser: two packets queued 1us apart could leave in either
// order, and the tunnel then spent its time repairing SACK gaps the harness
// invented. A real path — even a congested one — preserves the order of the
// packets that survive, so the line must too, or the measurements describe the
// harness instead of the tunnel.
type delayedLink struct {
	mu      sync.Mutex
	cond    *sync.Cond
	q       []delayedPkt
	delay   time.Duration
	lossPct int
	rng     *rand.Rand
	out     func([]byte)
	closed  atomic.Bool
}

type delayedPkt struct {
	at time.Time
	p  []byte
}

func newDelayedLink(delay time.Duration, lossPct int, seed int64, out func([]byte)) *delayedLink {
	l := &delayedLink{delay: delay, lossPct: lossPct, rng: rand.New(rand.NewSource(seed)), out: out}
	l.cond = sync.NewCond(&l.mu)
	go l.run()
	return l
}

func (l *delayedLink) push(p []byte) {
	l.mu.Lock()
	if l.lossPct > 0 && l.rng.Intn(100) < l.lossPct {
		l.mu.Unlock()
		return
	}
	l.q = append(l.q, delayedPkt{time.Now().Add(l.delay), p})
	l.cond.Signal()
	l.mu.Unlock()
}

func (l *delayedLink) close() {
	l.closed.Store(true)
	l.mu.Lock()
	l.q = nil
	l.mu.Unlock()
	l.cond.Broadcast()
}

func (l *delayedLink) run() {
	for {
		l.mu.Lock()
		for len(l.q) == 0 && !l.closed.Load() {
			l.cond.Wait()
		}
		if l.closed.Load() {
			l.mu.Unlock()
			return
		}
		head := l.q[0]
		l.q = l.q[1:]
		l.mu.Unlock()
		if wait := time.Until(head.at); wait > 0 {
			timer := time.NewTimer(wait)
			<-timer.C
			timer.Stop()
		}
		if l.closed.Load() {
			return
		}
		l.out(head.p)
	}
}

// findPortBlock returns a contiguous block of n free loopback UDP ports at or
// above base, or an error if none was found.
func findPortBlock(n, base int) (int, error) {
	for start := base; start < base+2000; start += 64 {
		ok := true
		var held []*net.UDPConn
		for p := start; p < start+n; p++ {
			c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: p})
			if err != nil {
				ok = false
				break
			}
			held = append(held, c)
		}
		for _, c := range held {
			c.Close()
		}
		if ok {
			return start, nil
		}
	}
	return 0, fmt.Errorf("no free contiguous UDP block of %d ports", n)
}

func newRangeRelay(t *testing.T, serverAddr string, n int, delay time.Duration, lossPct int) *rangeRelay {
	t.Helper()
	lo, err := findPortBlock(n, 24000)
	if err != nil {
		t.Fatalf("port block: %v", err)
	}
	r := &rangeRelay{lo: lo, hi: lo + n - 1, delay: delay, lossPct: lossPct}
	if err := r.bind(t, serverAddr); err != nil {
		t.Fatalf("relay bind: %v", err)
	}
	return r
}

// bind opens one socket per relay port plus its upstream, and wires one
// ordered delay line per direction per port.
func (r *rangeRelay) bind(t *testing.T, serverAddr string) error {
	t.Helper()
	srv, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return err
	}
	n := r.hi - r.lo + 1
	r.client = make([]atomic.Value, n)
	r.conns = make([]*net.UDPConn, n)
	r.ups = make([]*net.UDPConn, n)
	r.down = make([]*delayedLink, n)
	r.up = make([]*delayedLink, n)
	for i := 0; i < n; i++ {
		ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: r.lo + i})
		if err != nil {
			return err
		}
		up, err := net.DialUDP("udp", nil, srv)
		if err != nil {
			ln.Close()
			return err
		}
		r.conns[i], r.ups[i] = ln, up
		// The relay is a measurement device, not a bottleneck: a default 64 KB
		// receive buffer holds ~44 full records, so a paced batch of 16 plus a
		// pause in this goroutine was enough to drop datagrams that the path
		// itself would have carried. Ask for a few megabytes so any loss the
		// probes report belongs to the tunnel under test.
		_ = ln.SetReadBuffer(1 << 22)
		_ = ln.SetWriteBuffer(1 << 22)
		_ = up.SetReadBuffer(1 << 22)
		_ = up.SetWriteBuffer(1 << 22)
	}
	for i := 0; i < n; i++ {
		ln, up := r.conns[i], r.ups[i]
		// Each port is its own queue: packets spread across ports may arrive
		// out of order (that is the real multi-path behaviour under test),
		// but packets on one port never overtake each other.
		r.down[i] = newDelayedLink(r.delay, r.lossPct, int64(r.lo+i)*2+1, func(p []byte) {
			_, _ = up.Write(p)
			r.fwdDown.Add(1)
		})
		idx := i
		r.up[i] = newDelayedLink(r.delay, r.lossPct, int64(r.lo+i)*2+2, func(p []byte) {
			addr, _ := r.client[idx].Load().(*net.UDPAddr)
			if addr != nil {
				_, _ = ln.WriteToUDP(p, addr)
				r.fwdUp.Add(1)
			}
		})
	}
	for i := 0; i < n; i++ {
		go func(i int) { // client -> relay port -> server
			buf := make([]byte, 2048)
			for {
				n, addr, err := r.conns[i].ReadFromUDP(buf)
				if err != nil {
					return
				}
				r.client[i].Store(addr)
				r.down[i].push(append([]byte(nil), buf[:n]...))
			}
		}(i)
		go func(i int) { // server -> relay (same port) -> client
			buf := make([]byte, 2048)
			for {
				n, err := r.ups[i].Read(buf)
				if err != nil {
					return
				}
				r.up[i].push(append([]byte(nil), buf[:n]...))
			}
		}(i)
	}
	return nil
}

func (r *rangeRelay) Addr() string { return fmt.Sprintf("127.0.0.1:%d-%d", r.lo, r.hi) }

func (r *rangeRelay) Close() {
	r.closed.Store(true)
	for i := range r.conns {
		r.conns[i].Close()
		r.ups[i].Close()
		r.down[i].close()
		r.up[i].close()
	}
}

type echoRig struct {
	Client *Client
	Conn   net.Conn
	stop   func()
}

func startEchoRig(t *testing.T, relay *rangeRelay, srvAddr string, sockets, paths int) *echoRig {
	t.Helper()
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				io.Copy(conn, conn)
			}(c)
		}
	}()
	srv, err := NewServer(ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TargetAddr: "tcp://" + echoLn.Addr().String(),
		Passwords:  []string{"latency-psk"},
		Logger:     Nop,
	})
	if err != nil {
		echoLn.Close()
		t.Fatalf("NewServer: %v", err)
	}
	go srv.Start()
	addr := srv.conn.LocalAddr().String()
	stop := func() { srv.Close(); echoLn.Close() }
	if relay != nil {
		addr = relay.Addr()
		stop = func() { relay.Close(); srv.Close(); echoLn.Close() }
	}
	cli, err := NewClient(ClientConfig{
		ServerAddr: addr,
		Passwords:  []string{"latency-psk"},
		Logger:     Nop,
		Sockets:    sockets,
		Paths:      paths,
	})
	if err != nil {
		stop()
		t.Fatalf("NewClient: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	conn, err := cli.DialTunnel(ctx, DialOptions{})
	cancel()
	if err != nil {
		cli.Close()
		stop()
		t.Fatalf("DialTunnel: %v", err)
	}
	return &echoRig{Client: cli, Conn: conn, stop: func() {
		conn.Close()
		cli.Close()
		stop()
	}}
}

func percentile(d []time.Duration, p float64) time.Duration {
	if len(d) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), d...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[int(float64(len(s)-1)*p)]
}

func roundTrips(t *testing.T, conn net.Conn, req []byte, want int, n int) []time.Duration {
	t.Helper()
	out := make([]time.Duration, 0, n)
	resp := make([]byte, want)
	for i := 0; i < n; i++ {
		st := time.Now()
		conn.SetDeadline(time.Now().Add(15 * time.Second))
		if _, err := conn.Write(req); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		if _, err := io.ReadFull(conn, resp); err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		out = append(out, time.Since(st))
	}
	return out
}

// TestLatencyProbe_LoopbackRTT: algorithmic overhead on a clean loopback path.
func TestLatencyProbe_LoopbackRTT(t *testing.T) {
	rig := startEchoRig(t, nil, "", 1, 1)
	defer rig.stop()
	req := make([]byte, 64)
	d := roundTrips(t, rig.Conn, req, 64, 200)
	t.Logf("loopback serial RTT: p50=%v p95=%v max=%v", percentile(d, 0.5), percentile(d, 0.95), percentile(d, 1))
	if p95 := percentile(d, 0.95); p95 > 5*time.Millisecond {
		t.Errorf("tunnel p95 RTT on loopback = %v; algorithmic overhead should be < 5ms", p95)
	}
}

// TestLatencyProbe_DelayedSinglePort: 50 ms path, single socket/port baseline.
func TestLatencyProbe_DelayedSinglePort(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) { defer conn.Close(); io.Copy(conn, conn) }(c)
		}
	}()
	srv, err := NewServer(ServerConfig{
		ListenAddr: "127.0.0.1:0", TargetAddr: "tcp://" + echoLn.Addr().String(),
		Passwords: []string{"latency-psk"}, Logger: Nop,
	})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	defer srv.Close()
	relay := newRangeRelay(t, srv.conn.LocalAddr().String(), 1, 25*time.Millisecond, 0)
	defer relay.Close()
	cli, err := NewClient(ClientConfig{
		ServerAddr: relay.Addr(), Passwords: []string{"latency-psk"}, Logger: Nop,
		Sockets: 1, Paths: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	conn, err := cli.DialTunnel(ctx, DialOptions{})
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	req := make([]byte, 64)
	d := roundTrips(t, conn, req, 64, 60)
	t.Logf("50ms path (1 socket/1 port) serial RTT: p50=%v p95=%v max=%v", percentile(d, 0.5), percentile(d, 0.95), percentile(d, 1))
}

// TestLatencyProbe_DelayedDefaultSpread: the DEFAULT configuration (32 sockets,
// 32 ports) on a 50 ms path. This is the number the browser feels.
func TestLatencyProbe_DelayedDefaultSpread(t *testing.T) {
	relayPorts := 32
	lo, err := findPortBlock(relayPorts, 24000)
	if err != nil {
		t.Skipf("no free port block: %v", err)
	}
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) { defer conn.Close(); io.Copy(conn, conn) }(c)
		}
	}()
	srv, err := NewServer(ServerConfig{
		ListenAddr: "127.0.0.1:0", TargetAddr: "tcp://" + echoLn.Addr().String(),
		Passwords: []string{"latency-psk"}, Logger: Nop,
	})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	defer srv.Close()
	r := &rangeRelay{lo: lo, hi: lo + relayPorts - 1, delay: 25 * time.Millisecond}
	if err := r.bind(t, srv.conn.LocalAddr().String()); err != nil {
		t.Fatalf("relay bind: %v", err)
	}
	defer r.Close()
	cli, err := NewClient(ClientConfig{
		ServerAddr: r.Addr(), Passwords: []string{"latency-psk"}, Logger: Nop,
		Sockets: 32, Paths: 32,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	conn, err := cli.DialTunnel(ctx, DialOptions{})
	cancel()
	if err != nil {
		t.Fatalf("DialTunnel: %v", err)
	}
	defer conn.Close()
	req := make([]byte, 64)
	d := roundTrips(t, conn, req, 64, 80)
	t.Logf("50ms path DEFAULT (32 sockets/32 ports) serial RTT: p50=%v p95=%v max=%v", percentile(d, 0.5), percentile(d, 0.95), percentile(d, 1))
	if p95 := percentile(d, 0.95); p95 > 90*time.Millisecond {
		t.Errorf("default-spread p95 RTT = %v on a clean 50ms path; spread reordering is stalling the stream", p95)
	}
}

// pageLoadRig builds a 50ms/var-loss path around one session.
func pageLoadRig(t *testing.T, lossPct int) *echoRig {
	t.Helper()
	lo, err := findPortBlock(4, 24000)
	if err != nil {
		t.Skipf("no free port block: %v", err)
	}
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echoLn.Close() })
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				// "Web server": read one request, answer with a fixed 32 KB
				// body, repeat. Models an asset fetch, not an echo.
				body := make([]byte, 32*1024)
				req := make([]byte, 4096)
				for {
					if _, err := conn.Read(req); err != nil {
						return
					}
					if _, err := conn.Write(body); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	srv, err := NewServer(ServerConfig{
		ListenAddr: "127.0.0.1:0", TargetAddr: "tcp://" + echoLn.Addr().String(),
		Passwords: []string{"latency-psk"}, Logger: Nop,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	go srv.Start()
	r := &rangeRelay{lo: lo, hi: lo + 3, delay: 25 * time.Millisecond, lossPct: lossPct}
	if err := r.bind(t, srv.conn.LocalAddr().String()); err != nil {
		t.Fatalf("relay bind: %v", err)
	}
	t.Cleanup(r.Close)
	cli, err := NewClient(ClientConfig{
		ServerAddr: r.Addr(), Passwords: []string{"latency-psk"}, Logger: Nop,
		Sockets: 4, Paths: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cli.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	conn, err := cli.DialTunnel(ctx, DialOptions{})
	cancel()
	if err != nil {
		t.Fatalf("DialTunnel: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return &echoRig{Client: cli, Conn: conn, stop: func() {
		conn.Close()
		cli.Close()
		r.Close()
		srv.Close()
		echoLn.Close()
	}}
}

// TestLatencyProbe_PageLoad measures a web-like sequence: 30 serial exchanges
// of a 512-byte request and a 32 KB response — a page's worth of assets over a
// single SSH-carried stream. The lossless run is the floor; the 5% run is what
// a real lossy access link looks like.
func TestLatencyProbe_PageLoad(t *testing.T) {
	req := make([]byte, 512)
	for _, loss := range []int{0, 5} {
		rig := pageLoadRig(t, loss)
		// Warm up (estimator + FEC bootstrap).
		for i := 0; i < 5; i++ {
			roundTrips(t, rig.Conn, req, 32*1024, 1)
		}
		var total time.Duration
		var per, ttfb []time.Duration
		for i := 0; i < 30; i++ {
			st := time.Now()
			rig.Conn.SetDeadline(time.Now().Add(30 * time.Second))
			if _, err := rig.Conn.Write(req); err != nil {
				t.Fatal(err)
			}
			// First byte = request path + backend + first response frame.
			head := make([]byte, 1)
			if _, err := io.ReadFull(rig.Conn, head); err != nil {
				t.Fatalf("loss=%d iter %d ttfb: %v", loss, i, err)
			}
			ttfb = append(ttfb, time.Since(st))
			resp := make([]byte, 32*1024-1)
			if _, err := io.ReadFull(rig.Conn, resp); err != nil {
				t.Fatalf("loss=%d iter %d: %v", loss, i, err)
			}
			d := time.Since(st)
			per = append(per, d)
			total += d
		}
		t.Logf("page-load 30x(512B->32KB) loss=%d%%: total=%v p50=%v p95=%v max=%v | TTFB p50=%v p95=%v",
			loss, total, percentile(per, 0.5), percentile(per, 0.95), percentile(per, 1),
			percentile(ttfb, 0.5), percentile(ttfb, 0.95))
		rig.stop()
	}
}

// TestLatencyProbe_HandshakeUnderLoss measures session setup when the SYN/ACK
// themselves are lost — the reconnect path after a network blip.
func TestLatencyProbe_HandshakeUnderLoss(t *testing.T) {
	for _, loss := range []int{0, 5, 10} {
		rig := pageLoadRig(t, loss)
		const n = 6
		var mu sync.Mutex
		var durs []time.Duration
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				st := time.Now()
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				c, err := rig.Client.DialTunnel(ctx, DialOptions{})
				cancel()
				if err != nil {
					t.Errorf("loss=%d DialTunnel: %v", loss, err)
					return
				}
				mu.Lock()
				durs = append(durs, time.Since(st))
				mu.Unlock()
				c.Close()
			}()
		}
		wg.Wait()
		sort.Slice(durs, func(i, j int) bool { return durs[i] < durs[j] })
		t.Logf("setup loss=%d%%: %v", loss, durs)
		rig.stop()
	}
}

// TestLatencyProbe_BulkRate measures sustained single-stream throughput on the
// emulated path. With a 2048-frame window a 50ms path should sustain tens of
// Mbps; anything near a few hundred KB/s means the effective window collapsed.
func TestLatencyProbe_BulkRate(t *testing.T) {
	for _, delay := range []time.Duration{0, 25 * time.Millisecond} {
		for _, ports := range []int{1, 4} {
			lo, err := findPortBlock(ports, 24000)
			if err != nil {
				t.Skipf("no free port block: %v", err)
			}
			blk := make([]byte, 4*1024*1024)
			echoLn, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			go func() {
				for {
					c, err := echoLn.Accept()
					if err != nil {
						return
					}
					go func(conn net.Conn) {
						defer conn.Close()
						req := make([]byte, 64)
						for {
							if _, err := conn.Read(req); err != nil {
								return
							}
							if _, err := conn.Write(blk); err != nil {
								return
							}
						}
					}(c)
				}
			}()
			srv, err := NewServer(ServerConfig{
				ListenAddr: "127.0.0.1:0", TargetAddr: "tcp://" + echoLn.Addr().String(),
				Passwords: []string{"latency-psk"}, Logger: Nop,
			})
			if err != nil {
				t.Fatal(err)
			}
			go srv.Start()
			r := &rangeRelay{lo: lo, hi: lo + ports - 1, delay: delay}
			if err := r.bind(t, srv.conn.LocalAddr().String()); err != nil {
				t.Fatalf("bind: %v", err)
			}
			cli, err := NewClient(ClientConfig{
				ServerAddr: r.Addr(), Passwords: []string{"latency-psk"}, Logger: Nop,
				Sockets: ports, Paths: ports,
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			conn, err := cli.DialTunnel(ctx, DialOptions{})
			cancel()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := conn.Write([]byte("go")); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 64*1024)
			st := time.Now()
			var got int64
			conn.SetDeadline(time.Now().Add(8 * time.Second))
			for got < int64(len(blk)) {
				n, err := conn.Read(buf)
				if err != nil {
					dumpSessionState(t, cli, srv, "stall")
					var sb bytes.Buffer
					_ = pprof.Lookup("goroutine").WriteTo(&sb, 1)
					lines := strings.Split(sb.String(), "\n")
					for i, ln := range lines {
						if strings.Contains(ln, "tunnel.(*clientSession)") || strings.Contains(ln, "tunnel.(*ServerSession)") || strings.Contains(ln, "tunnel.(*transmitQueue)") || strings.Contains(ln, "tunnel.(*orderedDelivery)") || strings.Contains(ln, "sync.(*Cond)") {
							for j := i; j < len(lines) && j < i+12; j++ {
								t.Logf("GOROUTINE| %s", lines[j])
							}
						}
					}
					t.Fatalf("delay=%v ports=%d read at %d: %v", delay, ports, got, err)
				}
				got += int64(n)
			}
			el := time.Since(st)
			mbps := float64(got) * 8 / el.Seconds() / 1e6
			t.Logf("bulk delay=%v ports=%d: %d bytes in %v = %.2f Mbps (%.0f KB/s)",
				delay, ports, got, el, mbps, float64(got)/1024/el.Seconds())
			// A collapsed window lands near 1.8 Mbps — about eleven frames per
			// 50 ms round trip — which is what a fresh session used to do after
			// its opening burst was dropped. The floor only has to sit far
			// enough above that to be unambiguous.
			if delay > 0 && mbps < 25 {
				t.Errorf("bulk delay=%v ports=%d = %.1f Mbps; the window collapsed instead of filling the 50ms BDP", delay, ports, mbps)
			}
			conn.Close()
			cli.Close()
			r.Close()
			srv.Close()
			echoLn.Close()
		}
	}
}

// dumpSessionState prints the live window/credit/delivery state of every
// session on both ends, for diagnosing stalls.
func dumpSessionState(t *testing.T, cli *Client, srv *Server, why string) {
	t.Helper()
	if srv != nil {
		srv.sessions.Range(func(k, v any) bool {
			s, ok := v.(*ServerSession)
			if !ok {
				return true
			}
			s.unackedMu.Lock()
			outstanding := len(s.unacked)
			cwnd, credit, fb := 0, 0, uint64(0)
			if s.flow != nil {
				cwnd, credit, fb = s.flow.cwnd, s.flow.credit, s.flow.feedbackNo
			}
			lowest := s.lowestOutstanding
			sackedN, retriedN := 0, 0
			for _, p := range s.unacked {
				if p.sacked {
					sackedN++
				}
				if p.retries > 0 {
					retriedN++
				}
			}
			s.unackedMu.Unlock()
			s.delivery.mu.Lock()
			pending := len(s.delivery.pending)
			limit := s.delivery.limit
			s.delivery.mu.Unlock()
			s.flow.paceMu.Lock()
			next := time.Until(s.flow.nextSend).Round(time.Millisecond)
			s.flow.paceMu.Unlock()
			qlen := -1
			if s.tx != nil {
				qlen = len(s.tx.queue)
			}
			t.Logf("[%s:server] sid=%08X sendSeq=%d lowest=%d outstanding=%d sacked=%d retried=%d cwnd=%d credit=%d fbNo=%d paceDebt=%v txq=%d/32 | recv delivered=%d pending=%d/%d | srtt=%v rto=%v",
				why, s.sessionID, s.sendSeq.Load(), lowest, outstanding, sackedN, retriedN, cwnd, credit, fb, next, qlen,
				s.delivery.delivered.Load(), pending, limit, s.rttEst.SRTT(), s.rttEst.RTO())
			return true
		})
	}
	dumpClientSessionState(t, cli, why)
}

func dumpClientSessionState(t *testing.T, cli *Client, why string) {
	t.Helper()
	cli.sessions.Range(func(k, v any) bool {
		s, ok := v.(*clientSession)
		if !ok {
			return true
		}
		s.unackedMu.Lock()
		outstanding := len(s.unacked)
		cwnd, credit := 0, 0
		if s.flow != nil {
			cwnd, credit = s.flow.cwnd, s.flow.credit
		}
		s.unackedMu.Unlock()
		s.ackCoalesce.mu.Lock()
		lastValue, pend, lastAt := s.ackCoalesce.lastValue, s.ackCoalesce.pending, s.ackCoalesce.lastAt
		s.ackCoalesce.mu.Unlock()
		s.delivery.mu.Lock()
		pending := len(s.delivery.pending)
		limit := s.delivery.limit
		s.delivery.mu.Unlock()
		t.Logf("[%s:client] sid=%08X sendSeq=%d outstanding=%d cwnd=%d credit=%d | recv delivered=%d pending=%d/%d | ackCoalesce last=%d pend=%d lastAt=%v pktNo=%d | srtt=%v rto=%v",
			why, s.sid, s.sendSeq.Load(), outstanding, cwnd, credit,
			s.delivery.delivered.Load(), pending, limit,
			lastValue, pend, time.Since(lastAt).Round(time.Millisecond), s.sendPacketNo.Load(), s.rttEst.SRTT(), s.rttEst.RTO())
		return true
	})
}
