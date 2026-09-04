package main

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
)

// n:n port spreading — CLIENT-SIDE reference implementation.
//
// The server already supports n:n with no changes:
//   - sessions are keyed by SessionID, not by address, so a client may send
//     from as many local ports as it likes;
//   - only a port change on the SAME IP is treated as NAT rebinding and is
//     accepted from any frame carrying a valid SessionID (see
//     ServerSession.updateRemoteAddr) — with n local sockets the client's
//     source port changes constantly, and the server simply follows it;
//   - every reply leaves from the port the packet was addressed to (origdst +
//     sendSockPool), so each of the n x n 4-tuples is symmetric.
//
// What the server does NOT need is any change at all: what it needs is a client
// that actually varies BOTH endpoints.
//
// Why bother? A carrier or ISP often rate-limits on the full 4-tuple
// (srcIP:srcPort, dstIP:dstPort), and a single local socket is also limited by
// one kernel send buffer / one lock. Spreading over K local sockets x N remote
// ports multiplies the tuple space to K*N and parallelises the write path.
//
// This type is the reference contract for client implementations (Stun, myssh,
// …). It lives in the server repo next to PortSelector so both sides stay in
// sync; the udp_custom client in this repo uses it directly.

// socketBufferSize is the SO_RCVBUF/SO_SNDBUF hint applied to UDP sockets on
// both ends of the tunnel. Best effort: kernels clamp it (Linux also needs
// net.core.rmem_max raised to honour the full value).
const socketBufferSize = 4 << 20 // 4 MiB

// spreadSocket is one local UDP socket plus its own destination-port selector.
type spreadSocket struct {
	conn *net.UDPConn
	sel  *PortSelector
}

// SpreadDialer spreads outgoing packets over K local sockets x N remote ports.
type SpreadDialer struct {
	serverIP   net.IP
	pr         *PortRange
	socks      []*spreadSocket
	rr         uint64 // round-robin cursor over sockets
	fixedPaths int    // chosen remote-port subset size; 0 = whole range
	closed     int32
	closeOnce  sync.Once
}

// NewSpreadDialer parses a server address that carries a port range
// (e.g. "1.1.1.1:25000-25499") and binds numSockets local UDP sockets.
// numSockets <= 0 means 1 (no local spreading).
//
// numPaths controls how many DISTINCT remote ports the client randomly picks
// from the range for the whole session (the client is the source of truth for
// path selection; the server mirrors each one back via IP_RECVORIGDSTADDR).
// numPaths <= 0 means the client spreads every packet across the ENTIRE range
// (the original behaviour) — set it to e.g. 32 to pin a fixed 32-port subset
// per session, which bounds the server's per-port reply-socket pool and the
// number of independent NAT mappings.
func NewSpreadDialer(serverAddr string, numSockets, numPaths int) (*SpreadDialer, error) {
	host, ports, err := ParseServerAddrWithRange(serverAddr)
	if err != nil {
		return nil, err
	}
	pr, err := NewPortRange(ports)
	if err != nil {
		return nil, err
	}
	if numSockets <= 0 {
		numSockets = 1
	}
	serverIP, err := resolveServerIP(host)
	if err != nil {
		return nil, err
	}

	// Selector pool: either the whole range (per-packet random) or a fixed
	// subset of numPaths ports chosen once for this session.
	selPR := pr
	fixedPaths := 0
	if numPaths > 0 {
		if chosen := pickPortsFromRange(pr, numPaths); len(chosen) > 0 {
			if fpr, e := NewPortRange(chosen); e == nil {
				selPR = fpr
				fixedPaths = len(chosen)
			}
		}
	}

	d := &SpreadDialer{serverIP: serverIP, pr: pr, socks: make([]*spreadSocket, 0, numSockets), fixedPaths: fixedPaths}
	network := "udp6"
	bindIP := net.IPv6unspecified
	if serverIP.To4() != nil {
		network = "udp4"
		bindIP = net.IPv4zero
	}
	for i := 0; i < numSockets; i++ {
		conn, err := net.ListenUDP(network, &net.UDPAddr{IP: bindIP, Port: 0})
		if err != nil {
			d.Close()
			return nil, fmt.Errorf("spread socket %d: %w", i, err)
		}
		// A single tunnel can burst hundreds of KB at once; the OS default
		// receive buffer (64 KiB on Windows) would silently drop a good part
		// of it and force needless retransmissions.
		_ = conn.SetReadBuffer(socketBufferSize)
		_ = conn.SetWriteBuffer(socketBufferSize)
		// Each socket gets its own selector: no shared RNG, no lock contention
		// on the send path.
		d.socks = append(d.socks, &spreadSocket{conn: conn, sel: NewPortSelector(selPR, SelectorRandom)})
	}
	return d, nil
}

func resolveServerIP(host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return append(net.IP(nil), ip...), nil
	}
	addrs, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("spread: resolve host %q: %w", host, err)
	}
	var ipv6 net.IP
	for _, ip := range addrs {
		if v4 := ip.To4(); v4 != nil {
			return append(net.IP(nil), v4...), nil
		}
		if ipv6 == nil && ip.To16() != nil {
			ipv6 = ip
		}
	}
	if ipv6 != nil {
		return append(net.IP(nil), ipv6...), nil
	}
	return nil, fmt.Errorf("spread: host %q has no IP address", host)
}

// Paths returns the number of distinct remote ports the client uses. 0 means
// the whole configured range is spread per-packet (no fixed subset).
func (d *SpreadDialer) Paths() int { return d.fixedPaths }

// pickPortsFromRange returns n distinct ports drawn uniformly at random from
// pr. If n >= pr.Total() the whole range is returned. Uses a per-call RNG so
// the spread is not predictable across sessions.
func pickPortsFromRange(pr *PortRange, n int) []int {
	total := pr.Total()
	if n <= 0 || total == 0 {
		return nil
	}
	if n >= total {
		out := make([]int, total)
		for i := 0; i < total; i++ {
			out[i] = pr.PortAt(i)
		}
		return out
	}
	// Sparse partial Fisher-Yates: only materialise the n swapped positions,
	// not the entire (potentially 65K-port) range.
	rng := rand.New(rand.NewSource(randomSeed()))
	swaps := make(map[int]int, n*2)
	out := make([]int, n)
	for i := 0; i < n; i++ {
		j := i + rng.Intn(total-i)
		vi := i
		if v, ok := swaps[i]; ok {
			vi = v
		}
		vj := j
		if v, ok := swaps[j]; ok {
			vj = v
		}
		swaps[i], swaps[j] = vj, vi
		out[i] = pr.PortAt(vj)
	}
	return out
}

// Len returns the number of local sockets.
func (d *SpreadDialer) Len() int { return len(d.socks) }

// PortRange returns the parsed remote port range.
func (d *SpreadDialer) PortRange() *PortRange { return d.pr }

func (d *SpreadDialer) acceptsRemote(addr *net.UDPAddr) bool {
	return addr != nil && addr.IP.Equal(d.serverIP) && d.pr.Contains(addr.Port)
}

// Next picks the next (socketIndex, remotePort) pair WITHOUT sending anything.
// Exposed for tests and for clients that want to batch their writes.
// Socket indices rotate round-robin; the port comes from that socket's own
// random selector.
func (d *SpreadDialer) Next() (int, int) {
	if len(d.socks) == 0 || atomic.LoadInt32(&d.closed) == 1 {
		return -1, 0
	}
	idx := int(atomic.AddUint64(&d.rr, 1)-1) % len(d.socks)
	return idx, d.socks[idx].sel.Next()
}

// SendAt writes a frame from a specific local socket to a freshly chosen
// remote port.
func (d *SpreadDialer) SendAt(idx int, frame []byte) error {
	if atomic.LoadInt32(&d.closed) == 1 {
		return fmt.Errorf("spread: dialer closed")
	}
	if idx < 0 || idx >= len(d.socks) {
		return fmt.Errorf("spread: socket index %d out of range (have %d)", idx, len(d.socks))
	}
	port := d.socks[idx].sel.Next()
	dst := &net.UDPAddr{IP: d.serverIP, Port: port}
	_, err := d.socks[idx].conn.WriteToUDP(frame, dst)
	return err
}

// Send writes a frame using the round-robin socket and that socket's port
// selection. Call it once per datagram: the (socket, port) pair is what
// produces the n x n tuple spread.
func (d *SpreadDialer) Send(frame []byte) error {
	idx, port := d.Next()
	if idx < 0 {
		return fmt.Errorf("spread: dialer closed")
	}
	_, err := d.socks[idx].conn.WriteToUDP(frame, &net.UDPAddr{IP: d.serverIP, Port: port})
	return err
}

// Conn returns the underlying socket at idx so the client can run its own
// receive loop on each of them. Replies come back to the socket whose source
// port the server last saw, so the client must drain ALL sockets.
func (d *SpreadDialer) Conn(idx int) *net.UDPConn {
	if idx < 0 || idx >= len(d.socks) {
		return nil
	}
	return d.socks[idx].conn
}

// Conns returns every local socket.
func (d *SpreadDialer) Conns() []*net.UDPConn {
	out := make([]*net.UDPConn, 0, len(d.socks))
	for _, s := range d.socks {
		out = append(out, s.conn)
	}
	return out
}

// Close releases every local socket.
func (d *SpreadDialer) Close() {
	d.closeOnce.Do(func() {
		atomic.StoreInt32(&d.closed, 1)
		for _, s := range d.socks {
			_ = s.conn.Close()
		}
	})
}
