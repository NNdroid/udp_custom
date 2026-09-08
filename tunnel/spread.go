package tunnel

import (
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
)

// n:n port spreading — CLIENT-SIDE reference implementation.
//
// The server already supports n:n with no changes:
//   - sessions are keyed by SessionID, not by address, so a client may send
//     from as many local ports as it likes;
//   - a port change on the SAME IP is treated as NAT rebinding after record
//     authentication (see ServerSession.updateRemoteAddr) — with n local
//     sockets the client's source port changes constantly, and the server
//     simply follows it;
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

// maxReceiveSockets caps the server's SO_REUSEPORT receive group. Eight
// readers already outrun the target-forwarding path; beyond that, file
// descriptors and kernel hash-table pressure buy nothing.
const maxReceiveSockets = 8

// spreadSocket is one local UDP socket plus its own destination-port selector.
type spreadSocket struct {
	mu   sync.RWMutex
	conn *net.UDPConn
	sel  *PortSelector
}

// SpreadDialer spreads outgoing packets over K local sockets x N remote ports.
type SpreadDialer struct {
	serverHost string
	serverIP   net.IP
	serverAddr netip.Addr
	destMu     sync.RWMutex
	pr         *PortRange
	socks      []*spreadSocket
	rr         uint64 // round-robin cursor over sockets
	fixedPaths int    // chosen remote-port subset size; 0 = whole range
	closed     int32
	closeOnce  sync.Once
	listenUDP  UDPListenFunc
}

// UDPListenFunc lets an embedding application create the unconnected UDP
// sockets used for port spreading (for example through Android VPN protect).
type UDPListenFunc func(network string, laddr *net.UDPAddr) (*net.UDPConn, error)

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
	return newSpreadDialer(serverAddr, numSockets, numPaths, nil)
}

func newSpreadDialer(serverAddr string, numSockets, numPaths int, listenUDP UDPListenFunc) (*SpreadDialer, error) {
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
	// Precomputed netip form: every datagram send builds its destination as
	// AddrPortFrom(serverAddr, port) — zero allocation on the hot path.
	var destAddr netip.Addr
	if v4 := serverIP.To4(); v4 != nil {
		destAddr = netip.AddrFrom4([4]byte(v4))
	} else {
		destAddr, _ = netip.AddrFromSlice(serverIP)
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

	d := &SpreadDialer{
		serverHost: host,
		serverIP:   serverIP, serverAddr: destAddr,
		pr: pr, socks: make([]*spreadSocket, 0, numSockets), fixedPaths: fixedPaths,
		listenUDP: listenUDP,
	}
	for i := 0; i < numSockets; i++ {
		conn, err := d.openSocket()
		if err != nil {
			d.Close()
			return nil, fmt.Errorf("spread socket %d: %w", i, err)
		}
		// Each socket gets its own selector: no shared RNG, no lock contention
		// on the send path.
		d.socks = append(d.socks, &spreadSocket{conn: conn, sel: NewPortSelector(selPR, SelectorRandom)})
	}
	return d, nil
}

func ipToAddr(ip net.IP) netip.Addr {
	if v4 := ip.To4(); v4 != nil {
		return netip.AddrFrom4([4]byte(v4))
	}
	addr, _ := netip.AddrFromSlice(ip)
	return addr
}

func (d *SpreadDialer) openSocket() (*net.UDPConn, error) {
	d.destMu.RLock()
	serverIP := append(net.IP(nil), d.serverIP...)
	d.destMu.RUnlock()
	network, bindIP := "udp6", net.IPv6unspecified
	if serverIP.To4() != nil {
		network, bindIP = "udp4", net.IPv4zero
	}
	laddr := &net.UDPAddr{IP: bindIP, Port: 0}
	var (
		conn *net.UDPConn
		err  error
	)
	if d.listenUDP != nil {
		conn, err = d.listenUDP(network, laddr)
	} else {
		conn, err = net.ListenUDP(network, laddr)
	}
	if err != nil {
		return nil, err
	}
	_ = conn.SetReadBuffer(socketBufferSize)
	_ = conn.SetWriteBuffer(socketBufferSize)
	return conn, nil
}

// refreshDestination re-resolves hostnames whenever a dead socket is rebuilt.
// Literal IP configurations remain allocation-free and unchanged.
func (d *SpreadDialer) refreshDestination() error {
	if net.ParseIP(d.serverHost) != nil {
		return nil
	}
	ip, err := resolveServerIP(d.serverHost)
	if err != nil {
		return err
	}
	addr := ipToAddr(ip)
	if !addr.IsValid() {
		return fmt.Errorf("spread: resolved host %q to an invalid address", d.serverHost)
	}
	d.destMu.Lock()
	d.serverIP = append(d.serverIP[:0], ip...)
	d.serverAddr = addr
	d.destMu.Unlock()
	return nil
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

func (d *SpreadDialer) acceptsRemote(addr netip.AddrPort) bool {
	d.destMu.RLock()
	serverAddr := d.serverAddr
	d.destMu.RUnlock()
	return addr.Addr() == serverAddr && d.pr.Contains(int(addr.Port()))
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
		return ErrNoRoute
	}
	if idx < 0 || idx >= len(d.socks) {
		return fmt.Errorf("spread: socket index %d out of range (have %d)", idx, len(d.socks))
	}
	port := d.socks[idx].sel.Next()
	d.destMu.RLock()
	serverAddr := d.serverAddr
	d.destMu.RUnlock()
	sock := d.socks[idx]
	sock.mu.RLock()
	_, err := sock.conn.WriteToUDPAddrPort(frame, netip.AddrPortFrom(serverAddr, uint16(port)))
	sock.mu.RUnlock()
	return err
}

// Send writes a frame using the round-robin socket and that socket's port
// selection. Call it once per datagram: the (socket, port) pair is what
// produces the n x n tuple spread.
func (d *SpreadDialer) Send(frame []byte) error {
	idx, port := d.Next()
	if idx < 0 {
		return ErrNoRoute
	}
	d.destMu.RLock()
	serverAddr := d.serverAddr
	d.destMu.RUnlock()
	sock := d.socks[idx]
	sock.mu.RLock()
	_, err := sock.conn.WriteToUDPAddrPort(frame, netip.AddrPortFrom(serverAddr, uint16(port)))
	sock.mu.RUnlock()
	return err
}

// Conn returns the underlying socket at idx so the client can run its own
// receive loop on each of them. Replies come back to the socket whose source
// port the server last saw, so the client must drain ALL sockets.
func (d *SpreadDialer) Conn(idx int) *net.UDPConn {
	if idx < 0 || idx >= len(d.socks) {
		return nil
	}
	d.socks[idx].mu.RLock()
	defer d.socks[idx].mu.RUnlock()
	return d.socks[idx].conn
}

// Conns returns every local socket.
func (d *SpreadDialer) Conns() []*net.UDPConn {
	out := make([]*net.UDPConn, 0, len(d.socks))
	for _, s := range d.socks {
		s.mu.RLock()
		out = append(out, s.conn)
		s.mu.RUnlock()
	}
	return out
}

// Reopen replaces one failed socket. Concurrent callers are coalesced by the
// failed-pointer comparison, so only the goroutine that still owns the current
// socket creates a replacement. Hostnames are re-resolved before binding.
func (d *SpreadDialer) Reopen(idx int, failed *net.UDPConn) (*net.UDPConn, error) {
	if atomic.LoadInt32(&d.closed) == 1 {
		return nil, ErrNoRoute
	}
	if idx < 0 || idx >= len(d.socks) {
		return nil, fmt.Errorf("spread: socket index %d out of range (have %d)", idx, len(d.socks))
	}
	sock := d.socks[idx]
	sock.mu.Lock()
	defer sock.mu.Unlock()
	if sock.conn != failed && sock.conn != nil {
		return sock.conn, nil
	}
	if err := d.refreshDestination(); err != nil {
		return nil, err
	}
	conn, err := d.openSocket()
	if err != nil {
		return nil, err
	}
	old := sock.conn
	sock.conn = conn
	if old != nil {
		_ = old.Close()
	}
	return conn, nil
}

// Close releases every local socket.
func (d *SpreadDialer) Close() {
	d.closeOnce.Do(func() {
		atomic.StoreInt32(&d.closed, 1)
		for _, s := range d.socks {
			s.mu.Lock()
			if s.conn != nil {
				_ = s.conn.Close()
			}
			s.mu.Unlock()
		}
	})
}
