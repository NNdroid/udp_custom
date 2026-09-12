package tunnel

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"

	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type ServerConfig struct {
	// ListenAddr is the SINGLE UDP port the server binds. A firewall DNAT
	// redirects the whole client port range onto this port. The server
	// recovers each client's original destination port via
	// IP_RECVORIGDSTADDR and replies from a per-port socket so the reply's
	// SOURCE port equals the port the client addressed — which is what lets a
	// CGNAT accept the reply.
	ListenAddr string   `json:"listen"`
	TargetAddr string   `json:"target"`
	Passwords  []string `json:"passwords"`
	Magic      uint32   `json:"magic"`
	PrivateKey string   `json:"privkey"`
	LogLevel   string   `json:"log_level"`
	// OrigDst enables IP_RECVORIGDSTADDR (Linux only). REQUIRED whenever the
	// client spreads across more than one destination port: without it every
	// reply leaves from ListenAddr and strict NATs drop it.
	OrigDst     bool `json:"origdst"`
	SendSockMax int  `json:"sendsock_max"` // LRU cap for per-port reply sockets (0 = 512)
	SendWindow  int  `json:"send_window"`  // max DATA frames in flight awaiting ACK (0 = 256)

	// MaxPkt is the largest v2 RECORD this server puts on the wire: 40-byte
	// header + payload + 16-byte authentication tag, i.e. the UDP payload
	// size. 0 (or an absent field) = 1450, the historical value.
	//
	// Why it exists: 1450 produces a 1478-byte IPv4 datagram (1450 + 8 UDP +
	// 20 IP) and therefore assumes a 1500-byte path MTU. On a link with a
	// smaller MTU — 1420 is typical of WireGuard and similar tunnels — those
	// datagrams are fragmented in flight and IPv4 fragments are routinely
	// dropped by CGNATs, so small frames work while large ones stall. Lower
	// it when the server sits behind such a path: 1200 survives every path
	// with an MTU >= 1248, 548 never fragments on IPv4 at all.
	//
	// It may only shrink below the ceiling. Receive buffers keep the ceiling
	// size, so lowering it on ONE side alone is always safe and never needs
	// the peer to be reconfigured.
	//
	// With MtuProbe enabled (the default) this value is the probe ceiling and
	// the fallback when no probe result arrives — not a value the operator
	// has to get right.
	MaxPkt int `json:"max_pkt"`

	// MtuProbe enables answering the client's path probes (CMD_MTU_PROBE) and
	// applying the converged size from CMD_MTU_COMMIT. nil (field absent) =
	// enabled. Set false to make the server behave exactly as before probing
	// existed: probes are dropped (clients fall back to their max_pkt) and
	// the upstream pump starts ungated.
	MtuProbe *bool `json:"-"`

	// PortRange is the UDP port range the firewall DNATs onto ListenAddr. It
	// is the single source of truth for the client port range: the server
	// uses it at runtime to validate that every recovered original-destination
	// port actually belongs to the expected range — a packet whose origdst
	// port falls outside it is a firewall/DNAT misconfiguration signal — and
	// the gen-nftables / gen-iptables helpers default their --range to it.
	// The server NEVER binds these ports.
	PortRange string `json:"port_range"`

	// AllowedTargets gates client-REQUESTED per-session forwarding endpoints
	// (the target a client may name in its handshake, e.g.
	// "tcp://127.0.0.1:22" / "udp://10.0.0.5:51820"). Patterns support '*'
	// (any sequence) and '?' (one character) in the host and in the port:
	//
	//	"tcp://127.0.0.1:*"      any TCP port on loopback
	//	"tcp://*.internal:22"    SSH on any *.internal host
	//	"udp://*:51820"          one UDP port on any host
	//
	// The network must match exactly. An empty/absent list means ONLY the
	// default 'target' is available: any client-supplied target is rejected
	// (the SYN is silently dropped, like every other handshake failure).
	// The default target is always reachable by omitting the request.
	AllowedTargets []string `json:"allowed_targets"`

	// Logger receives diagnostic output. When nil, the LogLevel string decides
	// verbosity on the standard logger; an injected Logger wins over LogLevel
	// entirely. Embedders wanting silence pass Nop.
	Logger Logger `json:"-"`

	// ReceiveSockets opens this many UDP sockets sharing ListenAddr via
	// SO_REUSEPORT (Linux only), each with its own read goroutine — one
	// receive loop per socket scales packet intake beyond a single core. The
	// kernel hashes the 4-tuple, so every datagram from one client source
	// socket always lands on the same receiver and per-session ordering is
	// preserved. 0/1 = single socket (default). On non-Linux platforms any
	// value above 1 is clamped to 1 with a startup warning.
	ReceiveSockets int `json:"receive_sockets"`
}

// defaultSendWindow is the cap on frames awaiting ACK before the target read
// loop blocks. 256 frames x ~1.3KB ≈ 345KB in flight, which bounds both the
// unacked map and the retransmit backlog for a stalled client.
const defaultSendWindow = 256

const (
	pathChallengeTTL  = 5 * time.Second
	maxPathChallenges = 8
)

type pathChallenge struct {
	token   [pathChallengeSize]byte
	expires time.Time
}

// synCacheTTL is how long a verified handshake nonce is remembered. It must
// exceed the ±300s timestamp acceptance window so a replayed SYN can never be
// re-verified after its cache entry expires.
const synCacheTTL = 10 * time.Minute

// synCacheMax caps the handshake idempotency cache (16B nonce + ~30B record).
const synCacheMax = 4096

type Server struct {
	cfg            ServerConfig
	conn           *net.UDPConn   // primary bound listener (also the fallback reply socket)
	recvConns      []*net.UDPConn // SO_REUSEPORT receive group; recvConns[0] == conn
	bindPort       int            // local port actually bound
	maxPkt         int            // largest record we put on the wire (see ServerConfig.MaxPkt)
	sockPool       *sendSockPool  // per-origdst-port reply sockets
	origDstOK      bool           // IP_RECVORIGDSTADDR enabled & working
	portRange      *PortRange     // configured client port range (DNAT target); nil = not set
	outOfRangePkts uint64         // packets whose origdst port fell outside portRange
	privKey        [32]byte
	hasPrivKey     bool
	sessions       sync.Map // uint32 -> *ServerSession
	closed         int32
	closeChan      chan struct{}
	logger         Logger // never nil after NewServer

	// dialTarget dials the backend for each session; defaultTargetDialer is
	// used unless NewServerWithDialer supplies one.
	dialTarget TargetDialer

	// events delivers SessionEvent notifications to the embedder's handler on
	// a dedicated goroutine (never on receive paths).
	events *eventBus[SessionEvent]

	// synCache remembers verified handshake nonces so a retransmitted/replayed
	// SYN gets the SAME ack resent (idempotent) instead of dialing the target
	// again. This kills both the replay-amplification and the
	// duplicate-target-connection problems at once.
	synCache *synCache

	// synLimiter rate-limits SYNs per source IP; handshakeSem caps the number
	// of concurrent (potentially slow) target dials.
	synLimiter   *synLimiter
	handshakeSem chan struct{}
	sendWindow   int
	maxRecvQueue int

	// Debug counters (read with atomic; only ever used for logging).
	origPortChanges uint64 // times a session's mirrored reply port changed
	sendViaPort     uint64 // replies sent through a per-port socket
	sendViaMain     uint64 // replies that fell back to the main socket
	queueFullDrops  uint64 // reorder-buffer overflows
	decodeFailures  uint64 // undecodable datagrams (junk/scans/mismatched peers)
	macFailures     uint64 // v2 authentication failures
	replayDrops     uint64 // authenticated session packets rejected by the replay window
}

func parseLogLevel(s string) int { return LogLevel(s) }

// The server NEVER advertises a port list. The client picks its own
// destination ports from the configured range (a firewall DNATs that range onto
// the single ListenAddr port), and the server learns each path's original
// destination port from IP_RECVORIGDSTADDR. This keeps the client the single
// source of truth for path selection and removes any client/server sync.

func (s *Server) logDebug(format string, v ...interface{}) {
	s.logger.Debugf(format, v...)
}

func (s *Server) logInfo(format string, v ...interface{}) {
	s.logger.Infof(format, v...)
}

func (s *Server) logWarn(format string, v ...interface{}) {
	s.logger.Warnf(format, v...)
}

func (s *Server) logError(format string, v ...interface{}) {
	s.logger.Errorf(format, v...)
}

// maxPayload is the largest plaintext payload one DATA record may carry. A
// Server built as a bare literal (maxPkt 0) falls back to the ceiling instead
// of yielding a negative buffer size.
func (s *Server) maxPayload() int { return effectivePayloadCap(s.maxPkt) }

// ReplayFilter implements the per-direction 2048-packet sliding window used by
// every established v2 frame. Packet number zero and packets older than the
// window are always rejected. There is deliberately no wrap-around: exhausting
// uint64 packet numbers closes the session before another nonce can be used.
type ReplayFilter struct {
	maxSeq  uint64
	seenMax bool
	window  [32]uint64
	mu      sync.Mutex
}

func (rf *ReplayFilter) Seen(seq uint64) bool {
	if seq == 0 {
		return true
	}
	rf.mu.Lock()
	defer rf.mu.Unlock()
	if !rf.seenMax {
		return false
	}
	if seq > rf.maxSeq {
		return false
	}
	behind := rf.maxSeq - seq
	if behind >= 2048 {
		return true
	}
	return (rf.window[behind/64] & (1 << (behind % 64))) != 0
}

func (rf *ReplayFilter) acceptLocked(seq uint64) bool {
	if seq == 0 {
		return false
	}
	if !rf.seenMax {
		rf.seenMax = true
		rf.maxSeq = seq
		rf.window[0] = 1
		return true
	}
	if seq > rf.maxSeq {
		diff := seq - rf.maxSeq
		if diff >= 2048 {
			rf.window = [32]uint64{}
		} else {
			for diff > 0 {
				step := diff
				if step > 64 {
					step = 64
				}
				for i := len(rf.window) - 1; i > 0; i-- {
					rf.window[i] = (rf.window[i] << step) | (rf.window[i-1] >> (64 - step))
				}
				rf.window[0] <<= step
				diff -= step
			}
		}
		rf.maxSeq = seq
		rf.window[0] |= 1
		return true
	}
	behind := rf.maxSeq - seq
	if behind >= 2048 {
		return false
	}
	wordIdx := behind / 64
	bitIdx := behind % 64
	if (rf.window[wordIdx] & (1 << bitIdx)) != 0 {
		return false
	}
	rf.window[wordIdx] |= 1 << bitIdx
	return true
}

func (rf *ReplayFilter) Accept(seq uint64) bool {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	return rf.acceptLocked(seq)
}

// Remove rolls back a just-accepted packet when a bounded receive queue could
// not retain it. This lets an exact retransmission be considered again.
func (rf *ReplayFilter) Remove(seq uint64) {
	if seq == 0 {
		return
	}
	rf.mu.Lock()
	defer rf.mu.Unlock()
	if !rf.seenMax || seq > rf.maxSeq || rf.maxSeq-seq >= 2048 {
		return
	}
	behind := rf.maxSeq - seq
	rf.window[behind/64] &^= 1 << (behind % 64)
}

// CheckAndAdd returns true for a replay/too-old packet, false for a newly
// accepted packet.
func (rf *ReplayFilter) CheckAndAdd(seq uint64) bool {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	return !rf.acceptLocked(seq)
}

type unackedPkt struct {
	wire      []byte    // immutable encoded frame; reused verbatim on retries
	firstSent time.Time // when the frame was first sent; used to sample RTT
	sentTime  time.Time
	rto       time.Duration
	retries   int
}

type ServerSession struct {
	server        *Server
	sessionID     uint32
	raddr         netip.AddrPort
	raddrMu       sync.RWMutex
	targetNetwork string
	targetAddr    string
	upstream      net.Conn // backend connection ("udp": datagram Writes preserved; otherwise stream)
	replayFilter  ReplayFilter

	// frameKeys is used by PSK-only sessions. Noise sessions use their transport
	// AEAD for both DATA and control records and leave this nil.
	frameKeys *FrameKeys

	sendPacketNo uint64
	sendSeq      uint64
	recvSeq      uint64

	rttEst *rttEstimator // adaptive RTO estimator (RFC 6298 + Karn's rule)

	// maxPkt is this session's frame budget, set by the client's
	// CMD_MTU_COMMIT after its path probe converges. Zero = no commit received
	// yet, so the server's configured budget applies. It only ever shrinks the
	// local value and never changes again once set.
	maxPkt int

	// mtuGate holds target->client traffic until the frame budget is known
	// (commit received) or the client is clearly not probing (its first DATA
	// arrived, or mtuCommitWait elapsed). Without the gate the server could
	// encode an oversized frame in the pre-commit window and strand it: a
	// retransmission reuses its exact encoded bytes and cannot be re-chunked.
	mtuGate     chan struct{}
	mtuGateOnce sync.Once

	recvQueue map[uint64][]byte
	recvMu    sync.Mutex

	unacked   map[uint64]*unackedPkt
	unackedMu sync.Mutex
	// unackedCond is broadcast when frames are ACKed (window space freed) and
	// when the session closes, waking senders parked on the send window.
	unackedCond *sync.Cond

	lastActive time.Time
	activeMu   sync.Mutex

	// lastOrigPort is the pre-DNAT destination port (recovered via
	// IP_RECVORIGDSTADDR) of the most recent inbound packet on this session.
	// Server-initiated traffic reuses it so the reply's SOURCE port matches the
	// port the client last contacted — the key to traversing a CGNAT.
	lastOrigPort int32
	// pathAddrs maps each server-side port this session has been seen on to
	// the client's public (post-NAT) address for that path.
	pathAddrs map[int]netip.AddrPort
	pathMu    sync.RWMutex

	challengeMu    sync.Mutex
	pathChallenges map[netip.Addr]pathChallenge

	closed    int32
	closeChan chan struct{}
	closeOnce sync.Once
}

func parseTargetNetworkAndAddr(raw string) (network, addr string) {
	raw = strings.TrimSpace(raw)
	lower := strings.ToLower(raw)
	if strings.HasPrefix(lower, "udp://") {
		return "udp", raw[len("udp://"):]
	}
	if strings.HasPrefix(lower, "tcp://") {
		return "tcp", raw[len("tcp://"):]
	}
	return "tcp", raw
}

// requestedTargetTLV returns the exact TLV bytes a target string encodes to on
// the wire. Used by the handshake to validate that the SYN carries no bytes
// beyond base + target + msg1.
func requestedTargetTLV(target string) []byte {
	if target == "" {
		return nil
	}
	var l [targetRequestTLVLen]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(target)))
	return append(l[:], target...)
}

// matchTargetPattern reports whether endpoint matches one allowed_targets
// pattern. Both sides use parseTargetNetworkAndAddr semantics: the network
// (tcp/udp) must be equal, and the host:port part is matched with '*'
// (any sequence) and '?' (one character) wildcards. Host matching is
// case-insensitive. Endpoints must name (or wildcard) the port explicitly;
// a pattern without a port only matches endpoints without one.
func matchTargetPattern(pattern, endpoint string) bool {
	pNet, pRest := parseTargetNetworkAndAddr(pattern)
	eNet, eRest := parseTargetNetworkAndAddr(endpoint)
	if pNet != eNet {
		return false
	}
	pHost, pPort, pErr := net.SplitHostPort(pRest)
	eHost, ePort, eErr := net.SplitHostPort(eRest)
	if pErr != nil || eErr != nil {
		// A bare port ("22") is a valid Go addr form; fall back to whole-string
		// matching so such endpoints remain expressible.
		return wildcardMatch(strings.ToLower(pRest), strings.ToLower(eRest))
	}
	return wildcardMatch(strings.ToLower(pHost), strings.ToLower(eHost)) &&
		wildcardMatch(pPort, ePort)
}

// wildcardMatch is glob matching with '*' and '?' only (no escapes needed for
// hostnames and ports).
func wildcardMatch(pattern, s string) bool {
	// Iterative two-pointer glob: backtracks only on the last '*'.
	var si, pi int
	star := -1
	starSi := 0
	for si < len(s) {
		if pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == s[si]) {
			si++
			pi++
			continue
		}
		if pi < len(pattern) && pattern[pi] == '*' {
			star = pi
			starSi = si
			pi++
			continue
		}
		if star >= 0 {
			pi = star + 1
			starSi++
			si = starSi
			continue
		}
		return false
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}

// targetAllowed reports whether a client-requested endpoint may be forwarded.
// An empty pattern list never allows a request (default-target only).
func targetAllowed(endpoint string, patterns []string) bool {
	for _, p := range patterns {
		if p = strings.TrimSpace(p); p != "" && matchTargetPattern(p, endpoint) {
			return true
		}
	}
	return false
}

// TargetDialer dials the backend for one session. network is "tcp" (byte
// stream semantics) or "udp" (datagram boundaries preserved end to end);
// address is the granted endpoint's host:port. The default dialer performs a
// plain net.Dial (5s timeout for TCP). Must be safe for concurrent use; it is
// called from handshake goroutines.
type TargetDialer func(ctx context.Context, sessionID uint32, network, address string) (net.Conn, error)

// defaultTargetDialer is the plain out-dial used by NewServer.
func defaultTargetDialer() TargetDialer {
	return func(ctx context.Context, _ uint32, network, address string) (net.Conn, error) {
		if network == "udp" {
			return net.Dial("udp", address)
		}
		var d net.Dialer
		return d.DialContext(ctx, "tcp", address)
	}
}

// NewServer builds a server with the standard backend dialer.
func NewServer(cfg ServerConfig) (*Server, error) {
	return NewServerWithDialer(cfg, nil)
}

// NewServerWithDialer builds a server whose sessions obtain their backend
// connection through dial. A nil dialer falls back to plain net.Dial against
// the granted target. The dialer is consulted AFTER the client's target
// request passed the AllowedTargets filter, with the granted network/address.
func NewServerWithDialer(cfg ServerConfig, dial TargetDialer) (*Server, error) {
	return newServer(cfg, dial, nil)
}

// NewServerWithConn builds a server on a CALLER-OWNED UDP socket — for
// embedders that already hold the socket (systemd socket activation, a
// shared port, tests). The conn becomes the primary receive socket and the
// fallback reply socket exactly like NewServer's own bind; it is closed by
// Server.Close. ListenAddr is derived from conn.LocalAddr() for logging and
// the reply-from-port logic; cfg.ListenAddr itself is ignored.
//
// The receive-socket fan-out (ReceiveSockets) is disabled in this mode: the
// injected socket is the whole group. Pre-set socket options (buffer sizes,
// origdst on Linux, SO_REUSEPORT) are the caller's responsibility.
func NewServerWithConn(cfg ServerConfig, conn *net.UDPConn, dial TargetDialer) (*Server, error) {
	if conn == nil {
		return nil, fmt.Errorf("server: nil UDP conn")
	}
	return newServer(cfg, dial, conn)
}

func newServer(cfg ServerConfig, dial TargetDialer, injected *net.UDPConn) (*Server, error) {
	passwords := make([]string, 0, len(cfg.Passwords))
	for _, password := range cfg.Passwords {
		if password = strings.TrimSpace(password); password != "" {
			passwords = append(passwords, password)
		}
	}
	if len(passwords) == 0 {
		return nil, fmt.Errorf("server: protocol v2 requires at least one password (PSK)")
	}
	cfg.Passwords = passwords
	if cfg.Magic == 0 {
		cfg.Magic = UDPC_MAGIC_DEFAULT
	}
	logger := resolveLogger(cfg.Logger, cfg.LogLevel)

	// Resolve the single bind port from ListenAddr. This is the port the
	// firewall DNATs the whole client range onto; the server NEVER binds the
	// range itself. A ":0" lets the OS pick a port (handy for tests, and
	// acceptable internally — for a real DNAT target the operator should set a
	// fixed port so the firewall rule is stable).
	bindIP := net.IPv4zero
	bindPort := 0
	if cfg.ListenAddr != "" {
		if la, err := net.ResolveUDPAddr("udp", cfg.ListenAddr); err == nil {
			if la.IP != nil {
				bindIP = la.IP
			}
			bindPort = la.Port
		}
	}
	if bindPort == 0 {
		logger.Warnf("'listen' port is 0 (got %q): the OS will assign an ephemeral port. For a DNAT target use a fixed port so the firewall rule is stable.", cfg.ListenAddr)
	}

	// Receive socket fan-out: SO_REUSEPORT group on Linux, clamped to a single
	// socket elsewhere. Every socket gets its own read goroutine; the first
	// (conn) remains the fallback reply socket. An injected conn (embedder
	// owned) replaces the whole group.
	var recvConns []*net.UDPConn
	var origDstOK bool
	if injected != nil {
		_ = injected.SetReadBuffer(socketBufferSize)
		_ = injected.SetWriteBuffer(socketBufferSize)
		if cfg.OrigDst {
			if serr := enableOrigDst(injected); serr != nil {
				logger.Warnf("origdst requested but enable failed: %v (replies will fall back to the main socket)", serr)
			} else {
				origDstOK = true
			}
		}
		recvConns = []*net.UDPConn{injected}
	} else {
		nRecv := cfg.ReceiveSockets
		if nRecv < 1 {
			nRecv = 1
		}
		if nRecv > 1 && !reuseportSupported {
			logger.Warnf("receive_sockets=%d requested but SO_REUSEPORT receive is Linux-only; clamping to 1", nRecv)
			nRecv = 1
		}
		if nRecv > maxReceiveSockets {
			logger.Warnf("receive_sockets=%d exceeds the %d-socket cap; clamping", nRecv, maxReceiveSockets)
			nRecv = maxReceiveSockets
		}

		conn, err := bindReuseportUDP(&net.UDPAddr{IP: bindIP, Port: bindPort})
		if err != nil {
			return nil, fmt.Errorf("failed to listen on %s: %w", cfg.ListenAddr, err)
		}
		// An inbound burst must not be dropped just because the default socket
		// buffer is small.
		_ = conn.SetReadBuffer(socketBufferSize)
		_ = conn.SetWriteBuffer(socketBufferSize)
		bindPort = conn.LocalAddr().(*net.UDPAddr).Port

		// Bind the remaining sockets of the reuseport group. A failure here (port
		// stolen between binds, SO_REUSEPORT unavailable despite the platform
		// check, ...) is non-fatal: the group shrinks and the warning explains why.
		recvConns = []*net.UDPConn{conn}
		for i := 1; i < nRecv; i++ {
			c2, berr := bindReuseportUDP(&net.UDPAddr{IP: bindIP, Port: bindPort})
			if berr != nil {
				logger.Warnf("receive socket %d/%d bind failed: %v (continuing with %d socket(s))", i+1, nRecv, berr, len(recvConns))
				break
			}
			_ = c2.SetReadBuffer(socketBufferSize)
			_ = c2.SetWriteBuffer(socketBufferSize)
			recvConns = append(recvConns, c2)
		}
	}
	conn := recvConns[0]
	nRecv := len(recvConns)
	bindPort = conn.LocalAddr().(*net.UDPAddr).Port

	// Recover the client's pre-DNAT destination port so replies can leave from
	// the port the client actually addressed. Required for port-range
	// spreading behind a CGNAT; a no-op (and harmlessly disabled) otherwise.
	// Every socket of the group needs the option — the kernel delivers a
	// session's packets to whichever socket its 4-tuple hashes to.
	if injected == nil && cfg.OrigDst {
		for _, c2 := range recvConns {
			if serr := enableOrigDst(c2); serr != nil {
				logger.Warnf("origdst requested but enable failed: %v (replies will fall back to the main socket)", serr)
			} else {
				origDstOK = true
			}
		}
	}

	// Record budget: how large a single v2 record may be on the wire. It
	// only ever shrinks below the ceiling, so a peer that has not been
	// reconfigured still receives everything we send.
	maxPkt := resolveMaxPkt(cfg.MaxPkt, logger)
	logger.Infof("📏 [mtu] %s", describeMaxPkt(maxPkt))

	// Resolve the configured client port range (the firewall DNATs the whole
	// range onto ListenAddr). This is the single source of truth used at
	// runtime to validate incoming origdst ports and by the gen-* helpers as
	// the default --range.
	pr := PortRangeOf(cfg.PortRange)
	if pr != nil {
		logger.Infof("📣 [port_range] configured client port range: %s (%d ports); ensure the firewall DNATs it onto %s",
			pr.String(), pr.Total(), conn.LocalAddr())
	}

	if dial == nil {
		dial = defaultTargetDialer()
	}

	srv := &Server{
		cfg:          cfg,
		conn:         conn,
		recvConns:    recvConns,
		bindPort:     bindPort,
		maxPkt:       maxPkt,
		sockPool:     newSendSockPool(cfg.SendSockMax, func(format string, v ...interface{}) { logger.Warnf("[SockPool] "+format, v...) }),
		origDstOK:    origDstOK,
		portRange:    pr,
		closeChan:    make(chan struct{}),
		logger:       logger,
		dialTarget:   dial,
		events:       newEventBus[SessionEvent](256),
		synCache:     newSynCache(),
		synLimiter:   newSynLimiter(5, 20),
		handshakeSem: make(chan struct{}, 64),
		sendWindow:   defaultSendWindow,
		maxRecvQueue: 512,
	}
	if cfg.SendWindow > 0 {
		srv.sendWindow = cfg.SendWindow
	}
	if nRecv > 1 {
		srv.logInfo("🔀 SO_REUSEPORT receive group: %d sockets sharing %s (one read goroutine each)", nRecv, conn.LocalAddr())
	}

	// allowed_targets pattern check: a typo'd pattern (e.g. "tcp:/127.0.0.1:*"
	// or a port wildcard outside the host:port form) never matches anything,
	// which would silently deny every client request. Warn at startup instead.
	for _, p := range cfg.AllowedTargets {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		// A pattern must be parseable into network + host:port with at least
		// one port-ish token; anything else can never match a real endpoint.
		_, rest := parseTargetNetworkAndAddr(p)
		if _, _, err := net.SplitHostPort(rest); err != nil && !strings.ContainsAny(rest, "*?") {
			logger.Warnf("allowed_targets pattern %q looks malformed (no port and no wildcard) and will never match", p)
		}
	}

	if laddr, err := net.ResolveUDPAddr("udp", cfg.ListenAddr); err == nil && laddr.IP != nil && laddr.IP.IsLoopback() {
		srv.logWarn("⚠️ Listening on loopback %s: external clients cannot reach a loopback-bound socket. Prefer 0.0.0.0:%d or the interface address.",
			laddr, laddr.Port)
	}

	if cfg.PrivateKey != "" {
		pk, err := ParseNoiseKey(cfg.PrivateKey)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("invalid noise private key: %w", err)
		}
		srv.privKey = pk
		srv.hasPrivKey = true
		srv.logInfo("🔐 Noise_NK AEAD encryption enabled")
	}
	srv.logInfo("🎯 Server bound %s (origdst=%v, sendsock_max=%d)", conn.LocalAddr(), origDstOK, srv.sockPool.limit)
	return srv, nil
}

func (s *Server) Start() error {
	netType, target := parseTargetNetworkAndAddr(s.cfg.TargetAddr)
	s.logInfo("UDP server: %s -> Target [%s] %s (origdst=%v)", s.conn.LocalAddr(), netType, target, s.origDstOK)
	s.logInfo("Protocol v2 authentication enabled with %d valid PSK(s)", len(s.cfg.Passwords))

	go s.cleanupLoop()

	for _, rc := range s.recvConns {
		go s.serveConn(rc)
	}
	select {
	case <-s.closeChan:
		return nil
	}
}

// serveConn is the read loop for one socket of the receive group. It batches
// datagram reception (packetReader: block on the first, drain the burst) and
// recovers the client's pre-DNAT destination port via IP_RECVORIGDSTADDR when
// origdst is enabled, so replies can be mirrored back from that port.
func (s *Server) serveConn(conn *net.UDPConn) {
	reader := newPacketReader(conn, s.logger)
	for {
		if atomic.LoadInt32(&s.closed) == 1 {
			return
		}
		pkts, err := reader.next()
		if err != nil {
			if atomic.LoadInt32(&s.closed) == 1 {
				return
			}
			s.logWarn("UDP read error: %v", err)
			return
		}
		for i := range pkts {
			pkt := &pkts[i]
			remoteAddr, origDstPort := pkt.from, pkt.origPort

			// If a port range is configured, every packet's pre-DNAT destination
			// port must fall inside it. A packet outside the range means the
			// firewall DNAT is not redirecting what we expect (misconfiguration),
			// and the reply would never reach the client. Count + warn (throttled)
			// so an operator can catch a range/firewall mismatch early.
			if s.portRange != nil && origDstPort > 0 && !s.portRange.Contains(origDstPort) {
				if n := atomic.AddUint64(&s.outOfRangePkts, 1); n == 1 || n%1000 == 0 {
					s.logWarn("⚠️ Packet from %s arrived on origdst port %d which is OUTSIDE the configured port_range %s — possible firewall/DNAT misconfiguration",
						remoteAddr, origDstPort, s.portRange.String())
				}
			}

			var frame UDPCFrame
			if err := decodeUDPCFrame(pkt.data, s.cfg.Magic, &frame); err != nil {
				// Invalid magic / version / structure. Counted so silent junk
				// (port scans, misconfigured peers) is visible in Stats.
				if n := atomic.AddUint64(&s.decodeFailures, 1); n == 1 || n%1000 == 0 {
					s.logWarn("⚠️ Undecodable datagram from %s (%d bytes): %v (count=%d)", remoteAddr, len(pkt.data), err, n)
				}
				continue
			}

			if s.loggerLevel() <= 0 {
				s.logDebug("[Recv] origDst=%d from=%s cmd=0x%02X seq=%d ack=%d sid=0x%08X len=%d",
					origDstPort, remoteAddr, frame.Cmd, frame.Seq, frame.Ack, frame.SessionID, len(pkt.data))
			}

			if frame.Cmd == CMD_HANDSHAKE_SYN {
				// Cheap DoS gates before anything expensive happens: per-IP rate
				// limit first, then the (verifying) handshake goroutine.
				if ip := ipOf(remoteAddr); !s.synLimiter.Allow(ip, time.Now()) {
					s.logWarn("[Handshake] 🚦 Rate-limited SYN from %s", remoteAddr)
					continue
				}
				if frame.SessionID != 0 || frame.PacketNo != 0 || frame.Seq != 0 || frame.Ack != 0 || len(frame.Data) < synPayloadBase {
					continue
				}
				var clientNonce [clientNonceSize]byte
				copy(clientNonce[:], frame.Data[:clientNonceSize])
				matchedPSK := matchSynPSK(frame.raw, s.cfg.Passwords, clientNonce)
				if matchedPSK == "" {
					s.logWarn("[Handshake] ❌ Rejected SYN from %s: frame MAC verification failed", remoteAddr)
					continue
				}
				// The receive buffer is reused on the next batch read while handshake
				// verification runs asynchronously, so retain this one payload.
				frame.Data = append([]byte(nil), frame.Data...)
				go s.handleHandshake(remoteAddr, &frame, origDstPort, matchedPSK)
				continue
			}

			// Dispatch to existing session.
			//
			// Established v2 frames are authenticated before the packet-number replay
			// window and command dispatcher are allowed to mutate session state.
			if sessVal, ok := s.sessions.Load(frame.SessionID); ok && sessVal != nil {
				sess := sessVal.(*ServerSession)
				sess.processIncomingFrame(&frame, remoteAddr, origDstPort)
			}
		}
	}
}

// processIncomingFrame is the complete post-handshake receive boundary. No
// session state may be changed until shape, authentication, packet-number
// replay and source-path checks all succeed.
func (sess *ServerSession) processIncomingFrame(frame *UDPCFrame, remoteAddr netip.AddrPort, origPort int) bool {
	if frame == nil {
		return false
	}
	if !validSessionFrameShape(frame) {
		return false
	}
	// Decrypt into a pooled scratch buffer: the plaintext is consumed
	// synchronously below (target write / reorder-queue copy) and nothing
	// retains it past this call, so the buffer goes straight back to the pool.
	buf := getDecryptBuf()
	defer putDecryptBuf(buf)
	if !sess.verifyInboundFrame(frame, buf, remoteAddr) {
		return false
	}
	if !sess.replayFilter.Accept(frame.PacketNo) {
		atomic.AddUint64(&sess.server.replayDrops, 1)
		sess.server.emitSessionEvent(SessionEvent{
			Kind:      SessionReplayDropped,
			SessionID: sess.sessionID,
			Remote:    remoteAddr,
			Network:   sess.targetNetwork,
			Address:   sess.targetAddr,
			Detail:    "packet number below the replay window",
		})
		if frame.Cmd == CMD_DATA {
			sess.reackDuplicateData()
		}
		return false
	}
	if !sess.handleIncomingFrame(frame, remoteAddr, origPort) {
		// DATA rejection is temporary (full application queue or an IP path that
		// is still being validated). Roll only DATA back so its byte-identical
		// ARQ retransmission can be accepted later. A rejected control packet is
		// consumed permanently; otherwise an old ACK/FIN could be replayed after
		// the path migration completes.
		if frame.Cmd == CMD_DATA {
			sess.replayFilter.Remove(frame.PacketNo)
		}
		return false
	}
	return true
}

// verifyInboundFrame opens the AEAD record (PSK-derived or Noise transport
// key — same record format) into the caller's scratch buffer before the frame
// may touch session state. Returns false when the frame must be dropped.
func (sess *ServerSession) verifyInboundFrame(frame *UDPCFrame, dst []byte, remoteAddr netip.AddrPort) bool {
	var err error
	if sess.frameKeys != nil {
		frame.Data, err = OpenFrameAEADInto(dst, frame, sess.frameKeys.Recv)
	} else {
		err = errors.New("session has no record protection")
	}
	if err != nil {
		if n := atomic.AddUint64(&sess.server.macFailures, 1); n == 1 || n%100 == 0 {
			sess.server.logWarn("[Session 0x%08X] ⚠️ Frame authentication rejected cmd=0x%02X from %s: %v",
				sess.sessionID, frame.Cmd, remoteAddr, err)
			// Security event rides the SAME throttle as the warn so a flood
			// does not bury the SIEM either.
			sess.server.emitSessionEvent(SessionEvent{
				Kind:      SessionAuthRejected,
				SessionID: sess.sessionID,
				Remote:    remoteAddr,
				Network:   sess.targetNetwork,
				Address:   sess.targetAddr,
				Detail:    fmt.Sprintf("cmd=0x%02X: %v", frame.Cmd, err),
			})
		}
		return false
	}
	return true
}

func (s *Server) handleHandshake(remoteAddr netip.AddrPort, frame *UDPCFrame, origPort int, matchedPSK string) {
	// SYN payload: [16B ClientNonce] [8B Timestamp] [target TLV] [Optional 48B
	// Noise msg1]. The base payload is mandatory; the target request and msg1
	// are optional and validated against what this server actually runs.
	expectedLen := synPayloadBase
	if s.hasPrivKey {
		expectedLen += noiseMsg1Size
	}
	if matchedPSK == "" || len(frame.Data) < expectedLen || len(frame.Data) > synPayloadBase+targetRequestTLVLen+TargetMaxLen+noiseMsg1Size {
		s.logWarn("[Handshake] Rejected SYN from %s: invalid payload length %d", remoteAddr, len(frame.Data))
		return
	}

	var clientNonce [clientNonceSize]byte
	copy(clientNonce[:], frame.Data[:clientNonceSize])
	timestamp := int64(binary.BigEndian.Uint64(frame.Data[clientNonceSize:synPayloadBase]))

	// Check time drift (allow +/- 300 seconds)
	now := time.Now().Unix()
	if timestamp < now-300 || timestamp > now+300 {
		s.logWarn("[Handshake] Rejected SYN from %s: expired timestamp (%d vs now %d)", remoteAddr, timestamp, now)
		return
	}

	// Client-requested endpoint. The request rides inside the MAC'd payload,
	// so it cannot be forged or stripped; it must still pass AllowedTargets.
	// Empty = the server's default target (fixed single-target behaviour).
	requestedTarget, noiseMsg1, err := splitSynPayload(frame.Data, s.hasPrivKey)
	if err != nil {
		s.logWarn("[Handshake] Rejected SYN from %s: %v", remoteAddr, err)
		return
	}
	if len(frame.Data) != synPayloadBase+len(requestedTargetTLV(requestedTarget))+len(noiseMsg1) {
		s.logWarn("[Handshake] Rejected SYN from %s: trailing bytes in payload", remoteAddr)
		return
	}
	if requestedTarget != "" && !targetAllowed(requestedTarget, s.cfg.AllowedTargets) {
		reqNet, reqAddr := parseTargetNetworkAndAddr(requestedTarget)
		s.logWarn("[Handshake] ❌ Rejected SYN from %s: requested target %q is not in allowed_targets", remoteAddr, requestedTarget)
		s.emitSessionEvent(SessionEvent{
			Kind:    SessionTargetDenied,
			Remote:  remoteAddr,
			Network: reqNet,
			Address: reqAddr,
			Detail:  requestedTarget,
		})
		return
	}

	handshakeKeys := DerivePSKHandshakeKeys(matchedPSK, clientNonce)
	cacheKey := makeSynCacheKey(clientNonce, handshakeKeys.SynMAC)

	// Idempotent replay handling: a verified nonce we have seen before gets the
	// same ACK resent — no new session, no second target dial. This covers the
	// legitimate case (client lost our ACK and retransmits the SYN) and kills
	// the replay case (captive SYN within the ±300s window can no longer force
	// a fresh target connection per replay).
	cached, owner := s.synCache.Acquire(cacheKey, time.Now())
	if cached != nil {
		s.logInfo("[Handshake] ♻️ Replayed SYN from %s: resending cached ACK", remoteAddr)
		s.replyFromOrigPort(origPort, remoteAddr, cached)
		return
	}
	if !owner {
		// Another goroutine is already establishing this exact nonce. Its ACK
		// will be cached shortly; a normal client retransmission will receive it.
		return
	}
	handshakeComplete := false
	defer func() {
		if !handshakeComplete {
			s.synCache.Abort(cacheKey)
		}
	}()

	// Cap concurrent handshakes: the target dial below can block for up to 5s
	// (TCP), so unbounded SYN intake would pile up goroutines and sockets.
	select {
	case s.handshakeSem <- struct{}{}:
		defer func() { <-s.handshakeSem }()
	case <-s.closeChan:
		return
	case <-time.After(2 * time.Second):
		s.logWarn("[Handshake] 🚦 Handshake backlog full, dropping SYN from %s", remoteAddr)
		return
	}

	var noiseSess *NoiseSession
	// Noise_NK handshake: the client's message 1 rides in the SYN payload and
	// the server's message 2 is returned in the ACK payload. Both sides Split()
	// into two independent transport keys (client->server, server->client).
	var noiseMsg2 []byte
	if s.hasPrivKey {
		var err error
		noiseSess, noiseMsg2, err = NewServerNoiseSession(s.privKey, noiseMsg1)
		if err != nil {
			s.logWarn("[Handshake] ❌ Noise_NK handshake failed: %v", err)
			return
		}
		s.logInfo("[Handshake] 🔐 Noise_NK handshake complete for %s (channel binding %x…)",
			remoteAddr, noiseSess.HandshakeHash[:4])
	}

	// Forwarding endpoint: the client's allowed request, else the default.
	// grantedTarget is what the session actually uses AND what the ACK echoes
	// (empty for the default, exactly like the request wire form).
	targetAddr := s.cfg.TargetAddr
	if requestedTarget != "" {
		targetAddr = requestedTarget
	}
	targetNet, targetHostPort := parseTargetNetworkAndAddr(targetAddr)

	// Allocate a unique SessionID BEFORE dialing: the custom dialer is keyed by
	// session, so embedders can route/annotate per tunnel.
	var sid uint32
	for {
		var sidBuf [4]byte
		if _, err := rand.Read(sidBuf[:]); err != nil {
			// crypto/rand failure is catastrophic and must not silently loop.
			s.logError("[Handshake] ❌ crypto/rand failed: %v", err)
			return
		}
		sid = binary.BigEndian.Uint32(sidBuf[:])
		if sid != 0 {
			if _, exists := s.sessions.Load(sid); !exists {
				break
			}
		}
	}

	// Single upstream connection for every target type: plain TCP/UDP by
	// default, or the embedder's TargetDialer (Keyed by session, so an
	// embedder can route, pool, or proxy the upstream however it likes).
	dialCtx, cancelDial := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelDial()
	upstream, dialErr := s.dialTarget(dialCtx, sid, targetNet, targetHostPort)
	if dialErr != nil {
		s.logError("[Handshake] ❌ Failed to dial target [%s] %s: %v", targetNet, targetHostPort, dialErr)
		return
	}

	var serverNonce [serverNonceSize]byte
	if _, err := rand.Read(serverNonce[:]); err != nil {
		s.logError("[Handshake] ❌ crypto/rand failed: %v", err)
		upstream.Close()
		return
	}

	// Record protection: Noise traffic uses the forward-secret transport keys;
	// PSK-only traffic uses AEAD keys derived from the PSK + both nonces + SID
	// (same wire format, but no forward secrecy).
	var frameKeys *FrameKeys
	if noiseSess != nil {
		frameKeys = &FrameKeys{Send: noiseSess.SendCipher, Recv: noiseSess.RecvCipher}
	} else {
		keys := DerivePSKSessionKeys(matchedPSK, clientNonce, serverNonce, sid)
		if frameKeys, err = keys.ServerFrameCiphers(); err != nil {
			s.logError("[Handshake] ❌ session cipher init failed: %v", err)
			upstream.Close()
			return
		}
	}

	sess := &ServerSession{
		server:        s,
		sessionID:     sid,
		raddr:         remoteAddr,
		lastOrigPort:  int32(origPort),
		pathAddrs:     make(map[int]netip.AddrPort),
		targetNetwork: targetNet,
		targetAddr:    targetHostPort,
		upstream:      upstream,
		frameKeys:     frameKeys,
		sendSeq:       1,
		recvSeq:       1,
		recvQueue:     make(map[uint64][]byte),
		unacked:       make(map[uint64]*unackedPkt),
		lastActive:    time.Now(),
		closeChan:     make(chan struct{}),
		rttEst:        newRTTEstimator(200*time.Millisecond, 200*time.Millisecond, 10*time.Second),
		mtuGate:       make(chan struct{}),
	}
	sess.unackedCond = sync.NewCond(&sess.unackedMu)
	s.sessions.Store(sid, sess)
	sess.setPath(origPort, remoteAddr)

	// ACK payload echoes ClientNonce for concurrent-handshake routing and adds
	// ServerNonce for session key freshness, then the granted target (when the
	// client requested one) and the optional Noise msg2.
	ackData := make([]byte, 0, ackPayloadBase+targetRequestTLVLen+len(requestedTarget)+len(noiseMsg2))
	ackData = append(ackData, clientNonce[:]...)
	ackData = append(ackData, serverNonce[:]...)
	ackData = appendTargetTLV(ackData, requestedTarget)
	ackData = append(ackData, noiseMsg2...)
	ackFrame := &UDPCFrame{
		Magic:      s.cfg.Magic,
		Version:    UDPC_VERSION,
		Cmd:        CMD_HANDSHAKE_ACK,
		SessionID:  sid,
		Seq:        0,
		Ack:        0,
		WindowSize: 65535,
		Data:       ackData,
	}
	ackEncoded := SealFrameMAC(ackFrame, &handshakeKeys.AckMAC)
	s.synCache.Complete(cacheKey, ackEncoded)
	handshakeComplete = true
	s.replyFromOrigPort(origPort, remoteAddr, ackEncoded)

	s.logInfo("[Session 0x%08X] ✅ Established for %s -> Target [%s] %s", sid, remoteAddr, targetNet, targetHostPort)
	if requestedTarget != "" {
		s.logInfo("[Session 0x%08X] 🎯 Client-requested target honored: %s", sid, requestedTarget)
	}
	s.emitSessionEvent(SessionEvent{
		Kind:      SessionEstablished,
		SessionID: sid,
		Remote:    remoteAddr,
		Network:   targetNet,
		Address:   targetHostPort,
		Detail:    requestedTarget,
	})

	go sess.upstreamToUdpLoop()
	go sess.retransmitLoop()
}

// replyFromOrigPort sends data to addr so that the reply's SOURCE port equals
// origPort — the port the client originally addressed (recovered via
// IP_RECVORIGDSTADDR). A per-port socket is taken from the sendSockPool; that
// socket is bound to origPort, so the kernel stamps origPort as the source. A
// client behind a symmetric NAT / CGNAT only accepts replies whose source port
// matches the port it sent to, so this is what makes multi-path work. When
// origPort is 0 (origdst disabled or unavailable) it falls back to the main
// listening socket.
func (s *Server) replyFromOrigPort(origPort int, addr netip.AddrPort, data []byte) {
	cmd := cmdOfEncoded(data)
	// The client addressed the listen port directly (no port spreading): the
	// only correct reply source is the main socket, which already holds this
	// port. Skipping the per-port pool avoids a pointless bind(36712) that
	// always fails with EADDRINUSE and only produces misleading warnings.
	if origPort > 0 && origPort != s.bindPort {
		c, err := s.sockPool.Get(origPort)
		if err == nil {
			if n, werr := c.WriteToUDPAddrPort(data, addr); werr == nil {
				atomic.AddUint64(&s.sendViaPort, 1)
				if s.loggerLevel() <= 0 {
					s.logDebug("[Send] to=%s via=origPort:%d cmd=0x%02X len=%d", addr, origPort, cmd, n)
				}
				return
			} else {
				s.logWarn("[Send] ❌ origPort %d write to=%s cmd=0x%02X: %v (fallback to main)", origPort, addr, cmd, werr)
			}
		} else {
			s.logWarn("[Send] ❌ bind origPort %d failed: %v (fallback to main)", origPort, err)
		}
	}
	// Fallback to the main listening socket (correct behaviour only when the
	// client connected to ListenAddr directly, i.e. no port spreading).
	if n, werr := s.conn.WriteToUDPAddrPort(data, addr); werr == nil {
		atomic.AddUint64(&s.sendViaMain, 1)
		if s.loggerLevel() <= 0 {
			s.logDebug("[Send] to=%s via=main cmd=0x%02X len=%d", addr, cmd, n)
		}
		return
	}
	s.logWarn("[Send] ❌ main write failed cmd=0x%02X", cmd)
}

// sendToSession delivers data to the client on the most recently used path of
// the session. lastOrigPort holds the pre-DNAT destination port of the most
// recent inbound packet on this session, so replying through a socket bound to
// that port makes the reply's SOURCE port match what the client addressed —
// exactly what a CGNAT requires in order to accept the packet.
func (sess *ServerSession) sendToSession(data []byte) {
	s := sess.server
	localPort := int(atomic.LoadInt32(&sess.lastOrigPort))

	sess.pathMu.RLock()
	addr := sess.pathAddrs[localPort]
	if !addr.IsValid() {
		for p, a := range sess.pathAddrs {
			if p > 0 {
				localPort, addr = p, a
				break
			}
		}
	}
	sess.pathMu.RUnlock()
	if addr.IsValid() && localPort > 0 {
		atomic.StoreInt32(&sess.lastOrigPort, int32(localPort))
		s.replyFromOrigPort(localPort, addr, data)
		return
	}
	// Fallback to the main socket with the last authenticated address.
	if ra := sess.getRemoteAddr(); ra.IsValid() {
		s.replyFromOrigPort(0, ra, data)
	}
}

// cmdOfEncoded peeks the command byte out of an already-encoded frame so the
// send path can log it without re-decoding the whole frame.
func cmdOfEncoded(data []byte) byte {
	if len(data) > 5 {
		return data[5]
	}
	return 0
}

// updateRemoteAddr moves the session to a newly observed client address.
//
// A port-only change (same IP) is accepted after record authentication: it is
// plain NAT rebinding and, with port-range spreading, can happen on every
// datagram.
//
// An IP change is a genuine migration (WiFi -> cellular) and is worth an INFO
// line — but it is also exactly what a session hijacker needs, so callers must
// only set allowIPChange after AEAD authentication, replay filtering, and a
// bidirectional path challenge.
func (sess *ServerSession) updateRemoteAddr(newAddr netip.AddrPort, allowIPChange bool) {
	sess.raddrMu.RLock()
	unchanged := sess.raddr == newAddr
	sess.raddrMu.RUnlock()
	if unchanged {
		return
	}
	sess.raddrMu.Lock()
	defer sess.raddrMu.Unlock()
	if !sess.raddr.IsValid() {
		sess.raddr = newAddr
		return
	}
	if sess.raddr == newAddr {
		return
	}
	sameIP := sess.raddr.Addr() == newAddr.Addr()
	if !sameIP && !allowIPChange {
		sess.server.logWarn("[Session 0x%08X] 🛡️ Ignored unvalidated address change %s -> %s (path challenge required)",
			sess.sessionID, sess.raddr, newAddr)
		return
	}
	if sameIP {
		if sess.server.loggerLevel() <= 0 {
			sess.server.logDebug("[Session 0x%08X] 🔄 NAT rebinding (same IP, new port): %s -> %s",
				sess.sessionID, sess.raddr, newAddr)
		}
	} else {
		sess.server.logInfo("[Session 0x%08X] 🔄 Connection Migration: %s -> %s",
			sess.sessionID, sess.raddr, newAddr)
	}
	sess.raddr = newAddr
}

// ipOf returns the IP string of a netip.AddrPort — the SYN-rate-limiter key.
func ipOf(addr netip.AddrPort) string {
	if !addr.IsValid() {
		return ""
	}
	return addr.Addr().String()
}

func (sess *ServerSession) getRemoteAddr() netip.AddrPort {
	sess.raddrMu.RLock()
	defer sess.raddrMu.RUnlock()
	return sess.raddr
}

// setPath records that this session was seen on the pre-DNAT destination port
// coming from client address addr, and marks origPort as the preferred reply
// port. origPort is the pre-DNAT destination port the client addressed; a reply
// socket bound to it (see replyFromOrigPort) carries origPort as its SOURCE
// port — which is what a CGNAT requires in order to accept the packet.
func (sess *ServerSession) setPath(origPort int, addr netip.AddrPort) {
	if origPort <= 0 || !addr.IsValid() {
		return
	}
	if atomic.LoadInt32(&sess.lastOrigPort) == int32(origPort) {
		sess.pathMu.RLock()
		unchanged := sess.pathAddrs[origPort] == addr
		sess.pathMu.RUnlock()
		if unchanged {
			return
		}
	}
	sess.pathMu.Lock()
	if sess.pathAddrs == nil {
		sess.pathAddrs = make(map[int]netip.AddrPort)
	}
	if _, exists := sess.pathAddrs[origPort]; !exists && len(sess.pathAddrs) >= sess.server.sockPool.limit {
		for port := range sess.pathAddrs {
			delete(sess.pathAddrs, port)
			break
		}
	}
	sess.pathAddrs[origPort] = addr
	sess.pathMu.Unlock()
	old := atomic.SwapInt32(&sess.lastOrigPort, int32(origPort))
	if old != int32(origPort) {
		atomic.AddUint64(&sess.server.origPortChanges, 1)
	}
}

func (sess *ServerSession) touch() {
	sess.activeMu.Lock()
	sess.lastActive = time.Now()
	sess.activeMu.Unlock()
}

func (sess *ServerSession) handleIncomingFrame(frame *UDPCFrame, remoteAddr netip.AddrPort, origPort int) bool {
	if !sess.sameRemoteIP(remoteAddr) {
		if frame.Cmd == CMD_PATH_RESPONSE && sess.acceptPathResponse(remoteAddr, frame.Data) {
			sess.updateRemoteAddr(remoteAddr, true)
			sess.setPath(origPort, remoteAddr)
			sess.touch()
			return true
		}
		// Authentication proves who sent the frame, while the challenge proves
		// the claimed new path can receive replies. DATA delivery, ACK/FIN
		// semantics, and the stored route remain untouched until that response
		// returns. DATA's replay bit is rolled back by processIncomingFrame so ARQ
		// can retry it after migration.
		sess.sendPathChallenge(remoteAddr, origPort)
		return false
	}
	if frame.Cmd == CMD_DATA {
		// Client data proves the client is past its own probe phase (or never
		// probed at all) — either way the frame budget question is settled for
		// the target->client direction too.
		sess.openMtuGate()
		return sess.handleDataFromPath(frame, remoteAddr, origPort)
	}

	sess.updateRemoteAddr(remoteAddr, false)
	sess.setPath(origPort, remoteAddr)
	sess.touch()
	if frame.Ack > 0 {
		sess.handleAck(frame.Ack)
	}

	switch frame.Cmd {
	case CMD_PING:
		pong := &UDPCFrame{
			Magic:     sess.server.cfg.Magic,
			Version:   UDPC_VERSION,
			Cmd:       CMD_PONG,
			SessionID: sess.sessionID,
			Ack:       sess.currentAck(),
		}
		sess.sendControl(pong, func(data []byte) error { sess.sendToSession(data); return nil })

	case CMD_FIN:
		sess.server.logInfo("[Session 0x%08X] Received FIN from client", sess.sessionID)
		sess.Close()
	case CMD_MTU_PROBE:
		// Echo the probe byte for byte: the payload LENGTH is the size under
		// test, and a successful round trip proves BOTH directions can carry
		// it. The reply is a fresh authenticated record with its own packet
		// number. Probing disabled = silent drop, the universal old-peer
		// fallback contract.
		if !mtuProbeEnabled(sess.server.cfg.MtuProbe) {
			break
		}
		reply := &UDPCFrame{
			Magic: sess.server.cfg.Magic, Version: UDPC_VERSION,
			Cmd: CMD_MTU_PROBE_REPLY, SessionID: sess.sessionID,
			Ack: sess.currentAck(), Data: append([]byte(nil), frame.Data...),
		}
		sess.sendControl(reply, func(data []byte) error { sess.sendToSession(data); return nil })
	case CMD_MTU_COMMIT:
		sess.applyMtuCommit(int(binary.BigEndian.Uint16(frame.Data)))
	}
	return true
}

// applyMtuCommit pins the session's frame budget to the size the client's
// path probe converged on, releasing the upstream gate. The commit can only
// shrink the local budget, and only the first one is honored — the client
// sends a couple of identical copies back to back, so later ones are just
// duplicates, and the budget is immutable once set.
func (sess *ServerSession) applyMtuCommit(n int) {
	sess.openMtuGate()
	if sess.maxPkt > 0 {
		return
	}
	if n < maxPktFloor {
		n = maxPktFloor
	}
	if n > sess.server.maxPkt {
		n = sess.server.maxPkt
	}
	if n == sess.server.maxPkt {
		return // equals the configured budget: nothing to record
	}
	sess.maxPkt = n
	sess.server.logInfo("[Session 0x%08X] 📏 [mtu] client committed %d-byte records (payload %d, configured %d)",
		sess.sessionID, n, payloadCap(n), sess.server.maxPkt)
}

func (sess *ServerSession) sendPathChallenge(remoteAddr netip.AddrPort, origPort int) {
	var token [pathChallengeSize]byte
	now := time.Now()
	sess.challengeMu.Lock()
	if sess.pathChallenges == nil {
		sess.pathChallenges = make(map[netip.Addr]pathChallenge)
	}
	for ip, pending := range sess.pathChallenges {
		if now.After(pending.expires) {
			delete(sess.pathChallenges, ip)
		}
	}
	if pending, ok := sess.pathChallenges[remoteAddr.Addr()]; ok {
		token = pending.token
	} else {
		if _, err := rand.Read(token[:]); err != nil {
			sess.challengeMu.Unlock()
			return
		}
		if len(sess.pathChallenges) >= maxPathChallenges {
			for ip := range sess.pathChallenges {
				delete(sess.pathChallenges, ip)
				break
			}
		}
		sess.pathChallenges[remoteAddr.Addr()] = pathChallenge{token: token, expires: now.Add(pathChallengeTTL)}
	}
	sess.challengeMu.Unlock()

	challenge := &UDPCFrame{
		Magic: sess.server.cfg.Magic, Version: UDPC_VERSION,
		Cmd: CMD_PATH_CHALLENGE, SessionID: sess.sessionID, Data: token[:],
	}
	sess.sendControl(challenge, func(data []byte) error {
		sess.server.replyFromOrigPort(origPort, remoteAddr, data)
		return nil
	})
}

func (sess *ServerSession) acceptPathResponse(remoteAddr netip.AddrPort, data []byte) bool {
	if len(data) != pathChallengeSize {
		return false
	}
	sess.challengeMu.Lock()
	defer sess.challengeMu.Unlock()
	pending, ok := sess.pathChallenges[remoteAddr.Addr()]
	if !ok || time.Now().After(pending.expires) || !hmac.Equal(data, pending.token[:]) {
		return false
	}
	delete(sess.pathChallenges, remoteAddr.Addr())
	return true
}

// encodeFrame assigns a fresh per-direction packet number and seals the frame
// as a ChaCha20-Poly1305 record (PSK-derived or Noise transport key — same
// format, header as AAD, Poly1305 tag in the trailer). The buffer is freshly
// allocated: only use for frames whose wire bytes are retained (DATA).
func (sess *ServerSession) encodeFrame(f *UDPCFrame) []byte {
	f.PacketNo = atomic.AddUint64(&sess.sendPacketNo, 1)
	if f.PacketNo == 0 {
		return nil
	}
	if sess.frameKeys == nil {
		return nil
	}
	return SealFrameAEAD(f, sess.frameKeys.Send, f.Data)
}

// sendControl seals a control frame into a POOLED buffer and
// hands it to send. The buffer is returned to the pool before this call
// returns — send must copy or consume synchronously (net.UDPConn.Write does).
// Returns false when the session lacks record protection or the packet-number
// space is exhausted.
func (sess *ServerSession) sendControl(f *UDPCFrame, send func([]byte) error) bool {
	f.PacketNo = atomic.AddUint64(&sess.sendPacketNo, 1)
	if f.PacketNo == 0 || sess.frameKeys == nil {
		return false
	}
	wire := sealControlFrameAEAD(f, sess.frameKeys.Send)
	if len(wire) == 0 {
		return false
	}
	_ = send(wire)
	putFireAndForgetBuf(wire)
	return true
}

func (sess *ServerSession) currentAck() uint64 {
	if next := atomic.LoadUint64(&sess.recvSeq); next > 0 {
		return next - 1
	}
	return 0
}

func (sess *ServerSession) sameRemoteIP(addr netip.AddrPort) bool {
	if !addr.IsValid() {
		return false
	}
	sess.raddrMu.RLock()
	current := sess.raddr
	sess.raddrMu.RUnlock()
	return current.IsValid() && current.Addr() == addr.Addr()
}

func (sess *ServerSession) handleAck(ackSeq uint64) {
	sess.unackedMu.Lock()
	if len(sess.unacked) == 0 {
		sess.unackedMu.Unlock()
		return
	}
	// ACKs are interpreted cumulatively: "everything up to ackSeq has been
	// delivered". This matches the ACKs this end emits and keeps a lost ACK
	// from leaving a frame stuck in the retransmit queue — any later ACK
	// covers it.
	if pkt, ok := sess.unacked[ackSeq]; ok && pkt.retries == 0 {
		// Karn's rule: only sample RTT from a frame that was never
		// retransmitted; the RTT of a retransmitted one is not trustworthy.
		sess.rttEst.Sample(time.Since(pkt.firstSent))
	}
	for seq := range sess.unacked {
		if seq <= ackSeq {
			delete(sess.unacked, seq)
		}
	}
	sess.unackedMu.Unlock()
	// Free send-window space; keep the broadcast outside the lock to avoid
	// waking a sender straight into a contested mutex.
	sess.unackedCond.Broadcast()
}

func (sess *ServerSession) handleData(frame *UDPCFrame, remoteAddr netip.AddrPort) bool {
	return sess.handleDataFromPath(frame, remoteAddr, 0)
}

func (sess *ServerSession) handleDataFromPath(frame *UDPCFrame, remoteAddr netip.AddrPort, origPort int) bool {
	// Authentication/decryption and packet-number replay filtering have already
	// completed in the receive loop.
	payload := frame.Data
	if frame.Ack > 0 {
		sess.handleAck(frame.Ack)
	}

	expected := atomic.LoadUint64(&sess.recvSeq)
	if frame.Seq != expected {
		if frame.Seq < expected {
			// Already delivered. The peer is retransmitting because it never
			// saw our ACK, so re-ACK (cumulative) instead of silently
			// dropping — otherwise it would keep retrying until it gave up
			// and tore the session down.
			sess.sendCumulativeACK(expected - 1)
			return true
		}
		// Out-of-order: buffer the raw frame and wait for the missing one to
		// be retransmitted. We deliberately do NOT Ack here, so the client
		// keeps the missing sequence outstanding and resends it.
		sess.recvMu.Lock()
		accepted := true
		if _, dup := sess.recvQueue[frame.Seq]; !dup {
			if len(sess.recvQueue) >= sess.server.maxRecvQueue {
				atomic.AddUint64(&sess.server.queueFullDrops, 1)
				accepted = false
			} else {
				sess.recvQueue[frame.Seq] = append([]byte(nil), payload...)
			}
		}
		sess.recvMu.Unlock()
		if accepted {
			sess.updateRemoteAddr(remoteAddr, true)
			sess.setPath(origPort, remoteAddr)
			sess.touch()
		}
		return accepted
	}

	// Only a fresh authenticated DATA frame may migrate the session or install
	// a reply path.
	sess.updateRemoteAddr(remoteAddr, true)
	sess.setPath(origPort, remoteAddr)
	sess.touch()

	// In-order delivery. Gather the contiguous run (this frame plus anything
	// already buffered behind it) under the lock, then deliver
	// OUTSIDE the lock so a slow target write cannot stall the receive path.
	type pending struct {
		seq     uint64
		payload []byte
	}
	run := []pending{{seq: expected, payload: payload}}
	sess.recvMu.Lock()
	next := expected + 1
	for {
		raw, ok := sess.recvQueue[next]
		if !ok {
			break
		}
		delete(sess.recvQueue, next)
		run = append(run, pending{seq: next, payload: raw})
		next++
	}
	sess.recvMu.Unlock()

	delivered := uint64(0)
	for _, p := range run {
		if err := sess.writeToTarget(p.payload); err != nil {
			sess.server.logWarn("[Session 0x%08X] target write failed: %v", sess.sessionID, err)
			sess.Close()
			return true
		}
		delivered++
	}

	if delivered == 0 {
		return true
	}

	atomic.StoreUint64(&sess.recvSeq, expected+delivered)

	// Ack the highest contiguous sequence we have just delivered.
	sess.sendCumulativeACK(expected + delivered - 1)
	return true
}

// sendCumulativeACK emits an ACK meaning "everything up to ackSeq is
// delivered". Used after delivering a run and when re-ACKing a duplicate whose
// original ACK was lost. Control frames ride the pooled send buffer.
func (sess *ServerSession) sendCumulativeACK(ackSeq uint64) {
	ackFrame := &UDPCFrame{
		Magic:      sess.server.cfg.Magic,
		Version:    UDPC_VERSION,
		Cmd:        CMD_ACK,
		SessionID:  sess.sessionID,
		Ack:        ackSeq,
		WindowSize: 65535,
	}
	sess.sendControl(ackFrame, func(data []byte) error { sess.sendToSession(data); return nil })
}

func (sess *ServerSession) reackDuplicateData() {
	if ack := sess.currentAck(); ack > 0 {
		sess.sendCumulativeACK(ack)
	}
}

func (sess *ServerSession) writeToTarget(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if sess.upstream == nil {
		return fmt.Errorf("target connection unavailable")
	}
	if sess.targetNetwork == "udp" {
		n, err := sess.upstream.Write(data)
		if err == nil && n != len(data) {
			err = io.ErrShortWrite
		}
		return err
	}
	return writeAll(sess.upstream, data)
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func (sess *ServerSession) sendData(payload []byte) error {
	// Send window: block while too many frames are still un-ACKed. This is the
	// backpressure that keeps the unacked map (and the retransmit backlog)
	// bounded when the client is slow or silent — the "sliding window" in its
	// simplest form: the read loop stops reading the target until ACKs arrive.
	//
	// Like the client side: oversized payloads fail fast with an actionable
	// error instead of an opaque seal failure (the upstreamToUdpLoop reads at
	// most the frame budget, so this only guards custom dialers).
	if budget := sess.maxPayload(); len(payload) > budget {
		return fmt.Errorf("payload of %d bytes exceeds the per-frame budget (%d with max_pkt=%d): chunk writes to %d bytes or smaller",
			len(payload), budget, sess.server.maxPkt, budget)
	}
	sess.unackedMu.Lock()
	for len(sess.unacked) >= sess.server.sendWindow && atomic.LoadInt32(&sess.closed) == 0 {
		sess.unackedCond.Wait()
	}
	sess.unackedMu.Unlock()
	if atomic.LoadInt32(&sess.closed) == 1 {
		return fmt.Errorf("session closed")
	}

	seq := atomic.AddUint64(&sess.sendSeq, 1) - 1

	frame := &UDPCFrame{
		Magic:      sess.server.cfg.Magic,
		Version:    UDPC_VERSION,
		Cmd:        CMD_DATA,
		SessionID:  sess.sessionID,
		Seq:        seq,
		Ack:        sess.currentAck(),
		WindowSize: 65535,
		Data:       payload,
	}

	encoded := sess.encodeFrame(frame)
	if len(encoded) == 0 {
		return fmt.Errorf("failed to seal DATA frame")
	}

	sess.unackedMu.Lock()
	now := time.Now()
	sess.unacked[seq] = &unackedPkt{
		wire:      encoded,
		firstSent: now,
		sentTime:  now,
		rto:       sess.rttEst.RTO(), // adaptive RTO replaces the old fixed 200ms
		retries:   0,
	}
	sess.unackedMu.Unlock()

	// Server-initiated: reply on the most recently used path so the source
	// port matches the port the client last contacted.
	sess.sendToSession(encoded)
	return nil
}

// upstreamToUdpLoop pumps the backend connection into the tunnel. For "udp"
// targets the backend Write preserved datagram boundaries, and each Read here
// returns one datagram, so the end-to-end datagram semantics hold (one target
// datagram = one DATA frame). For stream targets the loop simply ships whatever
// chunk the next Read returns.
func (sess *ServerSession) upstreamToUdpLoop() {
	defer sess.Close()
	sess.awaitMtuGate()
	buf := make([]byte, sess.server.maxPayload())
	for {
		if atomic.LoadInt32(&sess.closed) == 1 {
			return
		}
		n, err := sess.upstream.Read(buf)
		if err != nil {
			if sess.targetNetwork == "tcp" && err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
				sess.server.logWarn("[Session 0x%08X] Target TCP read error: %v", sess.sessionID, err)
			}
			return
		}
		if n > 0 {
			sess.touch()
			sess.forwardUpstream(buf[:n])
		}
	}
}

// awaitMtuGate blocks until the session's frame budget is known (the client's
// commit record), the client proves it is not probing (its first DATA), or the
// bounded wait expires. Without it the server could encode target data at the
// configured budget in the pre-commit window and strand it on a narrow path.
// Disabled probing skips the wait entirely — legacy behaviour.
func (sess *ServerSession) awaitMtuGate() {
	if sess.mtuGate == nil || !mtuProbeEnabled(sess.server.cfg.MtuProbe) {
		return
	}
	select {
	case <-sess.mtuGate:
	case <-sess.closeChan:
		return
	case <-time.After(mtuCommitWait):
		sess.server.logWarn("[Session 0x%08X] no mtu commit within %v: starting the target pump at max_pkt=%d",
			sess.sessionID, mtuCommitWait, sess.server.maxPkt)
	}
	if atomic.LoadInt32(&sess.closed) == 1 {
		sess.server.logDebug("[Session 0x%08X] closed while waiting for the mtu gate", sess.sessionID)
	}
}

// openMtuGate releases the upstream pump exactly once.
func (sess *ServerSession) openMtuGate() {
	if sess.mtuGate == nil {
		return
	}
	sess.mtuGateOnce.Do(func() { close(sess.mtuGate) })
}

// maxPayload is the session's frame budget: whatever the client committed,
// capped by what this server is configured to send.
func (sess *ServerSession) maxPayload() int {
	budget := sess.server.maxPayload()
	if sess.maxPkt > 0 {
		if p := payloadCap(sess.maxPkt); p < budget {
			budget = p
		}
	}
	return budget
}

// forwardUpstream ships one target read into the tunnel under the session's
// frame budget. A TCP target is a byte stream, so an oversized read is simply
// split across records; a UDP datagram cannot be split without breaking its
// end-to-end boundary, so an oversized one is dropped with a warning — on a
// path that narrow it could not have been delivered intact anyway.
func (sess *ServerSession) forwardUpstream(chunk []byte) {
	if len(chunk) <= sess.maxPayload() {
		_ = sess.sendData(chunk)
		return
	}
	if sess.targetNetwork != "tcp" {
		sess.server.logWarn("[Session 0x%08X] dropping %d-byte target datagram: exceeds the %d-byte frame budget (narrow path)",
			sess.sessionID, len(chunk), sess.maxPayload())
		return
	}
	for off := 0; off < len(chunk); off += sess.maxPayload() {
		end := off + sess.maxPayload()
		if end > len(chunk) {
			end = len(chunk)
		}
		if err := sess.sendData(chunk[off:end]); err != nil {
			return
		}
	}
}

func (sess *ServerSession) retransmitLoop() {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-sess.closeChan:
			return
		case <-ticker.C:
			now := time.Now()
			sess.unackedMu.Lock()
			for seq, pkt := range sess.unacked {
				if now.Sub(pkt.sentTime) >= pkt.rto {
					if pkt.retries >= 15 {
						sess.server.logWarn("[Session 0x%08X] ⚠️ Max retries reached for Seq %d, closing session", sess.sessionID, seq)
						sess.unackedMu.Unlock()
						sess.Close()
						return
					}
					pkt.retries++
					pkt.sentTime = now
					pkt.rto = time.Duration(float64(pkt.rto) * 1.5) // back off 1.5x from the adaptive RTO
					if pkt.rto > sess.rttEst.maxRTT {
						pkt.rto = sess.rttEst.maxRTT
					}
					sess.sendToSession(pkt.wire)
				}
			}
			sess.unackedMu.Unlock()
		}
	}
}

func (sess *ServerSession) Close() {
	sess.closeOnce.Do(func() {
		atomic.StoreInt32(&sess.closed, 1)
		// Wake senders parked on the send window before anything else touches
		// the mutex they are waiting on.
		sess.unackedMu.Lock()
		sess.unackedCond.Broadcast()
		sess.unackedMu.Unlock()
		close(sess.closeChan)
		if sess.upstream != nil {
			sess.upstream.Close()
		}
		sess.server.sessions.Delete(sess.sessionID)
		sess.server.logInfo("[Session 0x%08X] 🛑 Session closed", sess.sessionID)
		sess.server.emitSessionEvent(SessionEvent{
			Kind:      SessionClosed,
			SessionID: sess.sessionID,
			Remote:    sess.getRemoteAddr(),
			Network:   sess.targetNetwork,
			Address:   sess.targetAddr,
		})
	})
}

// SessionEventKind enumerates the lifecycle transitions reported through
// Server.SetEventHandler.
type SessionEventKind int

const (
	// SessionEstablished fires after the handshake completed, the target
	// passed the filter, the backend was dialed, and the session is live.
	SessionEstablished SessionEventKind = iota
	// SessionClosed fires exactly once when the session tears down (FIN,
	// idle timeout, max retries, backend error, or server Close).
	SessionClosed
	// SessionAuthRejected fires when a session-bound frame fails frame-MAC or
	// AEAD verification — the security-event hook for SIEM pipelines.
	SessionAuthRejected
	// SessionReplayDropped fires when an authenticated packet is rejected by
	// the per-direction replay window.
	SessionReplayDropped
	// SessionTargetDenied fires when a client requested a target endpoint
	// that failed the allowed_targets filter (the SYN is silently dropped —
	// this event is the ONLY observability the operator gets).
	SessionTargetDenied
)

func (k SessionEventKind) String() string {
	switch k {
	case SessionEstablished:
		return "established"
	case SessionClosed:
		return "closed"
	case SessionAuthRejected:
		return "auth-rejected"
	case SessionReplayDropped:
		return "replay-dropped"
	case SessionTargetDenied:
		return "target-denied"
	}
	return "unknown"
}

// SessionEvent describes one session lifecycle or security transition.
// Network/Address name the granted backend when known. Detail carries
// human-readable context (rejection cause, requested endpoint, ...).
type SessionEvent struct {
	Kind      SessionEventKind
	SessionID uint32
	Remote    netip.AddrPort
	Network   string
	Address   string
	Detail    string
}

// SetEventHandler registers a callback for session lifecycle and security
// events. The handler runs on a DEDICATED goroutine (never on receive
// paths): it may block, but sustained pressure causes drops — see
// EventsDropped. Panics in the handler are recovered. Call before Start.
func (s *Server) SetEventHandler(fn func(SessionEvent)) {
	s.events.setHandler(fn)
}

// EventsDropped reports how many events were discarded because the handler
// could not keep up.
func (s *Server) EventsDropped() uint64 { return s.events.droppedCount() }

// emitSessionEvent is the internal fire-and-forget publisher.
func (s *Server) emitSessionEvent(ev SessionEvent) {
	s.events.emit(ev)
}

// synRecord caches the result of a verified handshake so a retransmitted or
// replayed SYN can be answered idempotently.
type synRecord struct {
	ackFrame  []byte // pre-encoded CMD_HANDSHAKE_ACK for the created session
	createdAt time.Time
}

// synCache maps a client nonce plus an opaque PSK-derived identifier to its
// verified handshake result. Including the credential identity prevents one
// authorized PSK from racing another PSK that intentionally reuses a nonce.
// Entries expire after synCacheTTL and are FIFO-evicted at synCacheMax.
type synCacheKey struct {
	nonce [clientNonceSize]byte
	pskID [16]byte
}

func makeSynCacheKey(nonce [clientNonceSize]byte, synMACKey [32]byte) synCacheKey {
	var key synCacheKey
	key.nonce = nonce
	copy(key.pskID[:], synMACKey[:len(key.pskID)])
	return key
}

type synCache struct {
	mu      sync.Mutex
	entries map[synCacheKey]synRecord
	fifo    []synFIFOEntry // insertion order, for eviction
}

type synFIFOEntry struct {
	key       synCacheKey
	createdAt time.Time
}

func newSynCache() *synCache {
	return &synCache{entries: make(map[synCacheKey]synRecord)}
}

// Acquire atomically returns a completed cached ACK or reserves the key for
// exactly one handshake goroutine. A nil ACK with owner=false means another
// goroutine currently owns the same in-progress handshake.
func (c *synCache) Acquire(key synCacheKey, now time.Time) (ack []byte, owner bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if rec, ok := c.entries[key]; ok {
		if now.Sub(rec.createdAt) <= synCacheTTL {
			return rec.ackFrame, false
		}
		delete(c.entries, key)
	}
	c.makeSpaceLocked(now)
	c.entries[key] = synRecord{createdAt: now}
	c.fifo = append(c.fifo, synFIFOEntry{key: key, createdAt: now})
	return nil, true
}

// Complete publishes the immutable ACK for a key reserved by Acquire.
func (c *synCache) Complete(key synCacheKey, ackFrame []byte) {
	c.mu.Lock()
	if rec, ok := c.entries[key]; ok && rec.ackFrame == nil {
		rec.ackFrame = append([]byte(nil), ackFrame...)
		c.entries[key] = rec
	}
	c.mu.Unlock()
}

// Abort removes an in-progress reservation after a failed handshake.
func (c *synCache) Abort(key synCacheKey) {
	c.mu.Lock()
	if rec, ok := c.entries[key]; ok && rec.ackFrame == nil {
		delete(c.entries, key)
	}
	c.mu.Unlock()
}

func (c *synCache) makeSpaceLocked(now time.Time) {
	for key, rec := range c.entries {
		if now.Sub(rec.createdAt) > synCacheTTL {
			delete(c.entries, key)
		}
	}
	for len(c.entries) >= synCacheMax && len(c.fifo) > 0 {
		oldest := c.fifo[0]
		c.fifo = c.fifo[1:]
		if rec, ok := c.entries[oldest.key]; ok && rec.createdAt.Equal(oldest.createdAt) {
			delete(c.entries, oldest.key)
		}
	}
	// Periodically compact stale FIFO metadata left behind by expiration/abort.
	if len(c.fifo) > synCacheMax*2 {
		fresh := c.fifo[:0]
		for _, item := range c.fifo {
			if rec, ok := c.entries[item.key]; ok && rec.createdAt.Equal(item.createdAt) {
				fresh = append(fresh, item)
			}
		}
		c.fifo = fresh
	}
}

// Len returns the number of cached nonces (used by tests).
func (c *synCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// synLimiter is a per-source-IP token bucket that throttles SYNs. A source IP
// gets `burst` tokens refilled at `rate` per second; when the map grows past
// 1024 buckets, long-idle ones are pruned.
type synLimiter struct {
	mu      sync.Mutex
	buckets map[string]*synBucket
	rate    float64 // tokens per second
	burst   float64
}

type synBucket struct {
	tokens float64
	last   time.Time
}

func newSynLimiter(ratePerSec, burst float64) *synLimiter {
	if ratePerSec <= 0 {
		ratePerSec = 5
	}
	if burst < 1 {
		burst = 10
	}
	return &synLimiter{
		buckets: make(map[string]*synBucket),
		rate:    ratePerSec,
		burst:   burst,
	}
}

// Allow consumes one token for ip. It never blocks.
func (l *synLimiter) Allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[ip]
	if !ok {
		if len(l.buckets) >= 1024 {
			for k, ob := range l.buckets {
				if now.Sub(ob.last) > time.Minute {
					delete(l.buckets, k)
				}
			}
		}
		b = &synBucket{tokens: l.burst, last: now}
		l.buckets[ip] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Len returns the number of tracked source IPs (used by tests).
func (l *synLimiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

func (s *Server) cleanupLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.closeChan:
			return
		case <-ticker.C:
			now := time.Now()
			s.sessions.Range(func(key, value interface{}) bool {
				sess := value.(*ServerSession)
				sess.activeMu.Lock()
				inactive := now.Sub(sess.lastActive)
				sess.activeMu.Unlock()

				if inactive > 60*time.Second {
					s.logInfo("[Session 0x%08X] ⏱️ Inactive for %v, cleaning up", sess.sessionID, inactive)
					sess.Close()
				}
				return true
			})

			// Periodic health snapshot: makes it obvious at a glance whether
			// port mirroring is actually happening or silently falling back,
			// and whether authentication / buffering is silently dropping.
			s.logDebug("[Stats] origdst=%v portRange=%v sendsocks=%d viaPort=%d viaMain=%d portChanges=%d queueFull=%d outOfRange=%d authFail=%d replayDrop=%d",
				s.origDstOK,
				s.portRange != nil,
				s.sockPool.Len(),
				atomic.LoadUint64(&s.sendViaPort),
				atomic.LoadUint64(&s.sendViaMain),
				atomic.LoadUint64(&s.origPortChanges),
				atomic.LoadUint64(&s.queueFullDrops),
				atomic.LoadUint64(&s.outOfRangePkts),
				atomic.LoadUint64(&s.macFailures),
				atomic.LoadUint64(&s.replayDrops))
		}
	}
}

// ServerStats is a point-in-time snapshot of the server's health counters, for
// embedders that want to export them (Prometheus, health endpoints, ...). All
// counters are cumulative since server start; Sessions is a live gauge.
type ServerStats struct {
	Sessions        int    // live sessions (gauge)
	ReceiveSockets  int    // SO_REUSEPORT receive group size (1 = single socket)
	SockPoolSize    int    // per-port reply sockets currently cached
	OrigDstOK       bool   // IP_RECVORIGDSTADDR active (Linux only)
	SendViaPort     uint64 // replies sent through a per-port socket (healthy mirroring)
	SendViaMain     uint64 // replies that fell back to the main socket (possible NAT trouble)
	OrigPortChanges uint64 // times a session's mirrored reply port changed
	QueueFullDrops  uint64 // reorder-buffer overflows (client behind or loss)
	OutOfRangePkts  uint64 // packets whose origdst port fell outside port_range
	AuthFailures    uint64 // v2 authentication rejections (forgery/replay diagnostics)
	DecodeFailures  uint64 // undecodable datagrams (junk, port scans, mismatched peers)
	ReplayDrops     uint64 // authenticated packets rejected by the replay window
}

// Stats returns a snapshot of the counters the server also logs every 15s.
func (s *Server) Stats() ServerStats {
	st := ServerStats{
		Sessions:        0, // counted below
		ReceiveSockets:  len(s.recvConns),
		OrigDstOK:       s.origDstOK,
		SockPoolSize:    s.sockPool.Len(),
		SendViaPort:     atomic.LoadUint64(&s.sendViaPort),
		SendViaMain:     atomic.LoadUint64(&s.sendViaMain),
		OrigPortChanges: atomic.LoadUint64(&s.origPortChanges),
		QueueFullDrops:  atomic.LoadUint64(&s.queueFullDrops),
		OutOfRangePkts:  atomic.LoadUint64(&s.outOfRangePkts),
		AuthFailures:    atomic.LoadUint64(&s.macFailures),
		DecodeFailures:  atomic.LoadUint64(&s.decodeFailures),
		ReplayDrops:     atomic.LoadUint64(&s.replayDrops),
	}
	s.sessions.Range(func(_, _ interface{}) bool {
		st.Sessions++
		return true
	})
	return st
}

func (s *Server) Close() {
	if atomic.CompareAndSwapInt32(&s.closed, 0, 1) {
		close(s.closeChan)
		for _, rc := range s.recvConns {
			rc.Close()
		}
		if s.sockPool != nil {
			s.sockPool.Close()
		}
		s.sessions.Range(func(key, value interface{}) bool {
			sess := value.(*ServerSession)
			sess.Close()
			return true
		})
		s.events.close()
	}
}

// loggerLevel reports the configured verbosity for debug-gating hot paths.
// An injected Logger always receives everything (level 0); the level filter is
// only applied inside resolveLogger for the default std logger.
func (s *Server) loggerLevel() int {
	if s.cfg.Logger != nil {
		return 0
	}
	return LogLevel(s.cfg.LogLevel)
}
