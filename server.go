package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log"
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

	// PortRange is the UDP port range the firewall DNATs onto ListenAddr. It
	// is the single source of truth for the client port range: the server
	// uses it at runtime to validate that every recovered original-destination
	// port actually belongs to the expected range — a packet whose origdst
	// port falls outside it is a firewall/DNAT misconfiguration signal — and
	// the gen-nftables / gen-iptables helpers default their --range to it.
	// The server NEVER binds these ports.
	PortRange string `json:"port_range"`
}

// defaultSendWindow is the cap on frames awaiting ACK before the target read
// loop blocks. 256 frames x ~1.3KB ≈ 345KB in flight, which bounds both the
// unacked map and the retransmit backlog for a stalled client.
const defaultSendWindow = 256

// synCacheTTL is how long a verified handshake nonce is remembered. It must
// exceed the ±300s timestamp acceptance window so a replayed SYN can never be
// re-verified after its cache entry expires.
const synCacheTTL = 10 * time.Minute

// synCacheMax caps the handshake idempotency cache (16B nonce + ~30B record).
const synCacheMax = 4096

type UDPCServer struct {
	cfg            ServerConfig
	conn           *net.UDPConn  // single bound listener (the DNAT target port)
	bindPort       int           // local port actually bound
	sockPool       *sendSockPool // per-origdst-port reply sockets
	origDstOK      bool          // IP_RECVORIGDSTADDR enabled & working
	portRange      *PortRange    // configured client port range (DNAT target); nil = not set
	outOfRangePkts uint64        // packets whose origdst port fell outside portRange
	privKey        [32]byte
	hasPrivKey     bool
	sessions       sync.Map // uint32 -> *ServerSession
	closed         int32
	closeChan      chan struct{}
	logLevel       int // 0: debug, 1: info, 2: warn, 3: error

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
	sendNoPort      uint64 // replies with no original port to mirror
	decryptFailures uint64 // Noise decrypt failures (nonce/corruption diagnostics)
	queueFullDrops  uint64 // reorder-buffer overflows
}

func parseLogLevel(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return 0
	case "info":
		return 1
	case "warn", "warning":
		return 2
	case "error":
		return 3
	default:
		return 1
	}
}

// The server NEVER advertises a port list. The client picks its own
// destination ports from the configured range (a firewall DNATs that range onto
// the single ListenAddr port), and the server learns each path's original
// destination port from IP_RECVORIGDSTADDR. This keeps the client the single
// source of truth for path selection and removes any client/server sync.

func (s *UDPCServer) logDebug(format string, v ...interface{}) {
	if s.logLevel <= 0 {
		log.Printf("[DEBUG] "+format, v...)
	}
}

func (s *UDPCServer) logInfo(format string, v ...interface{}) {
	if s.logLevel <= 1 {
		log.Printf("[INFO] "+format, v...)
	}
}

func (s *UDPCServer) logWarn(format string, v ...interface{}) {
	if s.logLevel <= 2 {
		log.Printf("[WARN] "+format, v...)
	}
}

func (s *UDPCServer) logError(format string, v ...interface{}) {
	if s.logLevel <= 3 {
		log.Printf("[ERROR] "+format, v...)
	}
}

// ReplayFilter implements a 2048-packet sliding-window anti-replay filter.
//
// It is wired at the top of handleData as a wrap-safe, defense-in-depth
// duplicate/replay gate: any sequence that was ever ACCEPTED (delivered or
// buffered) is rejected on sight. The recvSeq ordering check remains the
// primary gate; the filter hardens both against uint32 wrap-around and against
// future changes to the receive path.
//
// Semantics are transactional on purpose: callers must only Accept a sequence
// they actually buffered or delivered. Rejecting-then-accepting later (e.g. a
// frame dropped because the reorder queue was full, then retransmitted) must
// stay possible, otherwise a lost first copy would deadlock the session.
type ReplayFilter struct {
	maxSeq  uint32
	seenMax bool // whether maxSeq has ever been set (seq 0 is never used, so maxSeq==0 alone is ambiguous)
	window  [32]uint64
	mu      sync.Mutex
}

// isBeforeWrapSafe reports whether a < b in uint32 sequence space, correctly
// across wrap-around (RFC 1982 serial number arithmetic).
func isBeforeWrapSafe(a, b uint32) bool {
	return int32(a-b) < 0
}

// Seen reports whether seq was previously accepted. Sequences newer than
// anything seen, and sequences older than the 2048-window (which the caller
// rejects by other means), report false.
func (rf *ReplayFilter) Seen(seq uint32) bool {
	if seq == 0 {
		return true // seq 0 is reserved for handshake frames; never a valid DATA seq
	}
	rf.mu.Lock()
	defer rf.mu.Unlock()
	if !rf.seenMax {
		return false
	}
	delta := int32(seq - rf.maxSeq)
	if delta > 0 {
		return false // newer than everything accepted so far
	}
	behind := -delta
	if behind >= 2048 {
		return false // fell out of the window; primary ordering check handles these
	}
	return (rf.window[behind/64] & (1 << (behind % 64))) != 0
}

// Accept records seq as accepted. Returns false if it was already recorded.
func (rf *ReplayFilter) Accept(seq uint32) bool {
	if seq == 0 {
		return false
	}
	rf.mu.Lock()
	defer rf.mu.Unlock()
	if rf.seenMax {
		delta := int32(seq - rf.maxSeq)
		if delta > 0 {
			diff := uint32(delta)
			for diff > 0 {
				step := diff
				if step > 64 {
					step = 64
				}
				for i := 31; i > 0; i-- {
					rf.window[i] = (rf.window[i] << step) | (rf.window[i-1] >> (64 - step))
				}
				rf.window[0] <<= step
				diff -= step
			}
			rf.maxSeq = seq
			rf.window[0] |= 1
			return true
		}
		behind := uint32(-delta)
		if behind >= 2048 {
			// Ancient sequence: record it only if it is newer than the window
			// floor in sequence arithmetic — otherwise ignore (the caller
			// should not be accepting such frames anyway).
			return false
		}
		wordIdx := behind / 64
		bitIdx := behind % 64
		if (rf.window[wordIdx] & (1 << bitIdx)) != 0 {
			return false
		}
		rf.window[wordIdx] |= (1 << bitIdx)
		return true
	}
	rf.seenMax = true
	rf.maxSeq = seq
	rf.window[0] |= 1
	return true
}

// CheckAndAdd is the transactional one-shot form: returns true (and records
// nothing) when seq was already accepted, otherwise accepts it and returns
// false. Kept for callers/tests that want check-and-mark in one call.
func (rf *ReplayFilter) CheckAndAdd(seq uint32) bool {
	if rf.Seen(seq) {
		return true
	}
	rf.Accept(seq)
	return false
}

type unackedPkt struct {
	frame         *UDPCFrame
	firstSent     time.Time // when the frame was first sent; used to sample RTT
	sentTime      time.Time
	rto           time.Duration
	retries       int
	retransmitted bool // Karn's rule: never sample RTT from a retransmitted frame
}

type ServerSession struct {
	server        *UDPCServer
	sessionID     uint32
	raddr         net.Addr
	raddrMu       sync.RWMutex
	targetNetwork string
	targetAddr    string
	tcpConn       net.Conn
	udpConn       net.Conn
	noiseSession  *NoiseSession
	replayFilter  ReplayFilter

	sendSeq uint32
	recvSeq uint32

	rttEst *rttEstimator // adaptive RTO estimator (RFC 6298 + Karn's rule)

	recvQueue map[uint32][]byte
	recvMu    sync.Mutex

	unacked   map[uint32]*unackedPkt
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
	pathAddrs map[int]net.Addr
	pathMu    sync.Mutex

	closed    int32
	closeChan chan struct{}
	closeOnce sync.Once
}

func parseTargetNetworkAndAddr(raw string) (network, addr string) {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "udp://") {
		return "udp", strings.TrimPrefix(raw, "udp://")
	}
	if strings.HasPrefix(raw, "tcp://") {
		return "tcp", strings.TrimPrefix(raw, "tcp://")
	}
	return "tcp", raw
}

func NewUDPCServer(cfg ServerConfig) (*UDPCServer, error) {
	if cfg.Magic == 0 {
		cfg.Magic = UDPC_MAGIC_DEFAULT
	}

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
		log.Printf("[WARN] 'listen' port is 0 (got %q): the OS will assign an ephemeral port. For a DNAT target use a fixed port so the firewall rule is stable.", cfg.ListenAddr)
	}

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: bindIP, Port: bindPort})
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", cfg.ListenAddr, err)
	}
	// An inbound burst must not be dropped just because the default socket
	// buffer is small.
	_ = conn.SetReadBuffer(socketBufferSize)
	_ = conn.SetWriteBuffer(socketBufferSize)
	bindPort = conn.LocalAddr().(*net.UDPAddr).Port

	// Recover the client's pre-DNAT destination port so replies can leave from
	// the port the client actually addressed. Required for port-range
	// spreading behind a CGNAT; a no-op (and harmlessly disabled) otherwise.
	origDstOK := false
	if cfg.OrigDst {
		if serr := enableOrigDst(conn); serr != nil {
			log.Printf("[WARN] origdst requested but enable failed: %v (replies will fall back to the main socket)", serr)
		} else {
			origDstOK = true
		}
	}

	// Resolve the configured client port range (the firewall DNATs the whole
	// range onto ListenAddr). This is the single source of truth used at
	// runtime to validate incoming origdst ports and by the gen-* helpers as
	// the default --range.
	pr := portRangeOf(cfg.PortRange)
	if pr != nil {
		log.Printf("📣 [port_range] configured client port range: %s (%d ports); ensure the firewall DNATs it onto %s",
			pr.String(), pr.Total(), conn.LocalAddr())
	}

	srv := &UDPCServer{
		cfg:          cfg,
		conn:         conn,
		bindPort:     bindPort,
		sockPool:     newSendSockPool(cfg.SendSockMax, func(format string, v ...interface{}) { log.Printf("[SockPool] "+format, v...) }),
		origDstOK:    origDstOK,
		portRange:    pr,
		closeChan:    make(chan struct{}),
		logLevel:     parseLogLevel(cfg.LogLevel),
		synCache:     newSynCache(),
		synLimiter:   newSynLimiter(5, 20),
		handshakeSem: make(chan struct{}, 64),
		sendWindow:   defaultSendWindow,
		maxRecvQueue: 512,
	}
	if cfg.SendWindow > 0 {
		srv.sendWindow = cfg.SendWindow
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

func (s *UDPCServer) Start() error {
	netType, target := parseTargetNetworkAndAddr(s.cfg.TargetAddr)
	s.logInfo("UDP server: %s -> Target [%s] %s (origdst=%v)", s.conn.LocalAddr(), netType, target, s.origDstOK)
	if len(s.cfg.Passwords) > 0 {
		s.logInfo("Authentication enabled with %d valid PSK(s)", len(s.cfg.Passwords))
	} else {
		s.logInfo("Open mode (no PSK verification)")
	}

	go s.cleanupLoop()

	go s.serveConn(s.conn)
	select {
	case <-s.closeChan:
		return nil
	}
}

// serveConn is the read loop for the single bound listener. It recovers the
// client's pre-DNAT destination port (origDstPort) via IP_RECVORIGDSTADDR when
// origdst is enabled, so replies can be mirrored back from that port.
func (s *UDPCServer) serveConn(conn *net.UDPConn) {
	buf := make([]byte, 2048)
	for {
		if atomic.LoadInt32(&s.closed) == 1 {
			return
		}
		n, remoteAddr, origDstPort, err := readWithOrigDst(conn, buf)
		if err != nil {
			if atomic.LoadInt32(&s.closed) == 1 {
				return
			}
			s.logWarn("UDP read error: %v", err)
			continue
		}

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

		frame, err := DecodeUDPCFrame(buf[:n], s.cfg.Magic)
		if err != nil {
			continue // ignore invalid magic / corrupted packets
		}

		s.logDebug("[Recv] origDst=%d from=%s cmd=0x%02X seq=%d ack=%d sid=0x%08X len=%d",
			origDstPort, remoteAddr, frame.Cmd, frame.Seq, frame.Ack, frame.SessionID, n)

		if frame.Cmd == CMD_HANDSHAKE_SYN {
			// Cheap DoS gates before anything expensive happens: per-IP rate
			// limit first, then the (verifying) handshake goroutine.
			if ip := ipOf(remoteAddr); !s.synLimiter.Allow(ip, time.Now()) {
				s.logWarn("[Handshake] 🚦 Rate-limited SYN from %s", remoteAddr)
				continue
			}
			go s.handleHandshake(remoteAddr, frame, origDstPort)
			continue
		}

		// Dispatch to existing session.
		//
		// Address-migration policy: under Noise, only a DATA frame that
		// decrypts successfully may move a session to a NEW IP (see
		// handleData). Frames protected by nothing stronger than the 32-bit
		// SessionID (ACK/PING/FIN from an unverified source) may only follow
		// NAT rebinding on the SAME IP. Without Noise the protocol has no
		// per-frame authentication at all, so the legacy behaviour (migrate on
		// any valid-SID frame) is preserved.
		if sessVal, ok := s.sessions.Load(frame.SessionID); ok && sessVal != nil {
			sess := sessVal.(*ServerSession)
			sess.touch()
			allowIPChange := !s.hasPrivKey
			sess.updateRemoteAddr(remoteAddr, allowIPChange)
			sess.setPath(origDstPort, remoteAddr)
			sess.handleIncomingFrame(frame, remoteAddr)
		}
	}
}

func (s *UDPCServer) handleHandshake(remoteAddr net.Addr, frame *UDPCFrame, origPort int) {
	// Verify Handshake payload: [16B Nonce] [8B Timestamp] [32B HMAC-SHA256] [Optional 32B Noise ePub]
	if len(frame.Data) < 56 {
		s.logWarn("[Handshake] Rejected SYN from %s: payload too short (%d bytes)", remoteAddr, len(frame.Data))
		return
	}

	nonce := frame.Data[0:16]
	timestamp := int64(binary.BigEndian.Uint64(frame.Data[16:24]))
	clientSig := frame.Data[24:56]

	// Check time drift (allow +/- 300 seconds)
	now := time.Now().Unix()
	if timestamp < now-300 || timestamp > now+300 {
		s.logWarn("[Handshake] Rejected SYN from %s: expired timestamp (%d vs now %d)", remoteAddr, timestamp, now)
		return
	}

	// Verify PSK Authentication
	if len(s.cfg.Passwords) > 0 {
		if !VerifyAuthHMAC(nonce, s.cfg.Passwords, timestamp, clientSig) {
			s.logWarn("[Handshake] ❌ Rejected SYN from %s: invalid PSK signature", remoteAddr)
			return
		}
	}

	var nonceArr [16]byte
	copy(nonceArr[:], nonce)

	// Idempotent replay handling: a verified nonce we have seen before gets the
	// same ACK resent — no new session, no second target dial. This covers the
	// legitimate case (client lost our ACK and retransmits the SYN) and kills
	// the replay case (captive SYN within the ±300s window can no longer force
	// a fresh target connection per replay).
	if cached := s.synCache.Lookup(nonceArr, time.Now()); cached != nil {
		s.logInfo("[Handshake] ♻️ Replayed SYN from %s: resending cached ACK", remoteAddr)
		s.replyFromOrigPort(origPort, remoteAddr, cached)
		return
	}

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
		if len(frame.Data) < 56+noiseMsg1Size {
			s.logWarn("[Handshake] ❌ Rejected SYN from %s: missing Noise msg1 (need %d bytes, got %d)",
				remoteAddr, noiseMsg1Size, len(frame.Data)-56)
			return
		}
		var err error
		noiseSess, noiseMsg2, err = NewServerNoiseSession(s.privKey, frame.Data[56:56+noiseMsg1Size])
		if err != nil {
			s.logWarn("[Handshake] ❌ Noise_NK handshake failed: %v", err)
			return
		}
		s.logInfo("[Handshake] 🔐 Noise_NK handshake complete for %s (channel binding %x…)",
			remoteAddr, noiseSess.HandshakeHash[:4])
	}

	targetNet, targetHostPort := parseTargetNetworkAndAddr(s.cfg.TargetAddr)

	var tcpConn net.Conn
	var udpConn net.Conn
	var dialErr error

	if targetNet == "udp" {
		udpConn, dialErr = net.Dial("udp", targetHostPort)
	} else {
		tcpConn, dialErr = net.DialTimeout("tcp", targetHostPort, 5*time.Second)
	}

	if dialErr != nil {
		// Close whichever connection was successfully dialed before failing,
		// otherwise the fd leaks for the process lifetime.
		if tcpConn != nil {
			tcpConn.Close()
		}
		if udpConn != nil {
			udpConn.Close()
		}
		s.logError("[Handshake] ❌ Failed to dial target [%s] %s: %v", targetNet, targetHostPort, dialErr)
		return
	}

	// Allocate unique SessionID
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

	sess := &ServerSession{
		server:        s,
		sessionID:     sid,
		raddr:         remoteAddr,
		lastOrigPort:  int32(origPort),
		pathAddrs:     make(map[int]net.Addr),
		targetNetwork: targetNet,
		targetAddr:    targetHostPort,
		tcpConn:       tcpConn,
		udpConn:       udpConn,
		noiseSession:  noiseSess,
		sendSeq:       1,
		recvSeq:       1,
		recvQueue:     make(map[uint32][]byte),
		unacked:       make(map[uint32]*unackedPkt),
		lastActive:    time.Now(),
		closeChan:     make(chan struct{}),
		rttEst:        newRTTEstimator(200*time.Millisecond, 200*time.Millisecond, 10*time.Second),
	}
	sess.unackedCond = sync.NewCond(&sess.unackedMu)
	s.sessions.Store(sid, sess)
	sess.setPath(origPort, remoteAddr)

	// Send Handshake ACK (and remember it, so SYN retransmits get the same
	// session instead of dialing the target again). The ACK carries ONLY the
	// Noise msg2 (when encryption is on); the server never advertises ports —
	// the client chooses its own destination ports from the configured range
	// and the server learns each path from IP_RECVORIGDSTADDR.
	ackData := noiseMsg2
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
	ackEncoded := ackFrame.Encode()
	s.synCache.Remember(nonceArr, ackEncoded, time.Now())
	s.replyFromOrigPort(origPort, remoteAddr, ackEncoded)

	s.logInfo("[Session 0x%08X] ✅ Established for %s -> Target [%s] %s", sid, remoteAddr, targetNet, targetHostPort)

	if targetNet == "udp" {
		go sess.udpToUdpLoop()
	} else {
		go sess.tcpToUdpLoop()
	}
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
func (s *UDPCServer) replyFromOrigPort(origPort int, addr net.Addr, data []byte) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		var err error
		udpAddr, err = net.ResolveUDPAddr("udp", addr.String())
		if err != nil {
			s.logWarn("[Send] ❌ cannot resolve %s: %v", addr, err)
			return
		}
	}
	cmd := cmdOfEncoded(data)
	// The client addressed the listen port directly (no port spreading): the
	// only correct reply source is the main socket, which already holds this
	// port. Skipping the per-port pool avoids a pointless bind(36712) that
	// always fails with EADDRINUSE and only produces misleading warnings.
	if origPort > 0 && origPort != s.bindPort {
		c, err := s.sockPool.Get(origPort)
		if err == nil {
			if n, werr := c.WriteToUDP(data, udpAddr); werr == nil {
				atomic.AddUint64(&s.sendViaPort, 1)
				s.logDebug("[Send] to=%s via=origPort:%d cmd=0x%02X len=%d", udpAddr, origPort, cmd, n)
				return
			} else {
				s.logWarn("[Send] ❌ origPort %d write to=%s cmd=0x%02X: %v (fallback to main)", origPort, udpAddr, cmd, werr)
			}
		} else {
			s.logWarn("[Send] ❌ bind origPort %d failed: %v (fallback to main)", origPort, err)
		}
	}
	// Fallback to the main listening socket (correct behaviour only when the
	// client connected to ListenAddr directly, i.e. no port spreading).
	if n, werr := s.conn.WriteToUDP(data, udpAddr); werr == nil {
		atomic.AddUint64(&s.sendViaMain, 1)
		s.logDebug("[Send] to=%s via=main cmd=0x%02X len=%d", udpAddr, cmd, n)
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

	sess.pathMu.Lock()
	addr := sess.pathAddrs[localPort]
	sess.pathMu.Unlock()
	if addr != nil && localPort > 0 {
		s.replyFromOrigPort(localPort, addr, data)
		return
	}
	// Fallback: try any known path, then the main socket with the last addr.
	sess.pathMu.Lock()
	for p, a := range sess.pathAddrs {
		if p > 0 {
			sess.pathMu.Unlock()
			atomic.StoreInt32(&sess.lastOrigPort, int32(p))
			s.replyFromOrigPort(p, a, data)
			return
		}
	}
	sess.pathMu.Unlock()
	if ra := sess.getRemoteAddr(); ra != nil {
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
// A port-only change (same IP) is accepted from any frame that carries a valid
// SessionID: it is plain NAT rebinding — with port-range spreading it can even
// happen on every datagram — and an off-path attacker who spoofs it can only
// redirect replies into a NAT mapping they cannot read.
//
// An IP change is a genuine migration (WiFi -> cellular) and is worth an INFO
// line — but it is also exactly what a session hijacker needs, so callers must
// only set allowIPChange when the frame was authenticated (PSK/Noise). Under
// Noise this means: successful DATA decryption, enforced in handleData.
func (sess *ServerSession) updateRemoteAddr(newAddr net.Addr, allowIPChange bool) {
	sess.raddrMu.Lock()
	defer sess.raddrMu.Unlock()
	if sess.raddr == nil {
		sess.raddr = newAddr
		return
	}
	if sess.raddr.String() == newAddr.String() {
		return
	}
	sameIP := ipOf(sess.raddr) == ipOf(newAddr)
	if !sameIP && !allowIPChange {
		sess.server.logWarn("[Session 0x%08X] 🛡️ Ignored unauthenticated address change %s -> %s (need an authenticated DATA frame)",
			sess.sessionID, sess.raddr, newAddr)
		return
	}
	if sameIP {
		sess.server.logDebug("[Session 0x%08X] 🔄 NAT rebinding (same IP, new port): %s -> %s",
			sess.sessionID, sess.raddr, newAddr)
	} else {
		sess.server.logInfo("[Session 0x%08X] 🔄 Connection Migration: %s -> %s",
			sess.sessionID, sess.raddr, newAddr)
	}
	sess.raddr = newAddr
}

// ipOf returns the IP portion of an address as a string, or "" if unavailable.
func ipOf(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	if udp, ok := addr.(*net.UDPAddr); ok {
		return udp.IP.String()
	}
	if host, _, err := net.SplitHostPort(addr.String()); err == nil {
		return host
	}
	return addr.String()
}

func (sess *ServerSession) getRemoteAddr() net.Addr {
	sess.raddrMu.RLock()
	defer sess.raddrMu.RUnlock()
	return sess.raddr
}

// setPath records that this session was seen on the pre-DNAT destination port
// coming from client address addr, and marks origPort as the preferred reply
// port. origPort is the pre-DNAT destination port the client addressed; a reply
// socket bound to it (see replyFromOrigPort) carries origPort as its SOURCE
// port — which is what a CGNAT requires in order to accept the packet.
func (sess *ServerSession) setPath(origPort int, addr net.Addr) {
	if origPort <= 0 || addr == nil {
		return
	}
	sess.pathMu.Lock()
	if sess.pathAddrs == nil {
		sess.pathAddrs = make(map[int]net.Addr)
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

func (sess *ServerSession) handleIncomingFrame(frame *UDPCFrame, remoteAddr net.Addr) {
	switch frame.Cmd {
	case CMD_ACK:
		sess.handleAck(frame.Ack)

	case CMD_DATA:
		sess.handleData(frame, remoteAddr)

	case CMD_PING:
		pong := &UDPCFrame{
			Magic:     sess.server.cfg.Magic,
			Version:   UDPC_VERSION,
			Cmd:       CMD_PONG,
			SessionID: sess.sessionID,
			Seq:       frame.Seq,
			Ack:       atomic.LoadUint32(&sess.recvSeq),
		}
		sess.sendToSession(pong.Encode())

	case CMD_FIN:
		sess.server.logInfo("[Session 0x%08X] Received FIN from client", sess.sessionID)
		sess.Close()
	}
}

func (sess *ServerSession) handleAck(ackSeq uint32) {
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
		if isBeforeWrapSafe(seq, ackSeq) || seq == ackSeq {
			delete(sess.unacked, seq)
		}
	}
	sess.unackedMu.Unlock()
	// Free send-window space; keep the broadcast outside the lock to avoid
	// waking a sender straight into a contested mutex.
	sess.unackedCond.Broadcast()
}

func (sess *ServerSession) handleData(frame *UDPCFrame, remoteAddr net.Addr) {
	// Replay gate: reject anything already accepted (delivered or buffered).
	// Wrap-safe; also filters the reserved Seq 0.
	if frame.Seq == 0 || sess.replayFilter.Seen(frame.Seq) {
		return
	}

	expected := atomic.LoadUint32(&sess.recvSeq)
	if frame.Seq != expected {
		if isBeforeWrapSafe(frame.Seq, expected) {
			// Already delivered. The peer is retransmitting because it never
			// saw our ACK, so re-ACK (cumulative) instead of silently
			// dropping — otherwise it would keep retrying until it gave up
			// and tore the session down.
			sess.sendCumulativeACK(expected - 1)
			return
		}
		// Out-of-order: buffer the raw frame and wait for the missing one to
		// be retransmitted. We deliberately do NOT Ack here, so the client
		// keeps the missing sequence outstanding and resends it.
		sess.recvMu.Lock()
		if _, dup := sess.recvQueue[frame.Seq]; !dup {
			if len(sess.recvQueue) >= sess.server.maxRecvQueue {
				atomic.AddUint64(&sess.server.queueFullDrops, 1)
			} else {
				sess.recvQueue[frame.Seq] = frame.Data
			}
		}
		sess.recvMu.Unlock()
		return
	}

	// In-order delivery. Gather the contiguous run (this frame plus anything
	// already buffered behind it) under the lock, then decrypt and deliver
	// OUTSIDE the lock so a slow target write cannot stall the receive path.
	type pending struct {
		seq uint32
		ct  []byte
	}
	run := []pending{{seq: expected, ct: frame.Data}}
	sess.recvMu.Lock()
	next := expected + 1
	for {
		raw, ok := sess.recvQueue[next]
		if !ok {
			break
		}
		delete(sess.recvQueue, next)
		run = append(run, pending{seq: next, ct: raw})
		next++
	}
	sess.recvMu.Unlock()

	delivered := uint32(0)
	for _, p := range run {
		payload := p.ct
		if sess.noiseSession != nil && sess.noiseSession.RecvCipher != nil {
			plain, err := sess.noiseSession.RecvCipher.Decrypt(p.seq, p.ct)
			if err != nil {
				// Corruption or a frame we cannot open: do not advance recvSeq
				// past it and do not Ack it, so the client retransmits. With
				// Seq-derived nonces the retransmission carries the same
				// ciphertext, so a transient corruption self-heals.
				atomic.AddUint64(&sess.server.decryptFailures, 1)
				sess.server.logWarn("[Session 0x%08X] ⚠️ Noise decrypt failed for Seq %d: %v (waiting for retransmission)",
					sess.sessionID, p.seq, err)
				break
			}
			payload = plain
		}
		sess.writeToTarget(payload)
		sess.replayFilter.Accept(p.seq)
		delivered++
	}

	if delivered == 0 {
		return
	}

	atomic.StoreUint32(&sess.recvSeq, expected+delivered)

	// The frame that advanced the stream passed PSK authentication at
	// handshake and (when enabled) a successful AEAD open here, so it is
	// allowed to move the session to a new IP. This is the ONLY
	// address-migration path when Noise is enabled.
	sess.updateRemoteAddr(remoteAddr, true)

	// Ack the highest contiguous sequence we have just delivered.
	sess.sendCumulativeACK(expected + delivered - 1)
}

// sendCumulativeACK emits an ACK meaning "everything up to ackSeq is
// delivered". Used after delivering a run and when re-ACKing a duplicate whose
// original ACK was lost.
func (sess *ServerSession) sendCumulativeACK(ackSeq uint32) {
	ackFrame := &UDPCFrame{
		Magic:      sess.server.cfg.Magic,
		Version:    UDPC_VERSION,
		Cmd:        CMD_ACK,
		SessionID:  sess.sessionID,
		Ack:        ackSeq,
		WindowSize: 65535,
	}
	sess.sendToSession(ackFrame.Encode())
}

func (sess *ServerSession) writeToTarget(data []byte) {
	if len(data) == 0 {
		return
	}
	if sess.targetNetwork == "udp" && sess.udpConn != nil {
		sess.udpConn.Write(data)
	} else if sess.tcpConn != nil {
		sess.tcpConn.Write(data)
	}
}

func (sess *ServerSession) sendData(payload []byte) error {
	// Send window: block while too many frames are still un-ACKed. This is the
	// backpressure that keeps the unacked map (and the retransmit backlog)
	// bounded when the client is slow or silent — the "sliding window" in its
	// simplest form: the read loop stops reading the target until ACKs arrive.
	sess.unackedMu.Lock()
	for len(sess.unacked) >= sess.server.sendWindow && atomic.LoadInt32(&sess.closed) == 0 {
		sess.unackedCond.Wait()
	}
	sess.unackedMu.Unlock()
	if atomic.LoadInt32(&sess.closed) == 1 {
		return fmt.Errorf("session closed")
	}

	seq := atomic.AddUint32(&sess.sendSeq, 1) - 1

	dataToSend := payload
	if sess.noiseSession != nil && sess.noiseSession.SendCipher != nil {
		// Nonce is derived from the frame Seq (see seqNonce), so it must be
		// assigned before encryption and match the header.
		dataToSend = sess.noiseSession.SendCipher.Encrypt(seq, payload)
	}

	frame := &UDPCFrame{
		Magic:      sess.server.cfg.Magic,
		Version:    UDPC_VERSION,
		Cmd:        CMD_DATA,
		SessionID:  sess.sessionID,
		Seq:        seq,
		Ack:        atomic.LoadUint32(&sess.recvSeq),
		WindowSize: 65535,
		Data:       dataToSend,
	}

	encoded := frame.Encode()

	sess.unackedMu.Lock()
	sess.unacked[seq] = &unackedPkt{
		frame:     frame,
		firstSent: time.Now(),
		sentTime:  time.Now(),
		rto:       sess.rttEst.RTO(), // adaptive RTO replaces the old fixed 200ms
		retries:   0,
	}
	sess.unackedMu.Unlock()

	// Server-initiated: reply on the most recently used path so the source
	// port matches the port the client last contacted.
	sess.sendToSession(encoded)
	return nil
}

func (sess *ServerSession) tcpToUdpLoop() {
	defer sess.Close()
	buf := make([]byte, UDPC_MAX_DATA-16)
	for {
		if atomic.LoadInt32(&sess.closed) == 1 {
			return
		}
		n, err := sess.tcpConn.Read(buf)
		if err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
				sess.server.logWarn("[Session 0x%08X] Target TCP read error: %v", sess.sessionID, err)
			}
			return
		}
		if n > 0 {
			sess.touch()
			sess.sendData(buf[:n])
		}
	}
}

func (sess *ServerSession) udpToUdpLoop() {
	defer sess.Close()
	buf := make([]byte, UDPC_MAX_DATA-16)
	for {
		if atomic.LoadInt32(&sess.closed) == 1 {
			return
		}
		n, err := sess.udpConn.Read(buf)
		if err != nil {
			return
		}
		if n > 0 {
			sess.touch()
			sess.sendData(buf[:n])
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
					if pkt.retries == 1 {
						pkt.retransmitted = true // flagged on the first retry; later ones are not sampled
					}
					pkt.rto = time.Duration(float64(pkt.rto) * 1.5) // back off 1.5x from the adaptive RTO
					if pkt.rto > sess.rttEst.maxRTT {
						pkt.rto = sess.rttEst.maxRTT
					}
					sess.sendToSession(pkt.frame.Encode())
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
		if sess.tcpConn != nil {
			sess.tcpConn.Close()
		}
		if sess.udpConn != nil {
			sess.udpConn.Close()
		}
		sess.server.sessions.Delete(sess.sessionID)
		sess.server.logInfo("[Session 0x%08X] 🛑 Session closed", sess.sessionID)
	})
}

// synRecord caches the result of a verified handshake so a retransmitted or
// replayed SYN can be answered idempotently.
type synRecord struct {
	ackFrame  []byte // pre-encoded CMD_HANDSHAKE_ACK for the created session
	createdAt time.Time
}

// synCache maps a 16-byte handshake nonce to its verified handshake result.
// Entries expire after synCacheTTL and the map is FIFO-evicted at synCacheMax,
// so memory stays bounded even under a SYN flood.
type synCache struct {
	mu      sync.Mutex
	entries map[[16]byte]synRecord
	fifo    [][16]byte // insertion order, for eviction
}

func newSynCache() *synCache {
	return &synCache{entries: make(map[[16]byte]synRecord)}
}

// Lookup returns the cached ack for a nonce, or nil. Expired entries are
// treated as absent.
func (c *synCache) Lookup(nonce [16]byte, now time.Time) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	rec, ok := c.entries[nonce]
	if !ok {
		return nil
	}
	if now.Sub(rec.createdAt) > synCacheTTL {
		delete(c.entries, nonce)
		return nil
	}
	return rec.ackFrame
}

// Remember stores the ack for a nonce, pruning expired / oldest entries first.
func (c *synCache) Remember(nonce [16]byte, ackFrame []byte, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries[nonce]; ok {
		return
	}
	if len(c.fifo) >= synCacheMax {
		// Drop every expired entry first, then fall back to FIFO eviction.
		for k, rec := range c.entries {
			if now.Sub(rec.createdAt) > synCacheTTL {
				delete(c.entries, k)
			}
		}
		for len(c.fifo) >= synCacheMax {
			oldest := c.fifo[0]
			c.fifo = c.fifo[1:]
			delete(c.entries, oldest)
		}
	}
	c.entries[nonce] = synRecord{ackFrame: ackFrame, createdAt: now}
	c.fifo = append(c.fifo, nonce)
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

func (s *UDPCServer) cleanupLoop() {
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
			// and whether decryption / buffering is silently dropping.
			s.logDebug("[Stats] origdst=%v portRange=%v sendsocks=%d viaPort=%d viaMain=%d portChanges=%d decryptFail=%d queueFull=%d outOfRange=%d",
				s.origDstOK,
				s.portRange != nil,
				s.sockPool.Len(),
				atomic.LoadUint64(&s.sendViaPort),
				atomic.LoadUint64(&s.sendViaMain),
				atomic.LoadUint64(&s.origPortChanges),
				atomic.LoadUint64(&s.decryptFailures),
				atomic.LoadUint64(&s.queueFullDrops),
				atomic.LoadUint64(&s.outOfRangePkts))
		}
	}
}

func (s *UDPCServer) Close() {
	if atomic.CompareAndSwapInt32(&s.closed, 0, 1) {
		close(s.closeChan)
		if s.conn != nil {
			s.conn.Close()
		}
		if s.sockPool != nil {
			s.sockPool.Close()
		}
		s.sessions.Range(func(key, value interface{}) bool {
			sess := value.(*ServerSession)
			sess.Close()
			return true
		})
	}
}
