package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// udp_custom CLIENT (config.json "mode": "client").
//
// The client is the mirror image of the server: it listens on a LOCAL port for
// ordinary applications, and tunnels each accepted connection through the
// udp_custom ARQ protocol to a udp_custom server, which forwards it to the real
// backend.
//
//	app ──tcp──► client ──udp_custom DATA/ACK over possibly many ports──► server ──tcp──► backend
//
// Every protocol piece the server uses is reused here verbatim:
// PortSelector/SpreadDialer (port spreading, including n:n with several local
// sockets), the RFC 6298 RTT estimator, Noise_NK (client side), and the
// PacketNo-derived AEAD nonces that make retransmission and reordering safe.

// Log levels mirror parseLogLevel in server.go (debug=0 … error=3).
const (
	LogLevelDebug = 0
	LogLevelInfo  = 1
	LogLevelWarn  = 2
	LogLevelError = 3
)

const (
	clientMaxHandshakeAttempts = 8
	clientHandshakeBackoff     = 400 * time.Millisecond
	clientKeepAliveInterval    = 15 * time.Second
	clientRecvTimeout          = 75 * time.Second // > server's 60s idle cleanup
	clientMaxRetries           = 15
	clientRetransmitInterval   = 50 * time.Millisecond
)

type ClientConfig struct {
	// ListenAddr is the local address applications connect to, e.g. "127.0.0.1:1080".
	ListenAddr string
	// ServerAddr is the udp_custom server, "host:port" or "host:port-range".
	ServerAddr string
	// Target is the forwarding endpoint REQUESTED in the handshake, e.g.
	// "tcp://127.0.0.1:22" or "udp://10.0.0.5:51820". Empty (default) asks for
	// the server's default target. The server only honors requests that pass
	// its allowed_targets filter; a denied request means the handshake never
	// completes. The granted endpoint is what the server actually forwards to.
	Target    string
	Passwords []string
	Magic     uint32
	// ServerPub is the server's Noise static public key. Zero = no encryption.
	ServerPub  [32]byte
	LogLevel   string
	Sockets    int // local sockets for n:n spreading (<=0 or 1 = single socket)
	Paths      int // distinct remote ports to randomly pick from the range (<=0 = spread over the whole range per packet)
	SendWindow int // frames in flight before backpressure (0 = 256)

	// Logger receives diagnostic output. When nil, the LogLevel string decides
	// verbosity on the standard logger; an injected Logger wins over LogLevel
	// entirely. Embedders wanting silence pass Nop.
	Logger Logger `json:"-"`
	// ListenUDP optionally creates the sockets used by the spread dialer.
	ListenUDP UDPListenFunc `json:"-"`
}

// Client fronts local applications and tunnels them to one udp_custom server.
// The CLI uses Start (TCP listener front-end); embedders use DialTunnel to get
// one tunneled net.Conn per call without any local listener.
type Client struct {
	cfg    ClientConfig
	magic  uint32
	logger Logger // never nil after NewClient (tests may build bare literals)

	dialer *SpreadDialer

	sessions sync.Map // sessionID -> *clientSession

	// startOnce guards the lazily-started UDP receive loops (DialTunnel path;
	// Start starts them eagerly).
	startOnce sync.Once

	// Handshake ACKs echo ClientNonce, allowing independent local connections
	// to establish concurrently without sharing a global handshake lock.
	ackMu       sync.Mutex
	pendingAcks map[[clientNonceSize]byte]*pendingHandshake

	// events delivers ClientEvent notifications to the embedder's handler on
	// a dedicated goroutine (never on the receive path). nil bus = no events.
	events *eventBus[ClientEvent]

	closeOnce sync.Once
	closeChan chan struct{}
	closed    int32
	wg        sync.WaitGroup
}

// ClientEventKind enumerates the client-side lifecycle notifications.
type ClientEventKind int

const (
	// TunnelEstablished fires on the DialTunnel caller's goroutine right
	// after a handshake completes.
	TunnelEstablished ClientEventKind = iota
	// TunnelDied fires when a session ends (reason in Detail).
	TunnelDied
	// Reconnecting fires before each re-dial attempt made by
	// AutoReconnect (nth attempt in Attempt, starting at 1).
	Reconnecting
	// HandshakeRetrying fires when a SYN timed out and the client is about
	// to retransmit (Attempt = the upcoming attempt number).
	HandshakeRetrying
)

func (k ClientEventKind) String() string {
	switch k {
	case TunnelEstablished:
		return "established"
	case TunnelDied:
		return "died"
	case Reconnecting:
		return "reconnecting"
	case HandshakeRetrying:
		return "handshake-retrying"
	}
	return "unknown"
}

// ClientEvent is one client-side lifecycle notification.
type ClientEvent struct {
	Kind    ClientEventKind
	Session uint32 // session ID when known, 0 during handshakes
	Detail  string // human-readable context: death reason, target, ...
	Attempt int    // Reconnecting / HandshakeRetrying only
}

// SetEventHandler registers a callback for client lifecycle events. The
// handler runs on a DEDICATED goroutine (never on receive paths): it may
// block, but under sustained event pressure slow handlers cause drops —
// watch TunnelSession-level counters for authoritative state. Panics in the
// handler are recovered and logged.
func (c *Client) SetEventHandler(h func(ClientEvent)) {
	c.events.setHandler(h)
}

// EventsDropped reports how many events were discarded because the handler
// could not keep up. Zero on a healthy consumer.
func (c *Client) EventsDropped() uint64 { return c.events.droppedCount() }

type pendingHandshake struct {
	ackMAC [32]byte
	ch     chan *UDPCFrame
}

// DialOptions carries the per-tunnel parameters for Client.DialTunnel.
type DialOptions struct {
	// Target requests the forwarding endpoint ("tcp://host:port" /
	// "udp://host:port"). Empty = the server's default target. The request
	// must pass the server's allowed_targets filter or the handshake never
	// completes (the server silently drops denied SYNs).
	Target string
	// OnGranted, when set, receives the endpoint the server actually granted
	// ("" = the server default) once the handshake succeeds.
	OnGranted func(granted string)
}

func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.ServerAddr == "" {
		return nil, fmt.Errorf("client: 'server' is required (udp_custom server address)")
	}
	passwords := make([]string, 0, len(cfg.Passwords))
	for _, password := range cfg.Passwords {
		if password = strings.TrimSpace(password); password != "" {
			passwords = append(passwords, password)
		}
	}
	if len(passwords) == 0 {
		return nil, fmt.Errorf("client: at least one password (PSK) is required")
	}
	cfg.Passwords = passwords
	if cfg.Magic == 0 {
		cfg.Magic = UDPC_MAGIC_DEFAULT
	}
	if cfg.SendWindow <= 0 {
		cfg.SendWindow = defaultSendWindow
	}

	dialer, err := newSpreadDialer(cfg.ServerAddr, cfg.Sockets, cfg.Paths, cfg.ListenUDP)
	if err != nil {
		return nil, err
	}
	return &Client{
		cfg:         cfg,
		magic:       cfg.Magic,
		logger:      resolveLogger(cfg.Logger, cfg.LogLevel),
		dialer:      dialer,
		events:      newEventBus[ClientEvent](128),
		pendingAcks: make(map[[clientNonceSize]byte]*pendingHandshake),
		closeChan:   make(chan struct{}),
	}, nil
}

func (c *Client) logDebug(format string, args ...any) {
	if c.logger != nil {
		c.logger.Debugf(format, args...)
	}
}
func (c *Client) logInfo(format string, args ...any) {
	if c.logger != nil {
		c.logger.Infof(format, args...)
	}
}
func (c *Client) logWarn(format string, args ...any) {
	if c.logger != nil {
		c.logger.Warnf(format, args...)
	}
}
func (c *Client) logError(format string, args ...any) {
	if c.logger != nil {
		c.logger.Errorf(format, args...)
	}
}

// Start blocks: it serves local applications until Close is called. This is
// the CLI-facing mode; embedders that want single connections use DialTunnel.
func (c *Client) Start() error {
	if c.cfg.ListenAddr == "" {
		return fmt.Errorf("client: 'listen' is required for Start (CLI mode); embedders use DialTunnel instead")
	}
	ln, err := net.Listen("tcp", c.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("client listen %s: %w", c.cfg.ListenAddr, err)
	}
	c.startOnce.Do(c.startRecvLoops) // Start 与 DialTunnel 共用同一条懒启动路径，杜绝双收包循环
	c.logInfo("[Client] 🚀 udp_custom client listening on %s", ln.Addr())
	portDesc := fmt.Sprintf("%d port(s) in range", c.dialer.PortRange().Total())
	if p := c.dialer.Paths(); p > 0 {
		portDesc = fmt.Sprintf("%d chosen port(s) from range", p)
	}
	c.logInfo("[Client] 🔗 Tunnel to server %s (spread: %d socket(s) x %s)",
		c.cfg.ServerAddr, c.dialer.Len(), portDesc)
	if c.cfg.Target != "" {
		c.logInfo("[Client] 🎯 Requested target: %s", c.cfg.Target)
	}

	go func() {
		<-c.closeChan
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if atomic.LoadInt32(&c.closed) == 1 {
				return nil
			}
			return fmt.Errorf("client accept: %w", err)
		}
		c.wg.Add(1)
		go func(conn net.Conn) {
			defer c.wg.Done()
			c.serveConn(conn, c.cfg.Target)
		}(conn)
	}
}

// startRecvLoops launches one receive goroutine per spread socket. Called by
// Start and lazily by DialTunnel (once; subsequent calls are no-ops).
func (c *Client) startRecvLoops() {
	for idx := 0; idx < c.dialer.Len(); idx++ {
		c.wg.Add(1)
		go func(idx int) {
			defer c.wg.Done()
			c.recvSocketLoop(idx)
		}(idx)
	}
}

// recvSocketLoop supervises one spread slot for the lifetime of the Client.
// A fatal socket read (interface teardown, VPN revocation, descriptor failure)
// is repaired in-place; every session automatically starts using the new
// socket because sends address slots rather than retaining conn pointers.
func (c *Client) recvSocketLoop(idx int) {
	backoff := 100 * time.Millisecond
	for atomic.LoadInt32(&c.closed) == 0 {
		conn := c.dialer.Conn(idx)
		if conn == nil {
			return
		}
		err := c.recvFromSocket(conn)
		if atomic.LoadInt32(&c.closed) == 1 {
			return
		}
		c.logWarn("[Client] UDP receive socket %d failed: %v; rebuilding", idx, err)
		for atomic.LoadInt32(&c.closed) == 0 {
			if _, reopenErr := c.dialer.Reopen(idx, conn); reopenErr == nil {
				backoff = 100 * time.Millisecond
				break
			} else {
				c.logWarn("[Client] UDP receive socket %d rebuild failed: %v", idx, reopenErr)
			}
			timer := time.NewTimer(backoff)
			select {
			case <-c.closeChan:
				if !timer.Stop() {
					<-timer.C
				}
				return
			case <-timer.C:
			}
			backoff = minDuration(backoff*2, 5*time.Second)
		}
	}
}

// DialTunnel establishes one tunnel session and returns its local end as a
// net.Conn: writes are tunneled to the granted target, reads return the
// target's responses. Embedders use this instead of Start — no local TCP
// listener, no per-app port.
//
// The first call lazily starts the shared UDP receive loops; Client.Close
// tears down every tunnel at once. opts.Target requests a specific endpoint
// (subject to the server's allowed_targets filter); opts.OnGranted observes
// the granted one. Closing the returned conn tears only this session down.
//
// Connection semantics: the returned conn is a net.Pipe end — synchronous,
// unbuffered. A Write blocks until the tunnel session has consumed the bytes,
// and Read blocks until the target (through the tunnel) produces data. Use
// SetDeadline for timeouts; a deadline covers both directions. For TCP-style
// pipelining (write burst, read burst), callers that need buffered semantics
// should wrap the conn in a bufio.Writer.
//
// Errors: ErrClosed after Client.Close, ErrHandshakeTimeout when the server
// never answers (unreachable / PSK mismatch / target denied by
// allowed_targets), ctx.Err() on cancellation — all matchable via errors.Is.
//
// The returned conn is a *TunnelSession, which additionally exposes Done()
// (closed when the session ends for any reason) and Err() (the terminal
// cause), so embedders can select on session death instead of waiting for a
// failed Read.
func (c *Client) DialTunnel(ctx context.Context, opts DialOptions) (net.Conn, error) {
	if atomic.LoadInt32(&c.closed) == 1 {
		return nil, ErrClosed
	}
	c.startOnce.Do(c.startRecvLoops)

	appConn, sessionConn := net.Pipe()
	type established struct {
		sess *clientSession
		err  error
	}
	done := make(chan established, 1)
	go func() {
		sess, err := c.establish(ctx, opts.Target, sessionConn)
		done <- established{sess, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			appConn.Close()
			return nil, r.err
		}
		if opts.OnGranted != nil {
			// Runs on the DialTunnel caller's goroutine, before the first byte
			// can flow — embedders may rely on that ordering.
			opts.OnGranted(r.sess.granted)
		}
		return newTunnelSession(appConn, r.sess), nil
	case <-ctx.Done():
		// The handshake may still be in flight; it cleans up after itself, and
		// once it lands, closing both pipe ends tears any session down.
		go func() {
			r := <-done
			appConn.Close()
			sessionConn.Close()
			if r.err == nil && r.sess != nil {
				r.sess.close()
			}
		}()
		return nil, ctx.Err()
	}
}

// TunnelSession is the net.Conn returned by DialTunnel plus session-lifetime
// observation: Done closes when the session ends for ANY reason (peer FIN,
// idle timeout, retransmit exhaustion, target failure, Client.Close), and Err
// reports the cause once it has.
type TunnelSession struct {
	net.Conn
	sess *clientSession
	done chan struct{}

	errMu sync.Mutex
	err   error
}

func newTunnelSession(conn net.Conn, sess *clientSession) *TunnelSession {
	ts := &TunnelSession{Conn: conn, sess: sess, done: make(chan struct{})}
	go func() {
		<-sess.closeChan
		sess.closeReasonMu.Lock()
		reason := sess.closeReason
		sess.closeReasonMu.Unlock()
		ts.errMu.Lock()
		if reason == "" {
			ts.err = ErrTunnelClosed
		} else {
			ts.err = fmt.Errorf("%w: %s", ErrTunnelClosed, reason)
		}
		ts.errMu.Unlock()
		close(ts.done)
	}()
	return ts
}

// Done is closed when the tunnel session ends (peer FIN, idle timeout,
// retransmit exhaustion, target failure, or Client.Close). It is the
// context.Done analogue for a tunnel session.
func (t *TunnelSession) Done() <-chan struct{} { return t.done }

// Err returns the reason the session ended, or nil while it is alive. Valid
// only after Done is closed.
func (t *TunnelSession) Err() error {
	t.errMu.Lock()
	defer t.errMu.Unlock()
	return t.err
}

// ClientStats is a point-in-time snapshot of a Client's live state, for
// embedders that want to export it alongside ServerStats.
type ClientStats struct {
	Sessions int // live tunnels (gauge)
	Sockets  int // local UDP sockets in the spread set
	Paths    int // distinct remote ports pinned for the session (0 = whole range)
}

// Stats returns a snapshot of the client's live state.
func (c *Client) Stats() ClientStats {
	st := ClientStats{
		Sockets: c.dialer.Len(),
		Paths:   c.dialer.Paths(),
	}
	c.sessions.Range(func(_, _ any) bool {
		st.Sessions++
		return true
	})
	return st
}

func (c *Client) Close() {
	c.closeOnce.Do(func() {
		atomic.StoreInt32(&c.closed, 1)
		close(c.closeChan)
		c.sessions.Range(func(_, v any) bool {
			if s, ok := v.(*clientSession); ok {
				s.close()
			}
			return true
		})
		c.dialer.Close()
		c.logInfo("[Client] 🛑 Client stopped")
		c.events.close()
	})
}

// --- receive path -------------------------------------------------------------

func (c *Client) recvLoop(conn *net.UDPConn) {
	_ = c.recvFromSocket(conn)
}

func (c *Client) recvFromSocket(conn *net.UDPConn) error {
	buf := make([]byte, UDPC_MAX_PKT)
	// The 1s read deadline exists solely so this loop can notice Close. It is
	// refreshed only once per second at most — under load that is one
	// SetReadDeadline syscall per second, not per packet.
	var deadline time.Time
	for {
		select {
		case <-c.closeChan:
			return nil
		default:
		}
		if now := time.Now(); !now.Before(deadline) {
			deadline = now.Add(time.Second)
			conn.SetReadDeadline(deadline)
		}
		n, remoteAddr, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if atomic.LoadInt32(&c.closed) == 1 {
				return nil
			}
			return err
		}
		if !c.dialer.acceptsRemote(netip.AddrPortFrom(remoteAddr.Addr().Unmap(), remoteAddr.Port())) {
			continue
		}
		var frame UDPCFrame
		if err := decodeUDPCFrame(buf[:n], c.magic, &frame); err != nil {
			continue
		}
		c.dispatch(&frame)
	}
}

func (c *Client) dispatch(frame *UDPCFrame) {
	if frame.Cmd == CMD_HANDSHAKE_ACK {
		if frame.SessionID == 0 || frame.PacketNo != 0 || frame.Seq != 0 || frame.Ack != 0 || len(frame.Data) < ackPayloadBase {
			return
		}
		var clientNonce [clientNonceSize]byte
		copy(clientNonce[:], frame.Data[:clientNonceSize])
		c.ackMu.Lock()
		pending := c.pendingAcks[clientNonce]
		c.ackMu.Unlock()
		// Authenticate before enqueueing so a forged burst cannot occupy the
		// bounded candidate queue and starve the genuine server response.
		if pending != nil && VerifyFrameAuth(frame.raw, &pending.ackMAC) == nil {
			owned := *frame
			owned.raw = append([]byte(nil), frame.raw...)
			owned.Data = owned.raw[UDPC_HDR_SIZE : UDPC_HDR_SIZE+len(frame.Data)]
			select {
			case pending.ch <- &owned:
			default:
			}
		}
		return
	}
	v, ok := c.sessions.Load(frame.SessionID)
	if !ok {
		c.logDebug("[Client] frame for unknown session 0x%08X (cmd=%d)", frame.SessionID, frame.Cmd)
		return
	}
	sess := v.(*clientSession)
	if !validSessionFrameShape(frame) {
		return
	}
	if sess.frameKeys == nil {
		c.logDebug("[Client] [Session 0x%08X] ⚠️ session has no record protection", sess.sid)
		return
	}
	// Decrypt into a pooled scratch buffer: everything below consumes the
	// plaintext synchronously (app write / reorder-queue copy) and nothing
	// retains it past dispatch, so the buffer is returned at the end of the
	// dispatch — every path above/below is synchronous by construction.
	var err error
	buf := getDecryptBuf()
	defer putDecryptBuf(buf)
	frame.Data, err = OpenFrameAEADInto(buf, frame, sess.frameKeys.Recv)
	if err != nil {
		c.logDebug("[Client] [Session 0x%08X] ⚠️ Frame authentication rejected cmd=0x%02X: %v", sess.sid, frame.Cmd, err)
		return
	}
	if !sess.replayFilter.Accept(frame.PacketNo) {
		if frame.Cmd == CMD_DATA {
			sess.reackDuplicateData()
		}
		return
	}
	if frame.Ack > 0 {
		sess.handleAck(frame.Ack)
	}
	switch frame.Cmd {
	case CMD_DATA:
		if !sess.handleData(frame) {
			sess.replayFilter.Remove(frame.PacketNo)
		}
	case CMD_ACK:
		sess.touch()
	case CMD_PING:
		sess.touch()
		pong := &UDPCFrame{Magic: c.magic, Version: UDPC_VERSION, Cmd: CMD_PONG, SessionID: sess.sid, Ack: sess.currentAck()}
		sess.sendControl(pong, c.dialer.Send)
	case CMD_PONG:
		sess.touch()
	case CMD_FIN:
		c.logInfo("[Client] [Session 0x%08X] Server sent FIN", sess.sid)
		sess.closeWithReason("server sent FIN")
	case CMD_PATH_CHALLENGE:
		response := &UDPCFrame{
			Magic: c.magic, Version: UDPC_VERSION, Cmd: CMD_PATH_RESPONSE,
			SessionID: sess.sid, Data: append([]byte(nil), frame.Data...),
		}
		sess.sendControl(response, c.dialer.Send)
	}
}

// --- handshake -----------------------------------------------------------------

// establish performs the handshake, registers the session, starts its pump
// loops, and returns it. The session's conn is the caller-supplied local end.
func (c *Client) establish(ctx context.Context, target string, conn net.Conn) (*clientSession, error) {
	sid, _, frameKeys, granted, err := c.handshake(ctx, target)
	if err != nil {
		if conn != nil {
			conn.Close()
		}
		c.events.emit(ClientEvent{Kind: TunnelDied, Detail: "handshake failed: " + err.Error()})
		return nil, err
	}
	if granted != "" && granted != target {
		c.logInfo("[Client] [Session 0x%08X] 🎯 Server granted target %s (requested %s)", sid, granted, target)
	}

	sess := &clientSession{
		client: c,
		sid:    sid,
		conn:   conn,

		frameKeys:  frameKeys,
		granted:    granted,
		sendSeq:    1,
		recvSeq:    1,
		recvQueue:  make(map[uint64][]byte),
		unacked:    make(map[uint64]*unackedPkt),
		lastActive: time.Now(),
		lastSent:   time.Now(),
		closeChan:  make(chan struct{}),
		rttEst:     newRTTEstimator(200*time.Millisecond, 200*time.Millisecond, 10*time.Second),
	}
	sess.unackedCond = sync.NewCond(&sess.unackedMu)
	c.sessions.Store(sid, sess)
	c.logInfo("[Client] [Session 0x%08X] ✅ Tunnel established", sid)
	c.events.emit(ClientEvent{Kind: TunnelEstablished, Session: sid, Detail: granted})

	go func() {
		defer c.sessions.Delete(sid)
		defer conn.Close()
		c.logDebug("[Client] [Session 0x%08X] pump loop exiting", sid)
		sess.localToRemote()
		sess.close()
	}()
	go sess.retransmitLoop()
	go sess.keepAliveLoop()
	// Session death → TunnelDied event with the recorded root cause.
	go func() {
		<-sess.closeChan
		sess.closeReasonMu.Lock()
		reason := sess.closeReason
		sess.closeReasonMu.Unlock()
		c.events.emit(ClientEvent{Kind: TunnelDied, Session: sid, Detail: reason})
	}()
	return sess, nil
}

func (c *Client) serveConn(conn net.Conn, target string) {
	sess, err := c.establish(ctxBackground(), target, conn)
	if err != nil {
		c.logError("[Client] ❌ Handshake failed for %s: %v", conn.RemoteAddr(), err)
		conn.Close()
		return
	}
	<-sess.closeChan
	c.logInfo("[Client] [Session 0x%08X] 🛑 Closed", sess.sid)
}

func ctxBackground() context.Context { return context.Background() }

// handshake sends the SYN (retransmitting until the ACK arrives) and returns
// the new SessionID, record protection and the target the server actually
// granted ("" for the server's default). The request rides inside the MAC'd
// SYN payload; a server that does not allow it silently drops the SYN, which
// surfaces here as "no handshake ACK". Retransmissions reuse the exact SYN;
// the server's nonce cache responds with the exact same ACK/session.
func (c *Client) handshake(ctx context.Context, target string) (uint32, *NoiseSession, *FrameKeys, string, error) {
	if len(target) > TargetMaxLen {
		return 0, nil, nil, "", fmt.Errorf("target %q exceeds %d bytes", target, TargetMaxLen)
	}
	var nk *ClientNK
	var msg1 []byte
	var zero [32]byte
	encrypted := c.cfg.ServerPub != zero
	if encrypted {
		var err error
		nk, err = NewClientNK(c.cfg.ServerPub)
		if err != nil {
			return 0, nil, nil, "", err
		}
		msg1, err = nk.Message1()
		if err != nil {
			return 0, nil, nil, "", err
		}
	}

	var clientNonce [clientNonceSize]byte
	if _, err := rand.Read(clientNonce[:]); err != nil {
		return 0, nil, nil, "", fmt.Errorf("nonce: %w", err)
	}
	handshakeKeys := DerivePSKHandshakeKeys(c.cfg.Passwords[0], clientNonce)

	// [16B ClientNonce] [8B Timestamp] [target TLV] [optional 48B msg1].
	payload := make([]byte, synPayloadBase)
	now := time.Now().Unix()
	copy(payload[:clientNonceSize], clientNonce[:])
	binary.BigEndian.PutUint64(payload[clientNonceSize:synPayloadBase], uint64(now))
	payload = appendTargetTLV(payload, target)
	payload = append(payload, msg1...)

	syn := SealFrameMAC(&UDPCFrame{
		Magic: c.magic, Version: UDPC_VERSION,
		Cmd: CMD_HANDSHAKE_SYN, Data: payload,
	}, &handshakeKeys.SynMAC)
	if len(syn) == 0 {
		return 0, nil, nil, "", fmt.Errorf("failed to seal SYN")
	}

	ch := make(chan *UDPCFrame, 8)
	c.ackMu.Lock()
	if _, exists := c.pendingAcks[clientNonce]; exists {
		c.ackMu.Unlock()
		return 0, nil, nil, "", ErrNonceCollision
	}
	c.pendingAcks[clientNonce] = &pendingHandshake{ackMAC: handshakeKeys.AckMAC, ch: ch}
	c.ackMu.Unlock()
	defer func() {
		c.ackMu.Lock()
		delete(c.pendingAcks, clientNonce)
		c.ackMu.Unlock()
	}()

	for attempt := 1; attempt <= clientMaxHandshakeAttempts; attempt++ {
		if err := c.dialer.SendAt(0, syn); err != nil {
			c.logDebug("[Client] Handshake attempt %d send failed: %v", attempt, err)
		}
		timeout := clientHandshakeBackoff * time.Duration(attempt)
		timer := time.NewTimer(timeout)
		waiting := true
		for waiting {
			select {
			case ack := <-ch:
				// An unauthenticated forged ACK is noise, not a terminal handshake
				// error. Keep waiting for the genuine response until the deadline.
				if err := VerifyFrameAuth(ack.raw, &handshakeKeys.AckMAC); err != nil {
					c.logDebug("[Client] ignored invalid handshake ACK: %v", err)
					continue
				}
				granted, noiseMsg2, err := splitAckPayload(ack.Data, encrypted)
				if err != nil {
					timer.Stop()
					return 0, nil, nil, "", fmt.Errorf("authenticated handshake ACK payload: %w", err)
				}
				var echoedNonce [clientNonceSize]byte
				copy(echoedNonce[:], ack.Data[:clientNonceSize])
				if echoedNonce != clientNonce {
					continue
				}
				var serverNonce [serverNonceSize]byte
				copy(serverNonce[:], ack.Data[clientNonceSize:ackPayloadBase])
				if !encrypted {
					keys := DerivePSKSessionKeys(c.cfg.Passwords[0], clientNonce, serverNonce, ack.SessionID)
					frameKeys, err := keys.ClientFrameCiphers()
					if err != nil {
						timer.Stop()
						return 0, nil, nil, "", fmt.Errorf("session cipher init: %w", err)
					}
					timer.Stop()
					return ack.SessionID, nil, frameKeys, granted, nil
				}
				sess, err := nk.Finish(noiseMsg2)
				if err != nil {
					timer.Stop()
					return 0, nil, nil, "", fmt.Errorf("noise finish: %w", err)
				}
				c.logInfo("[Client] 🔐 Noise_NK established (channel binding %x…)", sess.HandshakeHash[:4])
				timer.Stop()
				return ack.SessionID, sess, &FrameKeys{Send: sess.SendCipher, Recv: sess.RecvCipher}, granted, nil
			case <-timer.C:
				c.logDebug("[Client] Handshake attempt %d timed out, retrying", attempt)
				if attempt < clientMaxHandshakeAttempts {
					c.events.emit(ClientEvent{Kind: HandshakeRetrying, Attempt: attempt + 1})
				}
				waiting = false
			case <-c.closeChan:
				timer.Stop()
				return 0, nil, nil, "", fmt.Errorf("client closed")
			case <-ctx.Done():
				timer.Stop()
				return 0, nil, nil, "", ctx.Err()
			}
		}
	}
	return 0, nil, nil, "", fmt.Errorf("%w (check: server reachable? same PSK on both ends? requested target allowed by the server's allowed_targets? - denied requests are silently dropped)", ErrHandshakeTimeout)
}

// --- session -------------------------------------------------------------------

type clientSession struct {
	client *Client
	sid    uint32
	conn   net.Conn // local application connection

	// frameKeys is used only by PSK-only sessions; Noise sessions use transport
	// AEAD for DATA and control records.
	frameKeys *FrameKeys

	// granted is the endpoint the server echoed in the handshake ACK ("" =
	// the server's default target). Exposed through DialOptions.OnGranted.
	granted string

	sendPacketNo uint64
	sendSeq      uint64
	recvSeq      uint64
	replayFilter ReplayFilter

	recvQueue map[uint64][]byte
	recvMu    sync.Mutex

	unacked     map[uint64]*unackedPkt
	unackedMu   sync.Mutex
	unackedCond *sync.Cond

	rttEst *rttEstimator

	lastActive time.Time
	lastSent   time.Time
	mu         sync.Mutex

	closeOnce sync.Once
	closeChan chan struct{}
	closed    int32

	// closeReason records the FIRST close cause for TunnelSession.Err().
	closeReason   string
	closeReasonMu sync.Mutex
}

func (s *clientSession) touch() {
	s.mu.Lock()
	s.lastActive = time.Now()
	s.mu.Unlock()
}

func (s *clientSession) isClosed() bool { return atomic.LoadInt32(&s.closed) == 1 }

// closeWithReason closes the session and records WHY, for TunnelSession.Err().
// The reason string is human-readable and stable enough for log matching.
func (s *clientSession) closeWithReason(reason string) {
	if reason == "" {
		reason = "closed"
	}
	s.closeReasonMu.Lock()
	if s.closeReason == "" {
		s.closeReason = reason // first writer wins: the root cause
	}
	s.closeReasonMu.Unlock()
	s.close()
}

func (s *clientSession) close() {
	s.closeOnce.Do(func() {
		atomic.StoreInt32(&s.closed, 1)
		s.unackedMu.Lock()
		if s.unackedCond != nil {
			s.unackedCond.Broadcast()
		}
		s.unackedMu.Unlock()
		close(s.closeChan)
		if s.conn != nil {
			// Tell the server to tear the session down; best effort.
			fin := &UDPCFrame{
				Magic: s.client.magic, Version: UDPC_VERSION,
				Cmd: CMD_FIN, SessionID: s.sid,
			}
			s.sendControl(fin, s.client.dialer.Send)
			s.conn.Close()
		}
	})
}

// localToRemote streams the local application's bytes into the tunnel.
func (s *clientSession) localToRemote() {
	// A short read deadline keeps a half-closed connection from pinning the
	// session forever; a timeout is the marker for "no data right now". The
	// deadline is refreshed at most once per second (see recvLoop).
	buf := make([]byte, UDPC_MAX_DATA)
	var deadline time.Time
	for {
		if s.isClosed() {
			return
		}
		if now := time.Now(); !now.Before(deadline) {
			deadline = now.Add(time.Second)
			s.conn.SetReadDeadline(deadline)
		}
		n, err := s.conn.Read(buf)
		if n > 0 {
			if serr := s.sendData(buf[:n]); serr != nil {
				if !s.isClosed() {
					s.client.logWarn("[Client] [Session 0x%08X] send failed: %v", s.sid, serr)
				}
				s.closeWithReason("tunnel send failed")
				return
			}
			s.mu.Lock()
			s.lastSent = time.Now()
			s.mu.Unlock()
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			s.closeWithReason("local conn read failed")
			return
		}
	}
}

// sendData assigns a sequence number, records the frame for retransmission and
// pushes it out. It blocks while the send window is full (backpressure).
func (s *clientSession) sendData(payload []byte) error {
	if s.isClosed() {
		return fmt.Errorf("session closed")
	}
	// A payload over UDPC_MAX_DATA cannot fit one frame: the AEAD seal would
	// return nil and this method would previously fail with an opaque
	// "failed to seal" AFTER a partial write had already been counted by the
	// caller. Fail fast with an actionable error instead; the CLI pump never
	// exceeds the budget (it reads at most UDPC_MAX_DATA), but library users
	// writing arbitrary-sized buffers hit this constantly.
	if len(payload) > UDPC_MAX_DATA {
		return fmt.Errorf("payload of %d bytes exceeds UDPC_MAX_DATA (%d): chunk writes to %d bytes or smaller",
			len(payload), UDPC_MAX_DATA, UDPC_MAX_DATA)
	}

	s.unackedMu.Lock()
	for len(s.unacked) >= s.client.cfg.SendWindow && atomic.LoadInt32(&s.closed) == 0 {
		s.unackedCond.Wait()
	}
	s.unackedMu.Unlock()
	if s.isClosed() {
		return fmt.Errorf("session closed")
	}

	seq := atomic.AddUint64(&s.sendSeq, 1) - 1
	outFrame := &UDPCFrame{
		Magic: s.client.magic, Version: UDPC_VERSION, Cmd: CMD_DATA,
		SessionID: s.sid, Seq: seq, Ack: s.currentAck(), Data: payload,
	}
	encoded := s.encodeFrame(outFrame)
	if len(encoded) == 0 {
		return fmt.Errorf("failed to seal DATA frame")
	}

	rto := s.rttEst.RTO()
	s.unackedMu.Lock()
	now := time.Now()
	s.unacked[seq] = &unackedPkt{
		wire:      encoded,
		firstSent: now,
		sentTime:  now,
		rto:       rto,
	}
	s.unackedMu.Unlock()

	// UDP write failures during route transitions are equivalent to packet
	// loss. The retained frame will be retried by retransmitLoop; returning an
	// error here would tear down the session before that machinery can help.
	if err := s.client.dialer.Send(encoded); err != nil {
		s.client.logWarn("[Client] [Session 0x%08X] initial DATA send deferred to retransmit loop: %v", s.sid, err)
	}
	return nil
}

func (s *clientSession) handleAck(ackSeq uint64) {
	s.unackedMu.Lock()
	// Cumulative, mirroring the server: everything up to ackSeq is delivered.
	if pkt, ok := s.unacked[ackSeq]; ok && pkt.retries == 0 {
		s.rttEst.Sample(time.Since(pkt.firstSent))
	}
	for seq := range s.unacked {
		if seq <= ackSeq {
			delete(s.unacked, seq)
		}
	}
	s.unackedMu.Unlock()
	if s.unackedCond != nil {
		s.unackedCond.Broadcast()
	}
}

func (s *clientSession) retransmitLoop() {
	ticker := time.NewTicker(clientRetransmitInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.closeChan:
			return
		case <-ticker.C:
			now := time.Now()
			s.unackedMu.Lock()
			for seq, pkt := range s.unacked {
				if now.Sub(pkt.sentTime) < pkt.rto {
					continue
				}
				pkt.retries++
				if pkt.retries > clientMaxRetries {
					s.client.logWarn("[Client] [Session 0x%08X] ⏱️ Seq %d abandoned after %d retries",
						s.sid, seq, pkt.retries)
					s.unackedMu.Unlock()
					s.closeWithReason("max retransmits exceeded")
					return
				}
				pkt.sentTime = now
				pkt.rto = minDuration(pkt.rto*3/2, 10*time.Second)
				_ = s.client.dialer.Send(pkt.wire)
			}
			s.unackedMu.Unlock()

			s.mu.Lock()
			idle := now.Sub(s.lastActive)
			s.mu.Unlock()
			if idle > clientRecvTimeout {
				s.client.logWarn("[Client] [Session 0x%08X] ⏱️ Idle timeout (%v)", s.sid, idle)
				s.closeWithReason("idle timeout")
				return
			}
		}
	}
}

func (s *clientSession) keepAliveLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.closeChan:
			return
		case <-ticker.C:
			s.mu.Lock()
			sinceSend := time.Since(s.lastSent)
			s.mu.Unlock()
			if sinceSend < clientKeepAliveInterval {
				continue
			}
			ping := &UDPCFrame{
				Magic: s.client.magic, Version: UDPC_VERSION, Cmd: CMD_PING,
				SessionID: s.sid, Ack: s.currentAck(),
			}
			s.sendControl(ping, s.client.dialer.Send)
			s.client.logDebug("[Client] [Session 0x%08X] keepalive PING sent (ack=%d)", s.sid, ping.Ack)
			s.mu.Lock()
			s.lastSent = time.Now()
			s.mu.Unlock()
		}
	}
}

// handleData delivers server data to the local application, buffering
// out-of-order frames and ACKing every frame it delivers.
func (s *clientSession) handleData(frame *UDPCFrame) bool {
	if frame.Seq == 0 {
		return true
	}

	// Several spread sockets have independent receive loops, so the complete
	// reorder/decrypt/deliver transition must be serialized. This prevents two
	// copies of the same expected sequence from both reaching the application.
	s.recvMu.Lock()
	defer s.recvMu.Unlock()

	payload := frame.Data

	expected := atomic.LoadUint64(&s.recvSeq)
	if frame.Seq != expected {
		if frame.Seq < expected {
			// Already delivered: the server is retransmitting because it lost
			// our ACK, so re-ACK instead of dropping it.
			s.sendACK(expected - 1)
			return true
		}
		if _, dup := s.recvQueue[frame.Seq]; dup {
			return true
		}
		if len(s.recvQueue) >= 512 {
			return false
		}
		s.recvQueue[frame.Seq] = append([]byte(nil), payload...)
		s.touch()
		return true
	}
	s.touch()

	type pending struct {
		seq     uint64
		payload []byte
	}
	run := []pending{{seq: expected, payload: payload}}
	next := expected + 1
	for {
		raw, ok := s.recvQueue[next]
		if !ok {
			break
		}
		delete(s.recvQueue, next)
		run = append(run, pending{seq: next, payload: raw})
		next++
	}

	delivered := uint64(0)
	for _, p := range run {
		if err := writeAll(s.conn, p.payload); err != nil {
			s.closeWithReason("application write failed")
			return true
		}
		delivered++
	}

	if delivered > 0 {
		atomic.StoreUint64(&s.recvSeq, expected+delivered)
		s.sendACK(expected + delivered - 1)
	}
	return true
}

// sendACK acknowledges everything up to ackSeq. Sent once per delivered frame
// and again whenever a duplicate shows up (its original ACK was lost), so the
// server can stop retransmitting. Control frames ride the pooled send buffer.
func (s *clientSession) sendACK(ackSeq uint64) {
	ack := &UDPCFrame{
		Magic: s.client.magic, Version: UDPC_VERSION, Cmd: CMD_ACK,
		SessionID: s.sid, Ack: ackSeq, WindowSize: 65535,
	}
	s.sendControl(ack, s.client.dialer.Send)
}

// sendControl seals a control frame into a POOLED buffer and
// hands it to send. The buffer returns to the pool before this call returns —
// send must consume the bytes synchronously. Returns false when the session
// lacks record protection or the packet-number space is exhausted.
func (s *clientSession) sendControl(f *UDPCFrame, send func([]byte) error) bool {
	f.PacketNo = atomic.AddUint64(&s.sendPacketNo, 1)
	if f.PacketNo == 0 || s.frameKeys == nil {
		return false
	}
	wire := sealControlFrameAEAD(f, s.frameKeys.Send)
	if len(wire) == 0 {
		return false
	}
	if err := send(wire); err != nil && !s.isClosed() {
		s.client.logWarn("[Client] [Session 0x%08X] send control failed: %v", s.sid, err)
	}
	putFireAndForgetBuf(wire)
	return true
}

func (s *clientSession) currentAck() uint64 {
	if next := atomic.LoadUint64(&s.recvSeq); next > 0 {
		return next - 1
	}
	return 0
}

func (s *clientSession) reackDuplicateData() {
	if ack := s.currentAck(); ack > 0 {
		s.sendACK(ack)
	}
}

// encodeFrame assigns a fresh packet number and seals the frame as a
// ChaCha20-Poly1305 record (PSK-derived or Noise transport key — same format,
// header as AAD, Poly1305 tag in the trailer).
func (s *clientSession) encodeFrame(f *UDPCFrame) []byte {
	f.PacketNo = atomic.AddUint64(&s.sendPacketNo, 1)
	if f.PacketNo == 0 {
		return nil
	}
	if s.frameKeys == nil {
		return nil
	}
	return SealFrameAEAD(f, s.frameKeys.Send, f.Data)
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
