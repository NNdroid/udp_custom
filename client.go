package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
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
// Seq-derived AEAD nonces that make retransmission and reordering safe.

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
	// Target is informational: the backend the SERVER forwards to. The server
	// decides the forwarding target (its own `target` config), the client
	// cannot choose it — the field is kept so a client config documents what
	// the tunnel is for.
	Target    string
	Passwords []string
	Magic     uint32
	// ServerPub is the server's Noise static public key. Zero = no encryption.
	ServerPub  [32]byte
	LogLevel   string
	Sockets    int // local sockets for n:n spreading (<=0 or 1 = single socket)
	Paths      int // distinct remote ports to randomly pick from the range (<=0 = spread over the whole range per packet)
	SendWindow int // frames in flight before backpressure (0 = 256)
}

// Client fronts local applications and tunnels them to one udp_custom server.
type Client struct {
	cfg      ClientConfig
	magic    uint32
	logLevel int

	dialer *SpreadDialer

	sessions sync.Map // sessionID -> *clientSession

	// Handshakes are serialised: a handshake ACK carries only the new
	// SessionID, not the SYN nonce, so concurrent handshakes could not be told
	// apart. They are fast (one round trip), so this costs nothing.
	//
	// hsMu is held for the whole handshake; pendingAck is therefore guarded by
	// its own mutex — the receive loop must be able to deliver the ACK while a
	// handshake is waiting for it (sharing hsMu would self-deadlock).
	hsMu       sync.Mutex
	ackMu      sync.Mutex
	pendingAck chan *UDPCFrame

	closeOnce sync.Once
	closeChan chan struct{}
	closed    int32
	wg        sync.WaitGroup
}

func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.ListenAddr == "" {
		return nil, fmt.Errorf("client: 'listen' is required (local port for applications)")
	}
	if cfg.ServerAddr == "" {
		return nil, fmt.Errorf("client: 'server' is required (udp_custom server address)")
	}
	if len(cfg.Passwords) == 0 {
		return nil, fmt.Errorf("client: at least one password (PSK) is required")
	}
	if cfg.Magic == 0 {
		cfg.Magic = UDPC_MAGIC_DEFAULT
	}
	if cfg.SendWindow <= 0 {
		cfg.SendWindow = defaultSendWindow
	}

	dialer, err := NewSpreadDialer(cfg.ServerAddr, cfg.Sockets, cfg.Paths)
	if err != nil {
		return nil, err
	}
	return &Client{
		cfg:       cfg,
		magic:     cfg.Magic,
		logLevel:  parseLogLevel(cfg.LogLevel),
		dialer:    dialer,
		closeChan: make(chan struct{}),
	}, nil
}

func (c *Client) logDebug(format string, args ...any) {
	if c.logLevel <= LogLevelDebug {
		fmt.Printf("[DEBUG] "+format+"\n", args...)
	}
}
func (c *Client) logInfo(format string, args ...any) {
	if c.logLevel <= LogLevelInfo {
		fmt.Printf("[INFO] "+format+"\n", args...)
	}
}
func (c *Client) logWarn(format string, args ...any) {
	if c.logLevel <= LogLevelWarn {
		fmt.Printf("[WARN] "+format+"\n", args...)
	}
}
func (c *Client) logError(format string, args ...any) {
	if c.logLevel <= LogLevelError {
		fmt.Printf("[ERROR] "+format+"\n", args...)
	}
}

// Start blocks: it serves local applications until Close is called.
func (c *Client) Start() error {
	ln, err := net.Listen("tcp", c.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("client listen %s: %w", c.cfg.ListenAddr, err)
	}

	// One receive loop per local socket: the server replies to whichever source
	// port it last saw, so frames for any session may land on any socket.
	for _, conn := range c.dialer.Conns() {
		c.wg.Add(1)
		go func(conn *net.UDPConn) {
			defer c.wg.Done()
			c.recvLoop(conn)
		}(conn)
	}

	c.logInfo("[Client] 🚀 udp_custom client listening on %s", ln.Addr())
	portDesc := fmt.Sprintf("%d port(s) in range", c.dialer.PortRange().Total())
	if p := c.dialer.Paths(); p > 0 {
		portDesc = fmt.Sprintf("%d chosen port(s) from range", p)
	}
	c.logInfo("[Client] 🔗 Tunnel to server %s (spread: %d socket(s) x %s)",
		c.cfg.ServerAddr, c.dialer.Len(), portDesc)
	if c.cfg.Target != "" {
		c.logInfo("[Client] 🎯 Backend target (server-side config): %s", c.cfg.Target)
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
			c.serveConn(conn)
		}(conn)
	}
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
	})
}

// --- receive path -------------------------------------------------------------

func (c *Client) recvLoop(conn *net.UDPConn) {
	buf := make([]byte, UDPC_MAX_PKT)
	for {
		select {
		case <-c.closeChan:
			return
		default:
		}
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if atomic.LoadInt32(&c.closed) == 1 {
				return
			}
			c.logWarn("[Client] recv error: %v", err)
			return
		}
		if !c.dialer.acceptsRemote(remoteAddr) {
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
		c.ackMu.Lock()
		ch := c.pendingAck
		c.ackMu.Unlock()
		if ch != nil {
			owned := *frame
			owned.Data = append([]byte(nil), frame.Data...)
			select {
			case ch <- &owned:
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
	switch frame.Cmd {
	case CMD_DATA:
		sess.handleData(frame)
	case CMD_ACK:
		sess.handleAck(frame.Ack)
	case CMD_PONG:
		sess.touch()
	case CMD_FIN:
		c.logInfo("[Client] [Session 0x%08X] Server sent FIN", sess.sid)
		sess.close()
	}
}

// --- handshake -----------------------------------------------------------------

func (c *Client) serveConn(conn net.Conn) {
	sid, noiseSess, err := c.handshake()
	if err != nil {
		c.logError("[Client] ❌ Handshake failed for %s: %v", conn.RemoteAddr(), err)
		conn.Close()
		return
	}

	sess := &clientSession{
		client:     c,
		sid:        sid,
		conn:       conn,
		noise:      noiseSess,
		sendSeq:    1,
		recvSeq:    1,
		recvQueue:  make(map[uint32][]byte),
		unacked:    make(map[uint32]*unackedPkt),
		lastActive: time.Now(),
		lastSent:   time.Now(),
		closeChan:  make(chan struct{}),
		rttEst:     newRTTEstimator(200*time.Millisecond, 200*time.Millisecond, 10*time.Second),
	}
	sess.unackedCond = sync.NewCond(&sess.unackedMu)
	c.sessions.Store(sid, sess)
	c.logInfo("[Client] [Session 0x%08X] ✅ Tunnel established for %s", sid, conn.RemoteAddr())

	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); sess.localToRemote() }()
	go func() { defer wg.Done(); sess.retransmitLoop() }()
	go func() { defer wg.Done(); sess.keepAliveLoop() }()
	wg.Wait()

	c.sessions.Delete(sid)
	conn.Close()
	c.logInfo("[Client] [Session 0x%08X] 🛑 Closed", sid)
}

// handshake sends the SYN (retransmitting until the ACK arrives) and returns
// the new SessionID. Retransmissions reuse the SAME nonce, which the server's
// idempotency cache answers with the SAME session — so a lost ACK never
// produces a duplicate session.
func (c *Client) handshake() (uint32, *NoiseSession, error) {
	c.hsMu.Lock()
	defer c.hsMu.Unlock()

	var nk *ClientNK
	var msg1 []byte
	var zero [32]byte
	encrypted := c.cfg.ServerPub != zero
	if encrypted {
		var err error
		nk, err = NewClientNK(c.cfg.ServerPub)
		if err != nil {
			return 0, nil, err
		}
		msg1, err = nk.Message1()
		if err != nil {
			return 0, nil, err
		}
	}

	payload := make([]byte, 56+len(msg1))
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return 0, nil, fmt.Errorf("nonce: %w", err)
	}
	now := time.Now().Unix()
	copy(payload[0:16], nonce[:])
	binary.BigEndian.PutUint64(payload[16:24], uint64(now))
	copy(payload[24:56], ComputeAuthHMAC(nonce[:], c.cfg.Passwords[0], now))
	copy(payload[56:], msg1)

	syn := (&UDPCFrame{
		Magic: c.magic, Version: UDPC_VERSION,
		Cmd: CMD_HANDSHAKE_SYN, Data: payload,
	}).Encode()

	ch := make(chan *UDPCFrame, 4)
	c.ackMu.Lock()
	c.pendingAck = ch
	c.ackMu.Unlock()
	defer func() {
		c.ackMu.Lock()
		c.pendingAck = nil
		c.ackMu.Unlock()
	}()

	for attempt := 1; attempt <= clientMaxHandshakeAttempts; attempt++ {
		if err := c.dialer.SendAt(0, syn); err != nil {
			return 0, nil, fmt.Errorf("send SYN: %w", err)
		}
		timeout := clientHandshakeBackoff * time.Duration(attempt)
		select {
		case ack := <-ch:
			if ack.SessionID == 0 {
				return 0, nil, fmt.Errorf("server returned a zero SessionID")
			}
			if !encrypted {
				return ack.SessionID, nil, nil
			}
			// ACK Data carries ONLY the Noise msg2 (the server never advertises
			// ports; the client chooses its own destination ports from the
			// configured range). Use it as-is.
			msg2 := ack.Data
			sess, err := nk.Finish(msg2)
			if err != nil {
				return 0, nil, fmt.Errorf("noise finish: %w", err)
			}
			c.logInfo("[Client] 🔐 Noise_NK established (channel binding %x…)", sess.HandshakeHash[:4])
			return ack.SessionID, sess, nil
		case <-time.After(timeout):
			c.logDebug("[Client] Handshake attempt %d timed out, retrying", attempt)
		case <-c.closeChan:
			return 0, nil, fmt.Errorf("client closed")
		}
	}
	return 0, nil, fmt.Errorf("no handshake ACK after %d attempts", clientMaxHandshakeAttempts)
}

// --- session -------------------------------------------------------------------

type clientSession struct {
	client *Client
	sid    uint32
	conn   net.Conn // local application connection
	noise  *NoiseSession

	sendSeq uint32
	recvSeq uint32

	recvQueue map[uint32][]byte
	recvMu    sync.Mutex

	unacked     map[uint32]*unackedPkt
	unackedMu   sync.Mutex
	unackedCond *sync.Cond

	rttEst *rttEstimator

	lastActive time.Time
	lastSent   time.Time
	mu         sync.Mutex

	closeOnce sync.Once
	closeChan chan struct{}
	closed    int32
}

func (s *clientSession) touch() {
	s.mu.Lock()
	s.lastActive = time.Now()
	s.mu.Unlock()
}

func (s *clientSession) isClosed() bool { return atomic.LoadInt32(&s.closed) == 1 }

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
			fin := (&UDPCFrame{
				Magic: s.client.magic, Version: UDPC_VERSION,
				Cmd: CMD_FIN, SessionID: s.sid,
			}).Encode()
			_ = s.client.dialer.Send(fin)
			s.conn.Close()
		}
	})
}

// localToRemote streams the local application's bytes into the tunnel.
func (s *clientSession) localToRemote() {
	// A short read deadline keeps a half-closed connection from pinning the
	// session forever; ERRATIME is the marker for "no data right now".
	buf := make([]byte, UDPC_MAX_DATA-16)
	for {
		if s.isClosed() {
			return
		}
		s.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, err := s.conn.Read(buf)
		if n > 0 {
			if serr := s.sendData(buf[:n]); serr != nil {
				if !s.isClosed() {
					s.client.logWarn("[Client] [Session 0x%08X] send failed: %v", s.sid, serr)
				}
				s.close()
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
			s.close()
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

	s.unackedMu.Lock()
	for len(s.unacked) >= s.client.cfg.SendWindow && atomic.LoadInt32(&s.closed) == 0 {
		s.unackedCond.Wait()
	}
	s.unackedMu.Unlock()
	if s.isClosed() {
		return fmt.Errorf("session closed")
	}

	seq := atomic.AddUint32(&s.sendSeq, 1) - 1
	data := payload
	if s.noise != nil {
		// Nonce = Seq: retransmissions reuse the same ciphertext AND nonce,
		// which is exactly what the server expects.
		data = s.noise.SendCipher.Encrypt(seq, payload)
	}
	outFrame := &UDPCFrame{
		Magic: s.client.magic, Version: UDPC_VERSION, Cmd: CMD_DATA,
		SessionID: s.sid, Seq: seq, Data: data,
	}
	encoded := outFrame.Encode()

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

	return s.client.dialer.Send(encoded)
}

func (s *clientSession) handleAck(ackSeq uint32) {
	s.unackedMu.Lock()
	// Cumulative, mirroring the server: everything up to ackSeq is delivered.
	if pkt, ok := s.unacked[ackSeq]; ok && pkt.retries == 0 {
		s.rttEst.Sample(time.Since(pkt.firstSent))
	}
	for seq := range s.unacked {
		if int32(seq-ackSeq) <= 0 {
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
					s.close()
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
				s.close()
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
			var ackVal uint32
			if rSeq := atomic.LoadUint32(&s.recvSeq); rSeq > 0 {
				ackVal = rSeq - 1
			}
			ping := (&UDPCFrame{
				Magic: s.client.magic, Version: UDPC_VERSION, Cmd: CMD_PING,
				SessionID: s.sid, Ack: ackVal,
			}).Encode()
			if err := s.client.dialer.Send(ping); err != nil && !s.isClosed() {
				s.client.logWarn("[Client] [Session 0x%08X] keepalive failed: %v", s.sid, err)
			}
			s.mu.Lock()
			s.lastSent = time.Now()
			s.mu.Unlock()
		}
	}
}

// handleData delivers server data to the local application, buffering
// out-of-order frames and ACKing every frame it delivers.
func (s *clientSession) handleData(frame *UDPCFrame) {
	if frame.Seq == 0 {
		return
	}

	// Several spread sockets have independent receive loops, so the complete
	// reorder/decrypt/deliver transition must be serialized. This prevents two
	// copies of the same expected sequence from both reaching the application.
	s.recvMu.Lock()
	defer s.recvMu.Unlock()

	payload := frame.Data
	if s.noise != nil {
		plain, err := s.noise.RecvCipher.Decrypt(frame.Seq, frame.Data)
		if err != nil {
			s.client.logWarn("[Client] [Session 0x%08X] ⚠️ Decrypt failed for Seq %d: %v", s.sid, frame.Seq, err)
			return
		}
		payload = plain
	}
	s.touch()

	expected := atomic.LoadUint32(&s.recvSeq)
	if frame.Seq != expected {
		if int32(frame.Seq-expected) < 0 {
			// Already delivered: the server is retransmitting because it lost
			// our ACK, so re-ACK instead of dropping it.
			s.sendACK(frame.Seq)
			return
		}
		if _, dup := s.recvQueue[frame.Seq]; !dup && len(s.recvQueue) < 512 {
			s.recvQueue[frame.Seq] = append([]byte(nil), payload...)
		}
		return
	}

	type pending struct {
		seq     uint32
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

	delivered := uint32(0)
	for _, p := range run {
		if err := writeAll(s.conn, p.payload); err != nil {
			s.close()
			return
		}
		delivered++
	}

	if delivered > 0 {
		atomic.StoreUint32(&s.recvSeq, expected+delivered)
		s.sendACK(expected + delivered - 1)
	}
}

// sendACK acknowledges everything up to ackSeq. Sent once per delivered frame
// and again whenever a duplicate shows up (its original ACK was lost), so the
// server can stop retransmitting.
func (s *clientSession) sendACK(ackSeq uint32) {
	ack := (&UDPCFrame{
		Magic: s.client.magic, Version: UDPC_VERSION, Cmd: CMD_ACK,
		SessionID: s.sid, Ack: ackSeq, WindowSize: 65535,
	}).Encode()
	if err := s.client.dialer.Send(ack); err != nil && !s.isClosed() {
		s.client.logWarn("[Client] [Session 0x%08X] send ACK failed: %v", s.sid, err)
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
