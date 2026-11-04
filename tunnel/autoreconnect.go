package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// AutoReconnect wraps one tunnel connection with transparent re-establishment:
// the first tunnel is dialed lazily on first use; when a Read or Write fails
// (peer gone, server restart, idle timeout — a clean server-side close
// surfaces as io.EOF), the wrapper drops the session and the NEXT operation
// dials a fresh one.
//
// Semantics:
//   - The failing operation surfaces its error ONCE; the following operation
//     runs on a fresh tunnel. Byte-stream continuity is NOT preserved across
//     reconnects (the old session's target is gone) — callers must tolerate a
//     torn stream exactly as with a flaky TCP link. Request/response protocols
//     (HTTP, DNS) fit naturally: the failed request is retried at that layer.
//   - Reconnects are NOT bound by the original DialTunnel context.
//   - A dial that FAILED (including the handshake inside it) throttles the
//     next dial with an exponential backoff, capped: a server that is
//     deliberately refusing sessions (policy kick, allowed_targets narrowed)
//     must not be hammered by a redial loop. Operations arriving during the
//     throttle window fail fast with the dial error instead of queueing.
//     A successful dial resets the backoff.
//   - Every successful dial invokes DialOptions.OnGranted again, so embedders
//     can log target changes.
//   - Close stops the wrapper; later operations return ErrClosed.
type AutoReconnect struct {
	client *Client
	opts   DialOptions
	ctx    context.Context
	cancel context.CancelFunc

	dialMu sync.Mutex
	mu     sync.Mutex
	conn   net.Conn
	closed bool

	needsRestart      bool
	reconnectAttempts uint64
	restarts          uint64
	readDeadline      time.Time
	writeDeadline     time.Time

	// Dial-throttle bookkeeping. nextDialAt zero means no throttle is active.
	dialFails   uint64
	nextDialAt  time.Time
	lastDialErr error
}

// reconnectBackoffBase is the wait after the first failed full dial (the
// handshake inside it already spends its own retry budget); each successive
// failure doubles it up to reconnectBackoffMax.
const (
	reconnectBackoffBase = 2 * time.Second
	reconnectBackoffMax  = 30 * time.Second
)

// NewAutoReconnect returns a wrapper around client.DialTunnel with automatic
// re-establishment. Dial options are reused verbatim on every attempt; the
// optional onGranted hook observes each established tunnel's granted target.
func NewAutoReconnect(client *Client, opts DialOptions, onGranted func(granted string)) *AutoReconnect {
	if onGranted != nil {
		original := opts.OnGranted
		opts.OnGranted = func(granted string) {
			if original != nil {
				original(granted)
			}
			onGranted(granted)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &AutoReconnect{client: client, opts: opts, ctx: ctx, cancel: cancel}
}

// ensure returns the live tunnel, dialing a fresh one when needed.
func (a *AutoReconnect) ensure() (net.Conn, error) {
	a.dialMu.Lock()
	defer a.dialMu.Unlock()

	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil, ErrClosed
	}
	if a.conn != nil {
		conn := a.conn
		a.mu.Unlock()
		return conn, nil
	}
	// Throttle after a failed dial: a server that keeps refusing sessions must
	// not face a redial loop at the caller's op rate. Surfacing the error
	// immediately (rather than sleeping under dialMu) keeps unrelated callers
	// responsive; the app retries at its own layer.
	if !a.nextDialAt.IsZero() {
		if wait := time.Until(a.nextDialAt); wait > 0 {
			err := fmt.Errorf("reconnect throttled for %v after a failed dial: %w", wait.Round(time.Millisecond), a.lastDialErr)
			a.mu.Unlock()
			return nil, err
		}
	}
	isReconnect := a.needsRestart
	if isReconnect {
		a.reconnectAttempts++
		a.client.logWarn("[AutoReconnect] 🔁 session lost; dialing replacement (attempt %d)", a.reconnectAttempts)
		a.client.events.emit(ClientEvent{
			Kind:    Reconnecting,
			Attempt: int(a.reconnectAttempts),
			Detail:  "dialing a replacement session",
		})
	} else {
		a.client.logDebug("[AutoReconnect] 🔌 dialing first tunnel session")
	}
	a.mu.Unlock()

	appConn, _, err := a.client.dialSession(a.ctx, a.opts)
	if err != nil {
		a.mu.Lock()
		a.dialFails++
		backoff := reconnectBackoffBase << min(a.dialFails-1, 4)
		if backoff > reconnectBackoffMax {
			backoff = reconnectBackoffMax
		}
		a.nextDialAt = time.Now().Add(backoff)
		a.lastDialErr = err
		a.mu.Unlock()
		a.client.logWarn("[AutoReconnect] ❌ dial failed: %v (throttling redials for %v)", err, backoff)
		return nil, err
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		_ = appConn.Close()
		return nil, ErrClosed
	}
	if !a.readDeadline.IsZero() {
		_ = appConn.SetReadDeadline(a.readDeadline)
	}
	if !a.writeDeadline.IsZero() {
		_ = appConn.SetWriteDeadline(a.writeDeadline)
	}
	a.conn = appConn
	a.dialFails = 0
	a.nextDialAt = time.Time{}
	a.lastDialErr = nil
	if isReconnect {
		a.restarts++
		a.needsRestart = false
		a.reconnectAttempts = 0
		a.client.logInfo("[AutoReconnect] ✅ tunnel re-established")
	}
	return a.conn, nil
}

// drop discards the current tunnel after an IO failure so the next operation
// dials a replacement. A clean server-side close (io.EOF) is reconnection-
// worthy too — a server RESTART is exactly that shape — but it is logged as
// its own kind so operators can tell a deliberate kick from a transport fault.
func (a *AutoReconnect) drop(conn net.Conn, cause error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.conn == conn {
		a.conn = nil
		a.needsRestart = true
		if errors.Is(cause, io.EOF) {
			a.client.logWarn("[AutoReconnect] ⚠️ server closed the session (EOF); the next operation re-dials")
		} else {
			a.client.logWarn("[AutoReconnect] ⚠️ session lost (%v); the next operation re-dials", cause)
		}
	}
	conn.Close()
}

// RestartCount reports how many times the tunnel has been re-established
// (excludes the initial dial).
func (a *AutoReconnect) RestartCount() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.restarts
}

// --- net.Conn surface: every op repairs the session transparently ------------

func (a *AutoReconnect) Read(b []byte) (int, error) {
	conn, err := a.ensure()
	if err != nil {
		return 0, err
	}
	n, rerr := conn.Read(b)
	if rerr != nil {
		a.drop(conn, rerr)
	}
	return n, rerr
}

func (a *AutoReconnect) Write(b []byte) (int, error) {
	conn, err := a.ensure()
	if err != nil {
		return 0, err
	}
	n, werr := conn.Write(b)
	if werr != nil {
		a.drop(conn, werr)
	}
	return n, werr
}

func (a *AutoReconnect) Close() error {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil
	}
	a.closed = true
	a.cancel()
	conn := a.conn
	a.conn = nil
	a.mu.Unlock()
	if conn != nil {
		return conn.Close()
	}
	return nil
}

func (a *AutoReconnect) LocalAddr() net.Addr {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.conn != nil {
		return a.conn.LocalAddr()
	}
	return pipeAddr{}
}

func (a *AutoReconnect) RemoteAddr() net.Addr {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.conn != nil {
		return a.conn.RemoteAddr()
	}
	return pipeAddr{}
}

func (a *AutoReconnect) SetDeadline(t time.Time) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.readDeadline = t
	a.writeDeadline = t
	if a.conn != nil {
		return a.conn.SetDeadline(t)
	}
	return nil
}

func (a *AutoReconnect) SetReadDeadline(t time.Time) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.readDeadline = t
	if a.conn != nil {
		return a.conn.SetReadDeadline(t)
	}
	return nil
}

func (a *AutoReconnect) SetWriteDeadline(t time.Time) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.writeDeadline = t
	if a.conn != nil {
		return a.conn.SetWriteDeadline(t)
	}
	return nil
}

// pipeAddr is a placeholder address before the first tunnel is established.
type pipeAddr struct{}

func (pipeAddr) Network() string { return "udpc" }
func (pipeAddr) String() string  { return "udpc-tunnel" }

var _ net.Conn = (*AutoReconnect)(nil)

// dialSession establishes one tunnel session and returns its local end —
// DialTunnel's per-call body, split out so AutoReconnect can re-dial.
func (c *Client) dialSession(ctx context.Context, opts DialOptions) (net.Conn, *clientSession, error) {
	appConn, sessionConn := net.Pipe()
	// The recv loops must be up before the SYN flies: the handshake ACK is
	// consumed by them (startOnce makes this idempotent with DialTunnel).
	c.startOnce.Do(c.startRecvLoops)
	sess, err := c.establish(ctx, opts.Target, sessionConn)
	if err != nil {
		appConn.Close()
		return nil, nil, err
	}
	if opts.OnGranted != nil {
		opts.OnGranted(sess.granted)
	}
	return appConn, sess, nil
}
