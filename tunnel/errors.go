package tunnel

import "errors"

// Sentinel errors for the public API. Embedders should test with errors.Is,
// not string comparison — messages may gain context over time.
var (
	// ErrClosed is returned by DialTunnel after Client.Close. Post-Close I/O
	// on tunnel connections surfaces net.ErrClosed.
	ErrClosed = errors.New("tunnel: closed")

	// ErrHandshakeTimeout means the server never answered the SYN. Usual
	// causes: unreachable server, mismatched PSK, or a requested target the
	// server's allowed_targets filter silently dropped.
	ErrHandshakeTimeout = errors.New("tunnel: handshake timed out")

	// ErrNonceCollision is returned when two concurrent handshakes drew the
	// same random client nonce (astronomically unlikely; just retry).
	ErrNonceCollision = errors.New("tunnel: client nonce collision")

	// ErrNoRoute is returned when the spread dialer has no usable socket to
	// the server.
	ErrNoRoute = errors.New("tunnel: no usable socket to the server")
)

// ErrTunnelClosed wraps the reason a live tunnel session ended (peer FIN,
// idle timeout, retransmit exhaustion, target failure). Returned by
// TunnelSession.Err after Done is closed; matchable via errors.Is.
var ErrTunnelClosed = errors.New("tunnel: session ended")
