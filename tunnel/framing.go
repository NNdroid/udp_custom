package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// Length-prefixed message framing — CLIENT-SIDE reference implementation.
//
// WHY THIS EXISTS
//
// The udp_custom tunnel is a BYTE STREAM for TCP targets:
//
//	client ──DATA(msg)──► server ──write──► tcp target
//	client ◄──DATA(chunk)── server ◄──read── tcp target
//
// The client→target direction preserves boundaries (each DATA frame becomes one
// TCP write), but the target→client direction does not: the server reads the
// target socket in UDPC_MAX_PKT-sized chunks and ships each chunk as its own
// DATA frame, so a reply may arrive split or coalesced regardless of how it was
// written. TCP itself never preserves write boundaries either, so there is
// nothing the server could do to fix this — framing is an application concern.
//
// (With `target = udp://` the tunnel DOES preserve datagram boundaries end to
// end: one datagram in, one DATA frame out. Framing is only needed for stream
// targets, or when the client application wants message semantics.)
//
// The wire format is deliberately boring: 4-byte big-endian length prefix
// followed by the payload. Clients that need message boundaries call
// EncodeMessage before sending and feed every received payload to a
// MessageAssembler.
//
// Like PortSelector and SpreadDialer this lives in the server repo so both ends
// stay in sync; the server never touches payloads and needs no changes.

const (
	// FrameHeaderSize is the length prefix of a framed message (uint32 BE).
	FrameHeaderSize = 4

	// MaxFramedMessage is the default largest payload a MessageAssembler will
	// accept (1 MiB). Cap this in your own application: without a limit a
	// hostile or buggy peer can make the assembler buffer unboundedly.
	MaxFramedMessage = 1 << 20
)

// ErrMessageTooLarge is returned when a framed message exceeds the assembler's
// limit. The assembler is then permanently broken (a desynced stream cannot be
// resynchronised safely), and every later Feed returns the same error until
// Reset is called.
var ErrMessageTooLarge = errors.New("framing: message exceeds maximum size")

// ErrAssemblerBroken is returned after a length error until Reset is called.
var ErrAssemblerBroken = errors.New("framing: assembler broken, call Reset()")

// EncodeMessage prefixes msg with its length. The returned slice is freshly
// allocated and safe to reuse the input afterwards.
func EncodeMessage(msg []byte) ([]byte, error) {
	if len(msg) > MaxFramedMessage {
		return nil, fmt.Errorf("%w (%d > %d)", ErrMessageTooLarge, len(msg), MaxFramedMessage)
	}
	out := make([]byte, FrameHeaderSize+len(msg))
	binary.BigEndian.PutUint32(out, uint32(len(msg)))
	copy(out[FrameHeaderSize:], msg)
	return out, nil
}

// EncodeMessages encodes several messages back to back — convenient when the
// client batches requests into a single DATA frame.
func EncodeMessages(msgs ...[]byte) ([]byte, error) {
	total := 0
	for _, m := range msgs {
		if len(m) > MaxFramedMessage {
			return nil, fmt.Errorf("%w (%d > %d)", ErrMessageTooLarge, len(m), MaxFramedMessage)
		}
		if len(m) > math.MaxInt-total-FrameHeaderSize {
			return nil, fmt.Errorf("framing: encoded batch too large")
		}
		total += FrameHeaderSize + len(m)
	}
	out := make([]byte, 0, total)
	for _, m := range msgs {
		var hdr [FrameHeaderSize]byte
		binary.BigEndian.PutUint32(hdr[:], uint32(len(m)))
		out = append(out, hdr[:]...)
		out = append(out, m...)
	}
	return out, nil
}

// MessageAssembler turns an arbitrary chunking of a framed byte stream back
// into whole messages. It is NOT safe for concurrent use — one assembler per
// connection/stream, driven from the client's single receive loop.
//
// Typical client loop:
//
//	asm := NewMessageAssembler(MaxFramedMessage)
//	for {
//	    _, payload := client.readData()      // one DATA frame, possibly a partial
//	    msgs, err := asm.Feed(payload)
//	    if err != nil { /* reset the session */ }
//	    for _, m := range msgs { handle(m) }
//	}
type MessageAssembler struct {
	buf        []byte
	maxPayload uint32
	broken     bool
}

// NewMessageAssembler returns an assembler that rejects messages larger than
// maxPayload. maxPayload <= 0 means MaxFramedMessage.
func NewMessageAssembler(maxPayload uint32) *MessageAssembler {
	if maxPayload <= 0 {
		maxPayload = MaxFramedMessage
	}
	return &MessageAssembler{maxPayload: maxPayload}
}

// Feed appends chunk to the pending stream and returns every message that is
// now complete (in order). It returns no messages (nil) when the chunk only
// contains a partial message.
func (a *MessageAssembler) Feed(chunk []byte) ([][]byte, error) {
	if a.broken {
		return nil, ErrAssemblerBroken
	}
	if len(chunk) > 0 {
		a.buf = append(a.buf, chunk...)
	}

	var msgs [][]byte
	for {
		if len(a.buf) < FrameHeaderSize {
			break
		}
		n := binary.BigEndian.Uint32(a.buf)
		if n > a.maxPayload {
			// A desynced stream cannot be resynchronised: refuse to keep
			// guessing at frame boundaries.
			a.broken = true
			a.buf = nil
			return nil, fmt.Errorf("%w (%d > %d)", ErrMessageTooLarge, n, a.maxPayload)
		}
		if len(a.buf) < FrameHeaderSize+int(n) {
			break
		}
		if msgs == nil {
			msgs = make([][]byte, 0, 4)
		}
		msg := make([]byte, n)
		copy(msg, a.buf[FrameHeaderSize:FrameHeaderSize+n])
		msgs = append(msgs, msg)
		a.buf = a.buf[FrameHeaderSize+n:]
	}

	// Reclaim the consumed prefix so a long-lived stream does not keep growing
	// its backing array.
	if len(a.buf) == 0 {
		// Retain modest buffers so a long-lived stream does not allocate again
		// for every complete frame. Oversized backing arrays are still dropped.
		if cap(a.buf) > 64*1024 {
			a.buf = nil
		} else {
			a.buf = a.buf[:0]
		}
	} else if cap(a.buf) > 64*1024 && len(a.buf)*4 < cap(a.buf) {
		compact := make([]byte, len(a.buf))
		copy(compact, a.buf)
		a.buf = compact
	}
	return msgs, nil
}

// Pending returns the number of bytes buffered for an incomplete message.
// Useful for health checks / detecting a stalled peer.
func (a *MessageAssembler) Pending() int { return len(a.buf) }

// Reset clears the buffer and any broken state (call it after an error, or when
// the underlying stream is restarted).
func (a *MessageAssembler) Reset() {
	a.buf = nil
	a.broken = false
}
