package tunnel

import (
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// chunkPipeBuffer is the per-direction byte budget of one chunkPipe end. It
// decouples the delivery pump from the application's read pattern: net.Pipe
// has no buffer at all, so every ~1.4 KB frame cost two synchronous goroutine
// handoffs, which pinned loopback throughput at a fraction of what the rest
// of the pipeline sustains. 256 KB absorbs a full Read batch without adding
// visible latency for interactive traffic (a lone frame is still readable
// immediately).
const chunkPipeBuffer = 256 * 1024

// chunkPipeChunk caps one queued piece: an application Write larger than the
// free buffer space is split into pieces of at most this size and queued
// piece by piece, blocking when the direction is full.
const chunkPipeChunk = 64 * 1024

// chunkPipe is a buffered, bidirectional in-memory conn pair with net.Pipe's
// observable semantics: Close on EITHER end fails BOTH ends (reads see
// io.EOF, writes see io.ErrClosedPipe), Read/Write honor deadlines, and
// reads may return fewer bytes than asked.
type chunkPipe struct {
	mu     sync.Mutex
	closed bool

	// down carries session->application data (delivery writes), up carries
	// application->session data (the uplink pump reads). Bytes is the queued
	// total; the waiters of a direction are its reader (data) and its writer
	// (space), so each signal channel has exactly one waiting class.
	down, up            chunkDir
	downData, downSpace chan struct{}
	upData, upSpace     chan struct{}
}

type chunkDir struct {
	chunks [][]byte
	bytes  int
}

func newChunkPipe() (app, session net.Conn) {
	p := &chunkPipe{
		downData:  make(chan struct{}, 1),
		downSpace: make(chan struct{}, 1),
		upData:    make(chan struct{}, 1),
		upSpace:   make(chan struct{}, 1),
	}
	return &chunkPipeEnd{p: p, appSide: true}, &chunkPipeEnd{p: p}
}

// signal wakes every waiter after any state change. Cap-1 channels make this
// a broadcast: waiters re-check state under the lock after waking.
func (p *chunkPipe) signal() {
	select {
	case p.downData <- struct{}{}:
	default:
	}
	select {
	case p.downSpace <- struct{}{}:
	default:
	}
	select {
	case p.upData <- struct{}{}:
	default:
	}
	select {
	case p.upSpace <- struct{}{}:
	default:
	}
}

func (p *chunkPipe) push(q *chunkDir, b []byte) int {
	piece := chunkPipeChunk
	if len(b) < piece {
		piece = len(b)
	}
	chunk := append([]byte(nil), b[:piece]...)
	q.chunks = append(q.chunks, chunk)
	q.bytes += len(chunk)
	return piece
}

// take drains queued bytes into b and reports how many landed.
func (q *chunkDir) take(b []byte) int {
	n := 0
	for n < len(b) && len(q.chunks) > 0 {
		copied := copy(b[n:], q.chunks[0])
		n += copied
		// The byte accounting must follow the CONSUMED amount, not the chunk
		// boundary: a partially consumed head chunk used to leak its leftover
		// bytes into q.bytes forever, which inflated the buffer occupancy
		// until every writer saw a permanently full queue and blocked.
		q.bytes -= copied
		if copied < len(q.chunks[0]) {
			q.chunks[0] = q.chunks[0][copied:]
			break
		}
		q.chunks[0] = nil
		q.chunks = q.chunks[1:]
	}
	if n > 0 && len(q.chunks) == 0 {
		q.chunks = nil
	}
	return n
}

// chunkPipeEnd is one net.Conn end of a chunkPipe. The deadline fields are
// guarded by the shared chunkPipe mutex.
type chunkPipeEnd struct {
	p       *chunkPipe
	appSide bool // app side reads `down` and writes `up`

	readDeadline  time.Time
	writeDeadline time.Time
}

func (e *chunkPipeEnd) queues() (readQ, writeQ *chunkDir) {
	if e.appSide {
		return &e.p.down, &e.p.up
	}
	return &e.p.up, &e.p.down
}

func (e *chunkPipeEnd) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	p := e.p
	for {
		p.mu.Lock()
		// Drained data wins over a concurrent close or an expired deadline:
		// bytes already queued were accepted from a successful Write, and a
		// reader that gets to them must not lose them (bufio-style drain on
		// close). Only an EMPTY queue reports the terminal states.
		readQ, _ := e.queues()
		if n := readQ.take(b); n > 0 {
			p.mu.Unlock()
			p.signal()
			return n, nil
		}
		if p.closed {
			p.mu.Unlock()
			return 0, io.EOF
		}
		if err := expired(e.readDeadline); err != nil {
			p.mu.Unlock()
			return 0, err
		}
		deadline, wake := e.readDeadline, p.downData
		if !e.appSide {
			wake = p.upData
		}
		p.mu.Unlock()
		if err := sleepUntil(wake, deadline); err != nil {
			return 0, err
		}
	}
}

func (e *chunkPipeEnd) Write(b []byte) (int, error) {
	p := e.p
	written := 0
	for written < len(b) {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return written, io.ErrClosedPipe
		}
		if err := expired(e.writeDeadline); err != nil {
			p.mu.Unlock()
			return written, err
		}
		_, writeQ := e.queues()
		if writeQ.bytes < chunkPipeBuffer {
			written += p.push(writeQ, b[written:])
			p.mu.Unlock()
			p.signal()
			continue
		}
		// Wait for space in the queue this end writes to: the app side writes
		// `up`, the session side writes `down`.
		deadline, wake := e.writeDeadline, p.upSpace
		if !e.appSide {
			wake = p.downSpace
		}
		p.mu.Unlock()
		if err := sleepUntil(wake, deadline); err != nil {
			return written, err
		}
	}
	return written, nil
}

func (e *chunkPipeEnd) Close() error {
	p := e.p
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.mu.Unlock()
	p.signal()
	return nil
}

func (e *chunkPipeEnd) LocalAddr() net.Addr  { return pipeAddr{} }
func (e *chunkPipeEnd) RemoteAddr() net.Addr { return pipeAddr{} }

func (e *chunkPipeEnd) SetDeadline(t time.Time) error {
	p := e.p
	p.mu.Lock()
	e.readDeadline = t
	e.writeDeadline = t
	p.mu.Unlock()
	p.signal()
	return nil
}

func (e *chunkPipeEnd) SetReadDeadline(t time.Time) error {
	p := e.p
	p.mu.Lock()
	e.readDeadline = t
	p.mu.Unlock()
	p.signal()
	return nil
}

func (e *chunkPipeEnd) SetWriteDeadline(t time.Time) error {
	p := e.p
	p.mu.Lock()
	e.writeDeadline = t
	p.mu.Unlock()
	p.signal()
	return nil
}

// expired reports the timeout error for a deadline already in the past, in
// the same shape net.Conn callers expect (net.Error with Timeout() true).
func expired(dl time.Time) error {
	if !dl.IsZero() && !time.Now().Before(dl) {
		return os.ErrDeadlineExceeded
	}
	return nil
}

// sleepUntil waits for a state change or a deadline. A zero deadline waits
// indefinitely; a past deadline returns the timeout error immediately.
func sleepUntil(wake <-chan struct{}, deadline time.Time) error {
	if !deadline.IsZero() {
		d := time.Until(deadline)
		if d <= 0 {
			return os.ErrDeadlineExceeded
		}
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-wake:
			return nil
		case <-timer.C:
			return os.ErrDeadlineExceeded
		}
	}
	<-wake
	return nil
}

var (
	_ net.Conn = (*chunkPipeEnd)(nil)
)
