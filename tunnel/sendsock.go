package tunnel

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
)

// sendSockPool caches UDP sockets bound to specific local ports so the server
// can reply with a SOURCE port that matches the DESTINATION port the client
// originally sent to.
//
// Background: when a client spreads every datagram across a destination port
// range and a firewall DNAT folds the whole range onto one internal port, the
// server receives everything on that single port and cannot tell the packets
// apart. If it replies from that same socket the reply's source port is wrong
// (it is the internal port, not the port the client addressed), and a client
// behind symmetric NAT / CGNAT drops the reply outright.
//
// A UDP socket's source port is fixed at bind time, so to emit a specific source
// port we need a socket bound to that port. This pool provides exactly that.
// It is populated lazily (only ports clients actually use are bound) and bounded
// by an LRU so a hostile or misconfigured client cannot exhaust file descriptors.
//
// These sockets are send-only in practice: the DNAT rule rewrites inbound
// packets to the internal port before local delivery, so nothing is ever
// delivered to them.
//
// Concurrency design (reworked after a review found two defects in the old
// mutex+list LRU):
//
//   - Lock-held bind: the old Get() ran net.ListenUDP while holding one global
//     mutex, so every reply of every session serialized behind a syscall. The
//     cache-hit path is now LOCK-FREE (sync.Map load + atomic recency stamp)
//     and the bind happens on a separate cold-path mutex (bindMu) that is
//     never touched by hits; concurrent first-binders for the same port are
//     serialized there with a double-check instead of racing EADDRINUSE.
//
//   - Use-after-close: the old eviction could Close a socket another goroutine
//     had just fetched and was writing through; the write then fell back to
//     the main socket, i.e. the reply left from the WRONG source port and a
//     CGNAT silently dropped it. Sockets are now reference-counted for the
//     duration of each write (pinned) and eviction only reclaims entries whose
//     refcount is zero. When every cached socket is pinned the pool transiently
//     exceeds the limit — that is deliberate: exceeding a soft bound is always
//     better than closing a socket mid-write. The overflow is reclaimed at the
//     next insert or the next unpin-to-zero.
//
//   - Poisoned-socket repair: a permanent write failure invalidates that exact
//     cached socket, re-binds the same source port, and retries the datagram
//     once. Without this a dead cached descriptor was returned forever and the
//     server repeatedly fell back to its main listening port; strict NAT/CGNAT
//     then dropped every reply until the process was restarted.
type sendSockPool struct {
	limit int

	// conns maps port -> *pooledConn. Chosen over a mutex-guarded map so the
	// per-datagram cache-hit path takes no lock at all (P0-1); writes to it
	// are rare (a port seen for the first time) and reconciled by LoadOrStore.
	conns sync.Map

	total   atomic.Int32 // number of entries currently in conns
	clock   atomic.Int64 // monotonic recency stamp source; never reused, immune to coarse wall clocks
	evictMu sync.Mutex   // serializes overflow-eviction scans only; never held on the hit path
	bindMu  sync.Mutex   // serializes bind/publish/repair on the cold path only; never held on healthy hits
	closed  atomic.Bool
	logf    func(format string, v ...interface{})
}

// DefaultSendSockMax bounds the reply-socket LRU when sendsock_max is unset.
// It doubles as the recommended ceiling for the port_range size: past this
// many ports the cache cannot hold one socket per port and starts thrashing.
// Kept as a named constant so validatePortRange reports the same number the
// pool actually enforces.
const DefaultSendSockMax = 512

// pooledConn is one cached UDP socket. It wraps the raw *net.UDPConn with the
// metadata the pool needs: its source port, a reference count pinning the
// socket against normal LRU eviction for the duration of each write, and a
// timestamped recency stamp replacing the old list-based LRU order.
type pooledConn struct {
	pool *sendSockPool
	conn *net.UDPConn
	port int

	refs    atomic.Int32 // >0 while a WriteToUDPAddrPort through this socket is in flight
	lastUse atomic.Int64 // pool clock stamp of the most recent Get; eviction reclaims the oldest
}

// LocalAddr proxies the underlying socket so callers that only inspect the
// bound port need no knowledge of the pooling.
func (pc *pooledConn) LocalAddr() net.Addr { return pc.conn.LocalAddr() }

func (pc *pooledConn) writeOnce(b []byte, addr netip.AddrPort) (int, error) {
	pc.refs.Add(1)
	n, err := pc.conn.WriteToUDPAddrPort(b, addr)
	remaining := pc.refs.Add(-1)
	if remaining == 0 && pc.pool != nil && int(pc.pool.total.Load()) > pc.pool.limit {
		pc.pool.reclaimOverflow()
	}
	return n, err
}

// WriteToUDPAddrPort pins the socket for the write. A transient send-pressure
// error is returned to the caller (ARQ retries it). A permanent error repairs
// the cached socket in-place and retries the SAME datagram once from the same
// source port, preserving strict-NAT symmetry without requiring a process
// restart.
func (pc *pooledConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	n, err := pc.writeOnce(b, addr)
	if err == nil || pc.pool == nil || !shouldReopenUDPWriteError(err) {
		return n, err
	}
	return pc.pool.repairAndRetry(pc, b, addr, err)
}

func newSendSockPool(limit int, logf func(format string, v ...interface{})) *sendSockPool {
	if limit <= 0 {
		limit = DefaultSendSockMax
	}
	return &sendSockPool{
		limit: limit,
		logf:  logf,
	}
}

// nextStamp hands out the next strictly-increasing recency stamp. A counter,
// not a wall clock: Windows-time granularity is far coarser than the gap
// between two Gets, and equal stamps would make the LRU victim ambiguous.
func (p *sendSockPool) nextStamp() int64 { return p.clock.Add(1) }

// Get returns the pooled socket bound to the given local port, creating it on
// demand. It never returns a nil conn together with a nil error.
func (p *sendSockPool) Get(port int) (*pooledConn, error) {
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid source port %d", port)
	}
	if p.closed.Load() {
		return nil, fmt.Errorf("send socket pool is closed")
	}

	// Fast path: cache hit. Lock-free on purpose (P0-1): one sync.Map load,
	// one atomic store for the recency stamp. No mutex is touched.
	if v, ok := p.conns.Load(port); ok {
		pc := v.(*pooledConn)
		pc.lastUse.Store(p.nextStamp())
		return pc, nil
	}

	// Slow path: this port is seen for the first time (or was evicted). The
	// bind+publish pair runs under bindMu so two racers for the SAME port can
	// never both bind.
	p.bindMu.Lock()
	if v, ok := p.conns.Load(port); ok { // racer published while we waited
		p.bindMu.Unlock()
		pc := v.(*pooledConn)
		pc.lastUse.Store(p.nextStamp())
		return pc, nil
	}
	if p.closed.Load() {
		p.bindMu.Unlock()
		return nil, fmt.Errorf("send socket pool is closed")
	}
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: port})
	if err != nil {
		p.bindMu.Unlock()
		if p.logf != nil {
			p.logf("[SockPool] ❌ bind port=%d failed: %v", port, err)
		}
		return nil, err
	}
	_ = uc.SetWriteBuffer(socketBufferSize)

	pc := &pooledConn{pool: p, conn: uc, port: port}
	pc.lastUse.Store(p.nextStamp())
	p.conns.Store(port, pc)
	p.bindMu.Unlock()

	n := p.total.Add(1)
	if p.logf != nil {
		p.logf("[SockPool] ✨ bound port=%d (cached=%d/limit=%d)", port, n, p.limit)
	}
	if int(n) > p.limit {
		// Pin the brand-new socket while the overflow scan runs: with every
		// older entry pinned it would otherwise be the ONLY unpinned candidate
		// and evict itself before the caller ever writes through it.
		pc.refs.Add(1)
		p.reclaimOverflow()
		pc.refs.Add(-1)
	}
	return pc, nil
}

// repairAndRetry replaces a permanently failed cached socket and retries one
// datagram. bindMu coalesces concurrent repair attempts for the same port. If
// another goroutine already published a replacement, use that socket instead.
func (p *sendSockPool) repairAndRetry(broken *pooledConn, b []byte, addr netip.AddrPort, cause error) (int, error) {
	if broken == nil || broken.port <= 0 {
		return 0, cause
	}
	if p.closed.Load() {
		return 0, cause
	}

	p.bindMu.Lock()
	if p.closed.Load() {
		p.bindMu.Unlock()
		return 0, cause
	}
	if v, ok := p.conns.Load(broken.port); ok && v != any(broken) {
		replacement := v.(*pooledConn)
		replacement.lastUse.Store(p.nextStamp())
		p.bindMu.Unlock()
		return replacement.WriteToUDPAddrPort(b, addr)
	}

	if actual, loaded := p.conns.LoadAndDelete(broken.port); loaded && actual == any(broken) {
		p.total.Add(-1)
	}
	// A permanent write failure means this descriptor is no longer useful.
	// Closing may make concurrent writers fail too; they converge here and use
	// the single replacement published below.
	_ = broken.conn.Close()

	uc, bindErr := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: broken.port})
	if bindErr != nil {
		p.bindMu.Unlock()
		if p.logf != nil {
			p.logf("[SockPool] ❌ repair port=%d after write error (%v) failed: %v", broken.port, cause, bindErr)
		}
		return 0, fmt.Errorf("reply socket write failed: %w; rebind port %d failed: %v", cause, broken.port, bindErr)
	}
	_ = uc.SetWriteBuffer(socketBufferSize)
	replacement := &pooledConn{pool: p, conn: uc, port: broken.port}
	replacement.lastUse.Store(p.nextStamp())
	p.conns.Store(broken.port, replacement)
	ncached := p.total.Add(1)
	p.bindMu.Unlock()

	if p.logf != nil {
		p.logf("[SockPool] 🔁 repaired port=%d after write failure (cached=%d/limit=%d)", broken.port, ncached, p.limit)
	}
	if int(ncached) > p.limit {
		replacement.refs.Add(1)
		p.reclaimOverflow()
		replacement.refs.Add(-1)
	}

	n, retryErr := replacement.writeOnce(b, addr)
	if retryErr != nil {
		return n, fmt.Errorf("reply socket repaired after %v but retry failed: %w", cause, retryErr)
	}
	return n, nil
}

// reclaimOverflow evicts least-recently-used UNPINNED sockets until the pool
// is back at or under its limit. Sockets with an in-flight write are never
// touched (P0-2): an overflow where every entry is pinned is left in place and
// reclaimed at the next insert or unpin instead.
func (p *sendSockPool) reclaimOverflow() {
	p.evictMu.Lock()
	defer p.evictMu.Unlock()

	for p.total.Load() > int32(p.limit) {
		type cand struct {
			port int
			pc   *pooledConn
		}
		cands := make([]cand, 0, 8)
		p.conns.Range(func(key, value any) bool {
			pc := value.(*pooledConn)
			if pc.refs.Load() == 0 {
				cands = append(cands, cand{port: key.(int), pc: pc})
			}
			return true
		})
		if len(cands) == 0 {
			return // everything pinned: soft overflow, retried on next insert/unpin
		}
		sort.Slice(cands, func(i, j int) bool {
			return cands[i].pc.lastUse.Load() < cands[j].pc.lastUse.Load()
		})

		victim := cands[0]
		if victim.pc.refs.Load() != 0 {
			victim.pc.lastUse.Store(p.nextStamp())
			return
		}
		if actual, loaded := p.conns.LoadAndDelete(victim.port); !loaded || actual != any(victim.pc) {
			return
		}
		p.total.Add(-1)
		_ = victim.pc.conn.Close()
		if p.logf != nil {
			p.logf("[SockPool] 🗑️ evict port=%d (cached=%d/limit=%d)", victim.port, p.total.Load(), p.limit)
		}
	}
}

// Len returns how many sockets are currently cached.
func (p *sendSockPool) Len() int {
	return int(p.total.Load())
}

// Close releases every cached socket. In-flight writes on closed sockets
// return errors to their callers; Close is a whole-pool teardown, so that is
// the expected behaviour.
func (p *sendSockPool) Close() {
	p.closed.Store(true)
	p.conns.Range(func(key, value any) bool {
		if p.conns.CompareAndDelete(key, value) {
			p.total.Add(-1)
		}
		_ = value.(*pooledConn).conn.Close()
		return true
	})
}
