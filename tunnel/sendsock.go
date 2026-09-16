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
type sendSockPool struct {
	limit int

	// conns maps port -> *pooledConn. Chosen over a mutex-guarded map so the
	// per-datagram cache-hit path takes no lock at all (P0-1); writes to it
	// are rare (a port seen for the first time) and reconciled by LoadOrStore.
	conns sync.Map

	total   atomic.Int32 // number of entries currently in conns
	clock   atomic.Int64 // monotonic recency stamp source; never reused, immune to coarse wall clocks
	evictMu sync.Mutex   // serializes overflow-eviction scans only; never held on the hit path
	bindMu  sync.Mutex   // serializes bind+publish on the cold path only; never held on the hit path
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
// two pieces of metadata the pool needs: a reference count pinning the socket
// against eviction for the duration of each write, and a timestamped recency
// stamp replacing the old list-based LRU order.
type pooledConn struct {
	pool *sendSockPool
	conn *net.UDPConn

	refs    atomic.Int32 // >0 while a WriteToUDPAddrPort through this socket is in flight
	lastUse atomic.Int64 // pool clock stamp of the most recent Get; eviction reclaims the oldest
}

// LocalAddr proxies the underlying socket so callers that only inspect the
// bound port need no knowledge of the pooling.
func (pc *pooledConn) LocalAddr() net.Addr { return pc.conn.LocalAddr() }

// WriteToUDPAddrPort pins the socket (refs++) for the duration of the write so
// a concurrent overflow eviction can never close it underneath the caller
// (P0-2). After the write the reference is dropped; if that uncovered an
// overflow, the deferred reclamation runs right here.
func (pc *pooledConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	pc.refs.Add(1)
	n, err := pc.conn.WriteToUDPAddrPort(b, addr)
	remaining := pc.refs.Add(-1)
	if remaining == 0 && pc.pool != nil && int(pc.pool.total.Load()) > pc.pool.limit {
		pc.pool.reclaimOverflow()
	}
	return n, err
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
// demand. It never returns a nil conn together with a nil error. The returned
// *pooledConn is pointer-stable across cache hits; a write racing an eviction
// can still observe a closed socket and surface the error — the send path
// treats that exactly like any other write failure (fall back to main).
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
	// never both bind: without it the loser gets EADDRINUSE while the winner
	// is still between bind and publish, and a single re-check cannot close
	// that window (observed as a flaky failure under -count=1 load). The
	// mutex is NEVER taken on the cache-hit path — the per-datagram hot path
	// stays lock-free (P0-1) — so it is only contended when several ports are
	// bound for the first time at the same instant, an event that happens at
	// most once per port per pool lifetime.
	p.bindMu.Lock()
	if v, ok := p.conns.Load(port); ok { // racer published while we waited
		p.bindMu.Unlock()
		pc := v.(*pooledConn)
		pc.lastUse.Store(p.nextStamp())
		return pc, nil
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

	pc := &pooledConn{pool: p, conn: uc}
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
		// and evict itself before the caller ever writes through it — which
		// would silently degrade this very reply to the main socket.
		pc.refs.Add(1)
		p.reclaimOverflow()
		pc.refs.Add(-1)
	}
	return pc, nil
}

// reclaimOverflow evicts least-recently-used UNPINNED sockets until the pool
// is back at or under its limit. Sockets with an in-flight write are never
// touched (P0-2): an overflow where every entry is pinned is left in place and
// reclaimed at the next insert or unpin instead.
func (p *sendSockPool) reclaimOverflow() {
	p.evictMu.Lock()
	defer p.evictMu.Unlock()

	for p.total.Load() > int32(p.limit) {
		// Collect unpinned candidates. Eviction is rare (only on overflow),
		// so the O(n) scan is fine next to the cost of getting this wrong.
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
		// Re-check refs immediately before removal: a writer may have pinned
		// the entry between the scan and here. Closing then would still be
		// SAFE (the write fails and the caller falls back to the main socket),
		// but skipping keeps the good path deterministic. Bump the stamp so
		// the next scan does not spin on the same pinned entry.
		if victim.pc.refs.Load() != 0 {
			victim.pc.lastUse.Store(p.nextStamp())
			return
		}
		if actual, loaded := p.conns.LoadAndDelete(victim.port); !loaded || actual != any(victim.pc) {
			return // someone else replaced it; nothing to do this round
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
