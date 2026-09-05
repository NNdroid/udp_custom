package tunnel

import (
	"container/list"
	"fmt"
	"net"
	"sync"
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
type sendSockPool struct {
	mu    sync.Mutex
	limit int
	conns map[int]*net.UDPConn
	elems map[int]*list.Element
	order *list.List // front = most recently used, back = eviction candidate
	logf  func(format string, v ...interface{})
}

// DefaultSendSockMax bounds the reply-socket LRU when sendsock_max is unset.
// It doubles as the recommended ceiling for the port_range size: past this
// many ports the cache cannot hold one socket per port and starts thrashing.
// Kept as a named constant so validatePortRange reports the same number the
// pool actually enforces.
const DefaultSendSockMax = 512

func newSendSockPool(limit int, logf func(format string, v ...interface{})) *sendSockPool {
	if limit <= 0 {
		limit = DefaultSendSockMax
	}
	return &sendSockPool{
		limit: limit,
		conns: make(map[int]*net.UDPConn),
		elems: make(map[int]*list.Element),
		order: list.New(),
		logf:  logf,
	}
}

// Get returns a socket bound to the given local port, creating it on demand.
// It never returns a nil conn together with a nil error.
func (p *sendSockPool) Get(port int) (*net.UDPConn, error) {
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid source port %d", port)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if c, ok := p.conns[port]; ok {
		p.order.MoveToFront(p.elems[port])
		return c, nil
	}

	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: port})
	if err != nil {
		if p.logf != nil {
			p.logf("[SockPool] ❌ bind port=%d failed: %v", port, err)
		}
		return nil, err
	}
	_ = uc.SetWriteBuffer(socketBufferSize)

	p.conns[port] = uc
	p.elems[port] = p.order.PushFront(port)
	if p.logf != nil {
		p.logf("[SockPool] ✨ bound port=%d (cached=%d/limit=%d)", port, len(p.conns), p.limit)
	}

	for p.order.Len() > p.limit {
		back := p.order.Back()
		if back == nil {
			break
		}
		victim := back.Value.(int)
		p.order.Remove(back)
		if oc, ok := p.conns[victim]; ok {
			_ = oc.Close()
			delete(p.conns, victim)
		}
		delete(p.elems, victim)
		if p.logf != nil {
			p.logf("[SockPool] 🗑️ evict port=%d (cached=%d/limit=%d)", victim, len(p.conns), p.limit)
		}
	}

	return uc, nil
}

// Len returns how many sockets are currently cached.
func (p *sendSockPool) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.conns)
}

// Close releases every cached socket.
func (p *sendSockPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for port, c := range p.conns {
		_ = c.Close()
		delete(p.conns, port)
	}
	p.elems = make(map[int]*list.Element)
	p.order.Init()
}
