package tunnel

import (
	"encoding/binary"
	"net/netip"
	"sync/atomic"
	"time"
)

func wireSequence(wire []byte) uint64 { return binary.BigEndian.Uint64(wire[20:28]) }

func creditProbeInterval(flow *sendFlow, outstanding map[uint64]*unackedPkt) (time.Duration, bool) {
	if flow == nil {
		return 0, false
	}
	sacked, gap := false, false
	for _, p := range outstanding {
		if p.sacked {
			sacked = true
		} else if !p.queued {
			gap = true
		}
	}
	if sacked && gap {
		return 25 * time.Millisecond, true
	}
	// Probe zero credit even after PONG cumulatively ACKed the final frame:
	// losing the separate window-opening SACK must not strand the next write.
	return 100 * time.Millisecond, flow.credit == 0 || sacked
}

func (s *clientSession) initTransmitter() {
	s.tx = newTransmitQueue(s.closeChan, s.client.dialer.sendBatch, func(n int) bool {
		return s.paceBurst(n)
	}, func(wires [][]byte) {
		s.markBatchTransmitted(wires)
	}, s.burstWindow, func(err error) {
		s.client.logWarn("[Client] [Session 0x%08X] ⚠️ batch send failed: %v (affected frames will be repaired by the retransmit loop)", s.sid, err)
	})
}

// paceBurst paces one batch against the effective window. Guarded by
// unackedMu by the caller's closure only; the lock is held here so cwnd and
// credit are read consistently.
func (s *clientSession) paceBurst(n int) bool {
	if s.flow == nil {
		return true
	}
	s.unackedMu.Lock()
	window := s.flow.window()
	s.unackedMu.Unlock()
	return s.flow.waitBurst(n, window, s.rttEst.SRTT(), s.closeChan)
}

func (s *clientSession) markBatchTransmitted(wires [][]byte) {
	s.unackedMu.Lock()
	markTransmitted(s.unacked, wires, time.Now())
	s.unackedMu.Unlock()
	notifyRetry(s.retryWake)
}

// burstWindow is the effective flight size: the smaller of the congestion
// window and the receiver's advertised credit.
func (s *clientSession) burstWindow() int {
	s.unackedMu.Lock()
	defer s.unackedMu.Unlock()
	if s.flow != nil {
		return s.flow.window()
	}
	return 16
}

func (s *ServerSession) initTransmitter() {
	s.tx = newTransmitQueue(s.closeChan, s.sendToSessionBatch, func(n int) bool {
		return s.paceBurst(n)
	}, func(wires [][]byte) {
		s.markBatchTransmitted(wires)
	}, s.burstWindow, func(err error) {
		s.server.logWarn("[Server] [Session 0x%08X] ⚠️ batch send failed: %v (affected frames will be repaired by the retransmit loop)", s.sessionID, err)
	})
}

func (s *ServerSession) paceBurst(n int) bool {
	if s.flow == nil {
		return true
	}
	s.unackedMu.Lock()
	window := s.flow.window()
	s.unackedMu.Unlock()
	return s.flow.waitBurst(n, window, s.rttEst.SRTT(), s.closeChan)
}

func (s *ServerSession) markBatchTransmitted(wires [][]byte) {
	s.unackedMu.Lock()
	markTransmitted(s.unacked, wires, time.Now())
	s.unackedMu.Unlock()
	notifyRetry(s.retryWake)
}

func (s *ServerSession) burstWindow() int {
	s.unackedMu.Lock()
	defer s.unackedMu.Unlock()
	if s.flow != nil {
		return s.flow.window()
	}
	return 16
}

// sendToSessionBatch ships one batch. Every branch degrades to per-frame
// writes, so there is no observable failure to report: the caller marks the
// frames transmitted either way and the retransmit loop repairs anything the
// kernel did not accept.
func (s *ServerSession) sendToSessionBatch(wires [][]byte) error {
	port := int(atomic.LoadInt32(&s.lastOrigPort))
	s.pathMu.RLock()
	addr := s.pathAddrs[port].addr
	s.pathMu.RUnlock()
	if !addr.IsValid() { // Preserve existing LRU route selection on the cold path.
		for _, wire := range wires {
			s.sendToSession(wire)
		}
		return nil
	}
	if port > 0 && port != s.server.bindPort {
		pc, err := s.server.sockPool.Get(port)
		if err != nil {
			for _, wire := range wires {
				s.sendToSession(wire)
			}
			return nil
		}
		pc.refs.Add(1)
		dst := make([]netip.AddrPort, len(wires))
		for i := range dst {
			dst[i] = addr
		}
		n, _ := writeUDPBatch(pc.conn, wires, dst)
		if pc.refs.Add(-1) == 0 && int(pc.pool.total.Load()) > pc.pool.limit {
			pc.pool.reclaimOverflow()
		}
		s.server.sendViaPort.Add(uint64(n))
		for _, wire := range wires[n:] {
			if _, err := pc.WriteToUDPAddrPort(wire, addr); err == nil {
				s.server.sendViaPort.Add(1)
			}
		}
		return nil
	}
	dst := make([]netip.AddrPort, len(wires))
	for i := range dst {
		dst[i] = addr
	}
	n, _ := writeUDPBatch(s.server.conn, wires, dst)
	s.server.sendViaMain.Add(uint64(n))
	for _, wire := range wires[n:] {
		s.server.replyFromOrigPort(0, addr, wire)
	}
	return nil
}

// sendBatch selects the same n:n tuples as Send and groups frames by source
// socket. Repair preserves each selected destination port and never resends a
// prefix that sendmmsg already accepted.
func (d *SpreadDialer) sendBatch(wires [][]byte) error {
	type selected struct {
		wire []byte
		port int
	}
	groups := make(map[int][]selected)
	for _, wire := range wires {
		idx, port := d.Next()
		if idx < 0 {
			return ErrNoRoute
		}
		groups[idx] = append(groups[idx], selected{wire, port})
	}
	var firstErr error
	for idx, group := range groups {
		d.destMu.RLock()
		addr := d.serverAddr
		d.destMu.RUnlock()
		data := make([][]byte, len(group))
		dst := make([]netip.AddrPort, len(group))
		for i, p := range group {
			data[i] = p.wire
			dst[i] = netip.AddrPortFrom(addr, uint16(p.port))
		}
		sock := d.socks[idx]
		sock.mu.RLock()
		conn := sock.conn
		n := 0
		if conn != nil {
			n, _ = writeUDPBatch(conn, data, dst)
		}
		sock.mu.RUnlock()
		for _, p := range group[n:] {
			if err := d.sendAtPort(idx, p.port, p.wire); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}
