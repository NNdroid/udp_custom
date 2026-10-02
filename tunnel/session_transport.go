package tunnel

import (
	"encoding/binary"
	"net/netip"
	"sync/atomic"
	"time"
)

func wireSequence(wire []byte) uint64 { return binary.BigEndian.Uint64(wire[20:28]) }

func needsCreditProbe(flow *sendFlow, outstanding map[uint64]*unackedPkt, now time.Time) bool {
	interval, need := creditProbeInterval(flow, outstanding)
	if !need || now.Sub(flow.lastProbe) < interval {
		return false
	}
	flow.lastProbe = now
	return true
}

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

func (s *clientSession) probeReceiveCredit(now time.Time) {
	s.unackedMu.Lock()
	probe := needsCreditProbe(s.flow, s.unacked, now)
	s.unackedMu.Unlock()
	if probe {
		s.sendControl(&UDPCFrame{Magic: s.client.magic, Version: UDPC_VERSION, Cmd: CMD_PING, SessionID: s.sid, Ack: s.currentAck()}, s.client.dialer.Send)
	}
}

func (s *ServerSession) probeReceiveCredit(now time.Time) {
	s.unackedMu.Lock()
	probe := needsCreditProbe(s.flow, s.unacked, now)
	s.unackedMu.Unlock()
	if probe {
		s.sendControl(&UDPCFrame{Magic: s.server.cfg.Magic, Version: UDPC_VERSION, Cmd: CMD_PING, SessionID: s.sessionID, Ack: s.currentAck()}, func(p []byte) error { s.sendToSession(p); return nil })
	}
}

func (s *clientSession) initTransmitter() {
	s.tx = newTransmitQueue(s.closeChan, func(wires [][]byte) { _ = s.client.dialer.sendBatch(wires) }, func(n int) bool {
		if s.flow == nil {
			return true
		}
		s.unackedMu.Lock()
		window := s.flow.cwnd
		s.unackedMu.Unlock()
		return s.flow.waitBurst(n, window, s.rttEst.SRTT(), s.closeChan)
	}, func(wires [][]byte) {
		s.unackedMu.Lock()
		markTransmitted(s.unacked, wires, time.Now())
		s.unackedMu.Unlock()
		notifyRetry(s.retryWake)
	}, func() int {
		s.unackedMu.Lock()
		defer s.unackedMu.Unlock()
		if s.flow != nil {
			return s.flow.cwnd
		}
		return 16
	})
}

func (s *ServerSession) initTransmitter() {
	s.tx = newTransmitQueue(s.closeChan, s.sendToSessionBatch, func(n int) bool {
		if s.flow == nil {
			return true
		}
		s.unackedMu.Lock()
		window := s.flow.cwnd
		s.unackedMu.Unlock()
		return s.flow.waitBurst(n, window, s.rttEst.SRTT(), s.closeChan)
	}, func(wires [][]byte) {
		s.unackedMu.Lock()
		markTransmitted(s.unacked, wires, time.Now())
		s.unackedMu.Unlock()
		notifyRetry(s.retryWake)
	}, func() int {
		s.unackedMu.Lock()
		defer s.unackedMu.Unlock()
		if s.flow != nil {
			return s.flow.cwnd
		}
		return 16
	})
}

func (s *ServerSession) sendToSessionBatch(wires [][]byte) {
	port := int(atomic.LoadInt32(&s.lastOrigPort))
	s.pathMu.RLock()
	addr := s.pathAddrs[port].addr
	s.pathMu.RUnlock()
	if !addr.IsValid() { // Preserve existing LRU route selection on the cold path.
		for _, wire := range wires {
			s.sendToSession(wire)
		}
		return
	}
	if port > 0 && port != s.server.bindPort {
		pc, err := s.server.sockPool.Get(port)
		if err != nil {
			for _, wire := range wires {
				s.sendToSession(wire)
			}
			return
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
		return
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
