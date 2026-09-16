package tunnel

import (
	"testing"
	"unsafe"
)

// TestZZAlignProbe is a throwaway diagnostic: it prints the byte offset of every
// field that is accessed with a 64-bit atomic op, so the 32-bit (arm/386)
// layout can be inspected directly instead of hand-computed.
func TestZZAlignProbe(t *testing.T) {
	bad := func(name string, off uintptr) {
		mark := "ok"
		if off%8 != 0 {
			mark = "*** MISALIGNED ***"
		}
		t.Logf("%-32s off=%3d %s", name, off, mark)
	}
	t.Logf("ptrsize=%d", unsafe.Sizeof(uintptr(0)))

	var cs clientSession
	bad("clientSession.sendPacketNo", unsafe.Offsetof(cs.sendPacketNo))
	bad("clientSession.sendSeq", unsafe.Offsetof(cs.sendSeq))
	bad("clientSession.recvSeq", unsafe.Offsetof(cs.recvSeq))

	var ss ServerSession
	bad("ServerSession.sendPacketNo", unsafe.Offsetof(ss.sendPacketNo))
	bad("ServerSession.sendSeq", unsafe.Offsetof(ss.sendSeq))
	bad("ServerSession.recvSeq", unsafe.Offsetof(ss.recvSeq))

	var s Server
	bad("Server.outOfRangePkts", unsafe.Offsetof(s.outOfRangePkts))
	bad("Server.origPortChanges", unsafe.Offsetof(s.origPortChanges))
	bad("Server.sendViaPort", unsafe.Offsetof(s.sendViaPort))
	bad("Server.sendViaMain", unsafe.Offsetof(s.sendViaMain))
	bad("Server.queueFullDrops", unsafe.Offsetof(s.queueFullDrops))
	bad("Server.decodeFailures", unsafe.Offsetof(s.decodeFailures))
	bad("Server.macFailures", unsafe.Offsetof(s.macFailures))
	bad("Server.replayDrops", unsafe.Offsetof(s.replayDrops))

	var eb eventBus[SessionEvent]
	bad("eventBus.dropped", unsafe.Offsetof(eb.dropped))

	var sd SpreadDialer
	bad("SpreadDialer.rr", unsafe.Offsetof(sd.rr))

	var ps PortSelector
	bad("PortSelector.rr", unsafe.Offsetof(ps.rr))

	bad("package-level fallbackSeed", uintptr(unsafe.Pointer(&fallbackSeed)))
}
