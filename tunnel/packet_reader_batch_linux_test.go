//go:build linux

package tunnel

import (
	"net"
	"testing"
)

func TestPacketReaderLinuxBatchDrain(t *testing.T) {
	recv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer recv.Close()

	send, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer send.Close()

	addr := recv.LocalAddr().(*net.UDPAddr)
	const count = 8
	for i := 0; i < count; i++ {
		if _, err := send.WriteToUDP([]byte{byte(i), 0x5a}, addr); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}

	r := newPacketReader(recv, Nop, false)
	pkts, err := r.next()
	if err != nil {
		t.Fatalf("next: %v", err)
	}
	if len(pkts) != count {
		t.Fatalf("got %d packets, want %d; Linux burst should be drained by one batch read", len(pkts), count)
	}
	for i, pkt := range pkts {
		if len(pkt.data) != 2 || pkt.data[0] != byte(i) || pkt.data[1] != 0x5a {
			t.Fatalf("packet %d mismatch: %x", i, pkt.data)
		}
		if !pkt.from.IsValid() {
			t.Fatalf("packet %d has invalid source address", i)
		}
	}
}
