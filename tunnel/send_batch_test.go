package tunnel

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestSendBatchRepairsSocketAndPreservesUnsentSuffix(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			ip := net.IPv4(127, 0, 0, 1)
			if network == "udp6" {
				ip = net.IPv6loopback
			}
			r, err := net.ListenUDP(network, &net.UDPAddr{IP: ip})
			if err != nil {
				if network == "udp6" {
					t.Skip(err)
				}
				t.Fatal(err)
			}
			defer r.Close()
			d, err := NewSpreadDialer(r.LocalAddr().String(), 1, 1)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			old := d.Conn(0)
			old.Close()
			if err = d.sendBatch([][]byte{[]byte("repair-a"), []byte("repair-b")}); err != nil {
				t.Fatal(err)
			}
			if d.Conn(0) == old {
				t.Fatal("batch failed to repair closed source socket")
			}
			buf := make([]byte, 1024)
			r.SetReadDeadline(time.Now().Add(time.Second))
			for _, want := range []string{"repair-a", "repair-b"} {
				n, _, err := r.ReadFromUDP(buf)
				if err != nil {
					t.Fatal(err)
				}
				if string(buf[:n]) != want {
					t.Fatalf("got %q want %q", buf[:n], want)
				}
			}
			if err = d.sendBatch([][]byte{[]byte("prefix"), make([]byte, 65536), []byte("suffix")}); err == nil {
				t.Fatal("oversized datagram should fail")
			}
			for _, want := range []string{"prefix", "suffix"} {
				n, _, err := r.ReadFromUDP(buf)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(buf[:n], []byte(want)) {
					t.Fatalf("partial batch duplicated prefix or lost suffix: %q", buf[:n])
				}
			}
		})
	}
}
