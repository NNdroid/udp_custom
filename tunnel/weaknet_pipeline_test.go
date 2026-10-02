package tunnel

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// A real UDP relay injects delay, loss, duplicates and reorder in both
// directions without requiring root or changing the host's network settings.
func lossyRelay(t *testing.T, server *net.UDPAddr) string {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	done := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		var client *net.UDPAddr
		dropped := [2]bool{}
		buf := make([]byte, 2048)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			direction := 0
			dest := server
			if from.Port == server.Port {
				direction = 1
				dest = client
			} else {
				client = from
			}
			if dest == nil {
				continue
			}
			wire := append([]byte(nil), buf[:n]...)
			delay := 5 * time.Millisecond
			duplicate := false
			if n >= UDPC_HDR_SIZE && wire[5] == CMD_DATA {
				seq := binary.BigEndian.Uint64(wire[20:28])
				if seq == 1 && !dropped[direction] {
					dropped[direction] = true
					continue
				}
				if seq == 2 {
					delay = 15 * time.Millisecond
				}
				duplicate = seq == 3
			}
			wg.Add(1)
			go func(wire []byte, dest *net.UDPAddr, delay time.Duration, duplicate bool) {
				defer wg.Done()
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-done:
					return
				case <-timer.C:
				}
				_, _ = conn.WriteToUDP(wire, dest)
				if duplicate {
					_, _ = conn.WriteToUDP(wire, dest)
				}
			}(wire, dest, delay, duplicate)
		}
	}()
	t.Cleanup(func() { close(done); conn.Close(); wg.Wait() })
	return conn.LocalAddr().String()
}

func TestPipelineRecoversLossReorderAndDuplicates(t *testing.T) {
	for _, fec := range []bool{false, true} {
		t.Run(map[bool]string{false: "ARQ", true: "FEC"}[fec], func(t *testing.T) {
			srv, err := NewServerWithDialer(ServerConfig{ListenAddr: "127.0.0.1:0", TargetAddr: "tcp://echo:1", Passwords: []string{"weaknet-test-secret"}, FEC: &fec, Logger: Nop}, func(context.Context, uint32, string, string) (net.Conn, error) {
				a, b := net.Pipe()
				go func() { defer b.Close(); _, _ = io.Copy(b, b) }()
				return a, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer srv.Close()
			go srv.Start()
			off := false
			addr := lossyRelay(t, srv.conn.LocalAddr().(*net.UDPAddr))
			c, err := NewClient(ClientConfig{ServerAddr: addr, Passwords: []string{"weaknet-test-secret"}, FEC: &fec, MtuProbe: &off, Logger: Nop})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			conn, err := c.DialTunnel(context.Background(), DialOptions{})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(10 * time.Second))
			want := make([]byte, 256<<10)
			for i := range want {
				want[i] = byte((i*17 + i/31) % 251)
			}
			written := make(chan error, 1)
			go func() { _, err := conn.Write(want); written <- err }()
			got := make([]byte, len(want))
			if _, err = io.ReadFull(conn, got); err != nil {
				t.Fatal(err)
			}
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatal("loss/reorder corrupted the byte stream")
			}
			if !fec {
				fast := 0
				c.sessions.Range(func(_, v any) bool {
					s := v.(*clientSession)
					s.unackedMu.Lock()
					fast += s.flow.fastRepairs
					s.unackedMu.Unlock()
					return true
				})
				if fast == 0 {
					t.Fatal("loss recovered only by timeout; selective fast repair was not exercised")
				}
			}
		})
	}
}
