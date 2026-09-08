package tunnel

// Application-layer target tests: the tunnel must carry REAL protocols, not
// just byte echoes. TCP targets are exercised with an actual HTTP server (10
// keep-alive requests over ONE tunnel session), UDP targets with a fake DNS
// server (10 queries over the same session, answers validated as DNS).
// Benchmarks measure sustained TCP and UDP throughput for both crypto modes.

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const targetsPSK = "targets-psk"

// startTargetPair boots a Server whose target is `target` and a Client in the
// requested crypto mode, and returns one live tunnel connection. Everything is
// registered for cleanup; the client uses the PUBLIC API only.
func startTargetPair(tb testing.TB, noise bool, target string) (*Server, *Client, net.Conn) {
	tb.Helper()
	cfg := ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TargetAddr: target,
		Passwords:  []string{targetsPSK},
		Logger:     Nop,
	}
	var pub [32]byte
	if noise {
		kp, err := GenerateNoiseKeyPair()
		if err != nil {
			tb.Fatal(err)
		}
		cfg.PrivateKey = hex.EncodeToString(kp.PrivateKey[:])
		pub = kp.PublicKey
	}
	srv, err := NewServer(cfg)
	if err != nil {
		tb.Fatal(err)
	}
	go srv.Start()
	tb.Cleanup(srv.Close)

	cli, err := NewClient(ClientConfig{
		ServerAddr: srv.conn.LocalAddr().String(),
		Passwords:  []string{targetsPSK},
		ServerPub:  pub,
		Logger:     Nop,
	})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(cli.Close)

	conn, err := cli.DialTunnel(context.Background(), DialOptions{})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { conn.Close() })
	return srv, cli, conn
}

// --- HTTP over the tunnel (TCP target) ----------------------------------------

func TestTargets_HTTPOverTunnel(t *testing.T) {
	for _, mode := range []struct {
		name  string
		noise bool
	}{{"psk", false}, {"noise", true}} {
		t.Run(mode.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, "hello-over-tunnel")
			}))
			defer ts.Close()

			srv, _, conn := startTargetPair(t, mode.noise, "tcp://"+ts.Listener.Addr().String())

			// 10 HTTP requests over the SAME tunnel session: the transport
			// dials exactly once and keep-alive reuses the connection.
			dials := 0
			hc := &http.Client{
				Timeout: 10 * time.Second,
				Transport: &http.Transport{
					DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
						dials++
						return conn, nil
					},
				},
			}
			for i := 0; i < 10; i++ {
				resp, err := hc.Get("http://target.invalid/")
				if err != nil {
					t.Fatalf("request %d: %v", i+1, err)
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					t.Fatalf("request %d read body: %v", i+1, err)
				}
				if resp.StatusCode != http.StatusOK || string(body) != "hello-over-tunnel" {
					t.Fatalf("request %d: status=%d body=%q", i+1, resp.StatusCode, body)
				}
			}
			if dials != 1 {
				t.Fatalf("HTTP opened %d connections, want 1 (10 requests must ride one tunnel session)", dials)
			}
			if st := srv.Stats(); st.Sessions != 1 {
				t.Fatalf("Sessions = %d, want 1", st.Sessions)
			}
		})
	}
}

// --- DNS over the tunnel (UDP target) -----------------------------------------

// startDNSTarget spins a fake UDP DNS server: every A query is answered with
// the query's own ID, the question echoed, and an A record 192.0.2.1.
func startDNSTarget(tb testing.TB) *net.UDPConn {
	tb.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if resp := buildDNSResponse(buf[:n]); resp != nil {
				if _, err := conn.WriteToUDP(resp, from); err != nil {
					return
				}
			}
		}
	}()
	return conn
}

func buildDNSQuery(id uint16, name string) []byte {
	var q []byte
	var h [12]byte
	binary.BigEndian.PutUint16(h[0:2], id)
	binary.BigEndian.PutUint16(h[2:4], 0x0100) // RD=1
	binary.BigEndian.PutUint16(h[4:6], 1)      // QDCOUNT=1
	q = append(q, h[:]...)
	for _, label := range strings.Split(name, ".") {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0)                      // root label
	q = append(q, 0x00, 0x01, 0x00, 0x01) // QTYPE=A, QCLASS=IN
	return q
}

func buildDNSResponse(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	resp := append([]byte(nil), query[:2]...)               // echo transaction ID
	resp = append(resp, 0x81, 0x80)                         // QR=1 RD=1, RA=1
	resp = append(resp, 0x00, 0x01)                         // QDCOUNT=1
	resp = append(resp, 0x00, 0x01)                         // ANCOUNT=1
	resp = append(resp, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // NS/AR = 0
	resp = append(resp, query[12:]...)                      // echo the question
	resp = append(resp, 0xC0, 0x0C)                         // NAME = pointer to QNAME
	resp = append(resp, 0x00, 0x01, 0x00, 0x01)             // TYPE=A, CLASS=IN
	resp = append(resp, 0x00, 0x00, 0x01, 0x2C)             // TTL=300
	resp = append(resp, 0x00, 0x04, 192, 0, 2, 1)           // RDLEN=4, 192.0.2.1
	return resp
}

func TestTargets_DNSOverTunnel(t *testing.T) {
	for _, mode := range []struct {
		name  string
		noise bool
	}{{"psk", false}, {"noise", true}} {
		t.Run(mode.name, func(t *testing.T) {
			dns := startDNSTarget(t)
			srv, _, conn := startTargetPair(t, mode.noise, "udp://"+dns.LocalAddr().String())

			// 10 DNS queries over the SAME tunnel session: UDP datagram
			// boundaries are preserved end to end, so each Write is exactly
			// one query and each Read exactly one answer.
			for i := 1; i <= 10; i++ {
				id := uint16(i)
				query := buildDNSQuery(id, "example.test")
				conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if _, err := conn.Write(query); err != nil {
					t.Fatalf("query %d write: %v", i, err)
				}
				buf := make([]byte, 1500)
				conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				n, err := conn.Read(buf)
				if err != nil {
					t.Fatalf("query %d read: %v", i, err)
				}
				if n < 12 {
					t.Fatalf("query %d: response too short (%d bytes)", i, n)
				}
				if got := binary.BigEndian.Uint16(buf[0:2]); got != id {
					t.Fatalf("query %d: response ID = %d", i, got)
				}
				if buf[2]&0x80 == 0 {
					t.Fatalf("query %d: response is not a QR answer", i)
				}
				if an := binary.BigEndian.Uint16(buf[6:8]); an != 1 {
					t.Fatalf("query %d: ANCOUNT = %d, want 1", i, an)
				}
				if !bytes.Equal(buf[n-4:n], []byte{192, 0, 2, 1}) {
					t.Fatalf("query %d: answer rdata = %v, want 192.0.2.1", i, buf[n-4:n])
				}
			}
			if st := srv.Stats(); st.Sessions != 1 {
				t.Fatalf("Sessions = %d, want 1 (10 queries must ride one session)", st.Sessions)
			}
		})
	}
}

// --- throughput benchmarks: protocol (PSK/Noise) x target (TCP/UDP) -----------

// benchTunnelTCPTarget: 16 KB writes pipelined 16 deep through the tunnel into
// a TCP echo target, read back in full — measures sustained stream throughput.
func benchTunnelTCPTarget(b *testing.B, noise bool) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()

	_, _, conn := startTargetPair(b, noise, "tcp://"+ln.Addr().String())
	conn.SetDeadline(time.Now().Add(10 * time.Minute))

	const chunk = 8192
	const batch = 16
	chunkBuf := make([]byte, chunk)
	readBuf := make([]byte, chunk*batch)
	b.SetBytes(int64(chunk * batch))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < batch; j++ {
			if _, err := conn.Write(chunkBuf); err != nil {
				b.Fatal(err)
			}
		}
		if _, err := io.ReadFull(conn, readBuf); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTCPTarget_PSK(b *testing.B)   { benchTunnelTCPTarget(b, false) }
func BenchmarkTCPTarget_Noise(b *testing.B) { benchTunnelTCPTarget(b, true) }

// benchTunnelUDPTarget: 1 KB datagrams pipelined 16 deep into a UDP echo
// target — measures datagram throughput with boundaries preserved.
func benchTunnelUDPTarget(b *testing.B, noise bool) {
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		b.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if _, err := echo.WriteToUDP(buf[:n], from); err != nil {
				return
			}
		}
	}()

	_, _, conn := startTargetPair(b, noise, "udp://"+echo.LocalAddr().String())
	conn.SetDeadline(time.Now().Add(10 * time.Minute))

	const chunk = 1024
	const batch = 16
	chunkBuf := make([]byte, chunk)
	b.SetBytes(int64(chunk * batch))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < batch; j++ {
			if _, err := conn.Write(chunkBuf); err != nil {
				b.Fatal(err)
			}
		}
		for j := 0; j < batch; j++ {
			if _, err := conn.Read(chunkBuf); err != nil {
				b.Fatal(err)
			}
		}
	}
}

func BenchmarkUDPTarget_PSK(b *testing.B)   { benchTunnelUDPTarget(b, false) }
func BenchmarkUDPTarget_Noise(b *testing.B) { benchTunnelUDPTarget(b, true) }
