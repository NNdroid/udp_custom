package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// Real end-to-end through BOTH halves of this repo:
//
//	local app ──tcp──► Client ──udp_custom──► UDPCServer ──tcp──► backend echo
//
// This is what makes "mode":"client" (config.client.json) actually work.

type tunnel struct {
	clientAddr string // local TCP address applications connect to
	cleanup    func()
}

// startTunnel wires backend + server + client together.
func startTunnel(t *testing.T, serverUDP string, pubKey [32]byte, useNoise bool, sockets int) *tunnel {
	t.Helper()

	// Backend: TCP echo.
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend listen: %v", err)
	}
	go func() {
		for {
			c, err := backend.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				io.Copy(conn, conn)
			}(c)
		}
	}()

	srvCfg := ServerConfig{
		ListenAddr: serverUDP,
		TargetAddr: backend.Addr().String(),
		Passwords:  []string{"tunnel_psk"},
		LogLevel:   "error",
	}
	if useNoise {
		kp, err := GenerateNoiseKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		srvCfg.PrivateKey = hexOf(kp.PrivateKey)
		pubKey = kp.PublicKey
	}
	srv, err := NewUDPCServer(srvCfg)
	if err != nil {
		t.Fatalf("NewUDPCServer: %v", err)
	}
	serverUDP = srv.conn.LocalAddr().String()
	go srv.Start()

	cli, err := NewClient(ClientConfig{
		ListenAddr: "127.0.0.1:0",
		ServerAddr: serverUDP,
		Passwords:  []string{"tunnel_psk"},
		Magic:      UDPC_MAGIC_DEFAULT,
		LogLevel:   "error",
		Sockets:    sockets,
	})
	if err != nil {
		srv.Close()
		t.Fatalf("NewClient: %v", err)
	}
	if useNoise {
		cli.cfg.ServerPub = pubKey
	}

	// Learn a free local port for the client (port 0 → OS-assigned, then
	// released for the client to bind).
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		srv.Close()
		t.Fatalf("find free port: %v", err)
	}
	clientListen := probe.Addr().String()
	probe.Close()
	cli.cfg.ListenAddr = clientListen

	go cli.Start()
	time.Sleep(150 * time.Millisecond)

	return &tunnel{
		clientAddr: clientListen,
		cleanup:    func() { cli.Close(); srv.Close(); backend.Close() },
	}
}

func (tn *tunnel) dial(t *testing.T) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", tn.clientAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial client %s: %v", tn.clientAddr, err)
	}
	return conn
}

func TestClientMode_StreamRoundTrip(t *testing.T) {
	tn := startTunnel(t, "127.0.0.1:0", [32]byte{}, false, 1)
	defer tn.cleanup()

	conn := tn.dial(t)
	defer conn.Close()

	msg := []byte("hello through the tunnel")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(buf, msg) {
		t.Fatalf("echo mismatch: %q", buf)
	}
}

// A transfer far larger than one DATA frame: exercises chunking, the send
// window, cumulative ACKs and retransmission under load.
func TestClientMode_LargeTransfer(t *testing.T) {
	tn := startTunnel(t, "127.0.0.1:0", [32]byte{}, false, 1)
	defer tn.cleanup()

	conn := tn.dial(t)
	defer conn.Close()

	const size = 512 * 1024
	payload := make([]byte, size)
	rand.Read(payload)

	go func() {
		for off := 0; off < size; off += 8192 {
			end := off + 8192
			if end > size {
				end = size
			}
			if _, err := conn.Write(payload[off:end]); err != nil {
				return
			}
		}
	}()

	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	got := make([]byte, size)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read %d bytes: %v", size, err)
	}
	if !bytes.Equal(got, payload) {
		for i := range got {
			if got[i] != payload[i] {
				t.Fatalf("first mismatch at byte %d", i)
			}
		}
	}
}

// Same tunnel with Noise_NK on: the client must derive matching transport keys
// from the server's static public key.
func TestClientMode_NoiseEncrypted(t *testing.T) {
	tn := startTunnel(t, "127.0.0.1:0", [32]byte{}, true, 1)
	defer tn.cleanup()

	conn := tn.dial(t)
	defer conn.Close()

	payload := make([]byte, 40000)
	rand.Read(payload)
	go conn.Write(payload)

	conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("encrypted stream mismatch")
	}
}

// Two local applications through ONE client: each gets its own session and its
// own backend connection — and must not see each other's bytes.
func TestClientMode_TwoLocalConnectionsAreIsolated(t *testing.T) {
	tn := startTunnel(t, "127.0.0.1:0", [32]byte{}, false, 2)
	defer tn.cleanup()

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", tn.clientAddr, 3*time.Second)
			if err != nil {
				errs <- err
				return
			}
			defer conn.Close()

			// Distinct, identifiable payloads so cross-talk is detectable.
			payload := bytes.Repeat([]byte{byte('A' + idx)}, 20000)
			go conn.Write(payload)

			conn.SetReadDeadline(time.Now().Add(20 * time.Second))
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, got); err != nil {
				errs <- fmt.Errorf("conn %d: %v", idx, err)
				return
			}
			if !bytes.Equal(got, payload) {
				errs <- fmt.Errorf("conn %d: stream corrupted", idx)
				return
			}
			errs <- nil
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

// The client config template (config.client.json) must be honoured: mode
// selects the client role and the required fields are validated.
func TestClientConfigValidation(t *testing.T) {
	if _, err := NewClient(ClientConfig{ServerAddr: "1.2.3.4:36712", Passwords: []string{"p"}}); err == nil {
		t.Fatal("missing listen must be rejected")
	}
	if _, err := NewClient(ClientConfig{ListenAddr: "127.0.0.1:0", Passwords: []string{"p"}}); err == nil {
		t.Fatal("missing server must be rejected")
	}
	if _, err := NewClient(ClientConfig{ListenAddr: "127.0.0.1:0", ServerAddr: "1.2.3.4:36712"}); err == nil {
		t.Fatal("missing password must be rejected")
	}
	// A port-range server address is accepted (spreading), sockets default to 1.
	cli, err := NewClient(ClientConfig{ListenAddr: "127.0.0.1:0", ServerAddr: "1.2.3.4:25000-25499", Passwords: []string{"p"}})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if cli.dialer.Len() != 1 {
		t.Fatalf("default sockets = %d, want 1", cli.dialer.Len())
	}
	if cli.dialer.PortRange().Total() != 500 {
		t.Fatalf("port range total = %d, want 500", cli.dialer.PortRange().Total())
	}
	if cli.cfg.SendWindow != defaultSendWindow {
		t.Fatalf("default send window = %d, want %d", cli.cfg.SendWindow, defaultSendWindow)
	}
}

// The shipped config.client.json template must actually boot the client (it
// used to be silently ignored, which started a SERVER on the client's port).
func TestClientConfigTemplateBootsClient(t *testing.T) {
	data, err := os.ReadFile("config.client.json")
	if err != nil {
		t.Skipf("config.client.json not available: %v", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse config.client.json: %v", err)
	}
	if cfg.Mode != "client" {
		t.Fatalf("template mode = %q, want client", cfg.Mode)
	}
	if cfg.Server == "" {
		t.Fatal("template is missing 'server'")
	}
}
