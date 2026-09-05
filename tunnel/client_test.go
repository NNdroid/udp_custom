package tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// Real end-to-end through BOTH halves of this repo:
//
//	local app ──tcp──► Client ──udp_custom──► Server ──tcp──► backend echo
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
	srv, err := NewServer(srvCfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
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

// The client config (config.client.json) must be honoured: mode selects the
// client role and the required fields are validated.
func TestClientConfigValidation(t *testing.T) {
	// ListenAddr is optional for embedders (DialTunnel needs no listener); it
	// is only enforced by Start.
	if _, err := NewClient(ClientConfig{ServerAddr: "1.2.3.4:36712", Passwords: []string{"p"}}); err != nil {
		t.Fatalf("listener-less client must be constructible for DialTunnel: %v", err)
	}
	startErr := func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panic: %v", r)
			}
		}()
		cli, cliErr := NewClient(ClientConfig{ServerAddr: "1.2.3.4:36712", Passwords: []string{"p"}})
		if cliErr != nil {
			return cliErr
		}
		return cli.Start()
	}()
	if startErr == nil {
		t.Fatal("Start without 'listen' must be rejected")
	}
	if _, err := NewClient(ClientConfig{ListenAddr: "127.0.0.1:0", Passwords: []string{"p"}}); err == nil {
		t.Fatal("missing server must be rejected")
	}
	if _, err := NewClient(ClientConfig{ListenAddr: "127.0.0.1:0", ServerAddr: "1.2.3.4:36712"}); err == nil {
		t.Fatal("missing password must be rejected")
	}
	if _, err := NewClient(ClientConfig{ListenAddr: "127.0.0.1:0", ServerAddr: "1.2.3.4:36712", Passwords: []string{" ", "\t"}}); err == nil {
		t.Fatal("blank passwords must be rejected")
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

func TestClientIgnoresForgedHandshakeACKBeforeValidACK(t *testing.T) {
	const psk = "handshake-psk"
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client, err := NewClient(ClientConfig{
		ListenAddr: "127.0.0.1:0",
		ServerAddr: server.LocalAddr().String(),
		Passwords:  []string{psk},
		LogLevel:   "error",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	go client.recvLoop(client.dialer.Conn(0))

	invalidSent := make(chan struct{})
	sendValid := make(chan struct{})
	serverErr := make(chan error, 1)
	go func() {
		buf := make([]byte, UDPC_MAX_PKT)
		_ = server.SetReadDeadline(time.Now().Add(time.Second))
		n, remote, err := server.ReadFromUDP(buf)
		if err != nil {
			serverErr <- err
			return
		}
		syn, err := DecodeUDPCFrame(buf[:n], UDPC_MAGIC_DEFAULT)
		if err != nil || len(syn.Data) < synPayloadBase {
			serverErr <- fmt.Errorf("decode SYN: %w", err)
			return
		}
		var clientNonce [clientNonceSize]byte
		copy(clientNonce[:], syn.Data[:clientNonceSize])
		keys := DerivePSKHandshakeKeys(psk, clientNonce)
		if err := VerifyFrameAuth(syn.Raw(), &keys.SynMAC); err != nil {
			serverErr <- fmt.Errorf("authenticate SYN: %w", err)
			return
		}
		var serverNonce [serverNonceSize]byte
		copy(serverNonce[:], "server-nonce-v2!")
		payload := append(append([]byte(nil), clientNonce[:]...), serverNonce[:]...)
		valid := SealFrameMAC(&UDPCFrame{
			Magic: UDPC_MAGIC_DEFAULT, Version: UDPC_VERSION,
			Cmd: CMD_HANDSHAKE_ACK, SessionID: 0x10203040, Data: payload,
		}, &keys.AckMAC)
		invalid := append([]byte(nil), valid...)
		invalid[len(invalid)-1] ^= 1
		if _, err := server.WriteToUDP(invalid, remote); err != nil {
			serverErr <- err
			return
		}
		close(invalidSent)
		<-sendValid
		_, err = server.WriteToUDP(valid, remote)
		serverErr <- err
	}()

	type handshakeResult struct {
		sid  uint32
		keys *FrameKeys
		err  error
	}
	result := make(chan handshakeResult, 1)
	go func() {
		sid, noise, keys, _, err := client.handshake(context.Background(), "")
		if noise != nil {
			err = fmt.Errorf("unexpected Noise session")
		}
		result <- handshakeResult{sid: sid, keys: keys, err: err}
	}()

	select {
	case <-invalidSent:
	case err := <-serverErr:
		t.Fatalf("fake server failed: %v", err)
	case <-time.After(time.Second):
		t.Fatal("fake server did not receive SYN")
	}

	var early *handshakeResult
	select {
	case got := <-result:
		early = &got
	case <-time.After(50 * time.Millisecond):
	}
	close(sendValid)
	if early != nil {
		t.Fatalf("forged ACK terminated handshake early: sid=%08x err=%v", early.sid, early.err)
	}

	select {
	case got := <-result:
		if got.err != nil {
			t.Fatal(got.err)
		}
		if got.sid != 0x10203040 || got.keys == nil {
			t.Fatalf("handshake result sid=%08x keys=%v", got.sid, got.keys)
		}
	case <-time.After(time.Second):
		t.Fatal("valid ACK did not complete handshake")
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestClientFiltersForgedHandshakeACKBeforeCandidateQueue(t *testing.T) {
	var nonce [clientNonceSize]byte
	copy(nonce[:], "client-nonce-v2!")
	keys := DerivePSKHandshakeKeys("correct-psk", nonce)
	wrong := DerivePSKHandshakeKeys("wrong-psk", nonce)
	ch := make(chan *UDPCFrame, 1)
	client := &Client{
		magic: UDPC_MAGIC_DEFAULT,
		pendingAcks: map[[clientNonceSize]byte]*pendingHandshake{
			nonce: {ackMAC: keys.AckMAC, ch: ch},
		},
	}
	payload := append(append([]byte(nil), nonce[:]...), make([]byte, serverNonceSize)...)
	frameFor := func(key *[32]byte) *UDPCFrame {
		wire := SealFrameMAC(&UDPCFrame{
			Magic: UDPC_MAGIC_DEFAULT, Version: UDPC_VERSION,
			Cmd: CMD_HANDSHAKE_ACK, SessionID: 1, Data: payload,
		}, key)
		frame, err := DecodeUDPCFrame(wire, UDPC_MAGIC_DEFAULT)
		if err != nil {
			t.Fatal(err)
		}
		return frame
	}
	for i := 0; i < 32; i++ {
		client.dispatch(frameFor(&wrong.AckMAC))
	}
	if len(ch) != 0 {
		t.Fatal("forged ACK reached the bounded handshake queue")
	}
	client.dispatch(frameFor(&keys.AckMAC))
	if len(ch) != 1 {
		t.Fatal("authenticated ACK did not reach the handshake queue")
	}
}
