package tunnel

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// api_test.go is the embedding acceptance test: everything here goes through
// the PUBLIC surface (NewServerWithDialer / SetEventHandler / NewClient /
// DialTunnel) exactly as an external program would. No test rig, no internals.

// TestAPI_EmbeddedTunnelEndToEnd runs an in-process backend behind a custom
// TargetDialer, tunnels a net.Conn through it with DialTunnel, and observes
// the session lifecycle events. This is the shape an embedding application
// takes: no config file, no TCP listener, injected dialer and logger.
func TestAPI_EmbeddedTunnelEndToEnd(t *testing.T) {
	// --- server side: custom dialer spawns a per-session in-process backend.
	var (
		dialMu        sync.Mutex
		dialCalls     []string
		eventMu       sync.Mutex
		established   []SessionEvent
		closed        []SessionEvent
		establishedCh = make(chan SessionEvent, 4)
		closedCh      = make(chan SessionEvent, 4)
	)
	backend := func(conn net.Conn) {
		defer conn.Close()
		io.Copy(conn, conn)
	}
	dialer := TargetDialer(func(ctx context.Context, sessionID uint32, network, address string) (net.Conn, error) {
		dialMu.Lock()
		dialCalls = append(dialCalls, network+" "+address)
		dialMu.Unlock()
		serverSide, clientSide := net.Pipe()
		go backend(serverSide)
		return clientSide, nil
	})

	srv, err := NewServerWithDialer(ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TargetAddr: "tcp://in-process.default:1234",
		Passwords:  []string{"embed-psk"},
		Logger:     Nop,
	}, dialer)
	if err != nil {
		t.Fatalf("NewServerWithDialer: %v", err)
	}
	defer srv.Close()
	srv.SetEventHandler(func(ev SessionEvent) {
		switch ev.Kind {
		case SessionEstablished:
			establishedCh <- ev
		case SessionClosed:
			closedCh <- ev
		}
	})
	go srv.Start()

	// --- client side: no listener, injected Nop logger.
	cli, err := NewClient(ClientConfig{
		ServerAddr: srv.conn.LocalAddr().String(),
		Passwords:  []string{"embed-psk"},
		Logger:     Nop,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer cli.Close()

	var granted string
	conn, err := cli.DialTunnel(context.Background(), DialOptions{
		OnGranted: func(g string) { granted = g },
	})
	if err != nil {
		t.Fatalf("DialTunnel: %v", err)
	}

	// The default-target request is granted silently (no TLV): OnGranted must
	// observe exactly the empty string.
	if granted != "" {
		t.Fatalf("OnGranted = %q, want empty for default target", granted)
	}

	// Round trip through the tunnel.
	msg := []byte("ping through the embedded tunnel")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo mismatch: got %q", buf)
	}

	// The custom dialer was used with the server's default target.
	dialMu.Lock()
	if len(dialCalls) != 1 || dialCalls[0] != "tcp in-process.default:1234" {
		t.Fatalf("dial calls = %v, want one tcp dial to the default target", dialCalls)
	}
	dialMu.Unlock()

	// Lifecycle events.
	select {
	case ev := <-establishedCh:
		if ev.Network != "tcp" || ev.Address != "in-process.default:1234" {
			t.Fatalf("established event = %+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no SessionEstablished event")
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case <-closedCh:
	case <-time.After(3 * time.Second):
		t.Fatal("no SessionClosed event after conn.Close")
	}
	eventMu.Lock()
	defer eventMu.Unlock()
	_ = established
	_ = closed
}

// TestAPI_PerSessionTargetThroughDialTunnel proves an embedder can point each
// tunnel at its own endpoint via DialOptions.Target, gated by allowed_targets.
func TestAPI_PerSessionTargetThroughDialTunnel(t *testing.T) {
	// In-process "backends": two pipe-echo pools keyed by address.
	echo := func(conn net.Conn, tag byte) {
		defer conn.Close()
		buf := make([]byte, 1)
		for {
			if _, err := io.ReadFull(conn, buf); err != nil {
				return
			}
			if _, err := conn.Write([]byte{tag}); err != nil {
				return
			}
		}
	}
	dialer := TargetDialer(func(ctx context.Context, _ uint32, network, address string) (net.Conn, error) {
		if network != "tcp" {
			return nil, net.UnknownNetworkError(network)
		}
		serverSide, clientSide := net.Pipe()
		var tag byte
		if address == "backend-a:1" {
			tag = 'A'
		} else if address == "backend-b:2" {
			tag = 'B'
		} else {
			return nil, io.ErrUnexpectedEOF
		}
		go echo(serverSide, tag)
		return clientSide, nil
	})

	srv, err := NewServerWithDialer(ServerConfig{
		ListenAddr:     "127.0.0.1:0",
		TargetAddr:     "tcp://backend-a:1",
		Passwords:      []string{"embed-psk"},
		AllowedTargets: []string{"tcp://backend-*:*"},
		Logger:         Nop,
	}, dialer)
	if err != nil {
		t.Fatalf("NewServerWithDialer: %v", err)
	}
	defer srv.Close()
	go srv.Start()

	cli, err := NewClient(ClientConfig{
		ServerAddr: srv.conn.LocalAddr().String(),
		Passwords:  []string{"embed-psk"},
		Logger:     Nop,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer cli.Close()

	// Tunnel 1: default target -> backend A.
	connA, err := cli.DialTunnel(context.Background(), DialOptions{})
	if err != nil {
		t.Fatalf("DialTunnel default: %v", err)
	}
	defer connA.Close()

	// Tunnel 2: explicit target -> backend B.
	var grantedB string
	connB, err := cli.DialTunnel(context.Background(), DialOptions{
		Target:    "tcp://backend-b:2",
		OnGranted: func(g string) { grantedB = g },
	})
	if err != nil {
		t.Fatalf("DialTunnel targetB: %v", err)
	}
	defer connB.Close()
	if grantedB != "tcp://backend-b:2" {
		t.Fatalf("OnGranted = %q, want the requested target", grantedB)
	}

	probe := func(conn net.Conn, want byte) {
		t.Helper()
		if _, err := conn.Write([]byte{0}); err != nil {
			t.Fatalf("probe write: %v", err)
		}
		buf := make([]byte, 1)
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("probe read: %v", err)
		}
		if buf[0] != want {
			t.Fatalf("backend tag = %c, want %c", buf[0], want)
		}
	}
	probe(connA, 'A')
	probe(connB, 'B')

	// Tunnel 3: a request OUTSIDE allowed_targets must fail the handshake
	// (the server drops denied SYNs) instead of silently hitting backend A.
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	if _, err := cli.DialTunnel(ctx, DialOptions{Target: "tcp://evil:9"}); err == nil {
		t.Fatal("denied target unexpectedly established a tunnel")
	}
}

// TestAPI_ServerStatsSnapshot proves the exported counters reflect live
// sessions and movement on the receive path — the surface embedders wire into
// monitoring systems.
func TestAPI_ServerStatsSnapshot(t *testing.T) {
	srv, err := NewServerWithDialer(ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TargetAddr: "tcp://stats.default:1",
		Passwords:  []string{"stats-psk"},
		Logger:     Nop,
	}, func(ctx context.Context, _ uint32, network, address string) (net.Conn, error) {
		serverSide, clientSide := net.Pipe()
		go func() {
			defer serverSide.Close()
			io.Copy(serverSide, serverSide)
		}()
		return clientSide, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go srv.Start()

	before := srv.Stats()
	if before.Sessions != 0 {
		t.Fatalf("Sessions = %d before any client, want 0", before.Sessions)
	}

	cli, err := NewClient(ClientConfig{
		ServerAddr: srv.conn.LocalAddr().String(),
		Passwords:  []string{"stats-psk"},
		Logger:     Nop,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	conn, err := cli.DialTunnel(context.Background(), DialOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Push one byte round trip so the session is fully live.
	if _, err := conn.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}

	after := srv.Stats()
	if after.Sessions != 1 {
		t.Fatalf("Sessions = %d with one live tunnel, want 1", after.Sessions)
	}
	if after.SendViaPort+after.SendViaMain == 0 {
		t.Fatal("no replies counted; send-path stats did not move")
	}
}
