package tunnel

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestAPI_SentinelErrors verifies the errors.Is contract embedders rely on.
func TestAPI_SentinelErrors(t *testing.T) {
	// DialTunnel after Close must return ErrClosed (matchable via errors.Is).
	srv, err := NewServer(ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TargetAddr: "tcp://127.0.0.1:1",
		Passwords:  []string{"sentinel-psk"},
		Logger:     Nop,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go srv.Start()

	cli, err := NewClient(ClientConfig{
		ServerAddr: srv.conn.LocalAddr().String(),
		Passwords:  []string{"sentinel-psk"},
		Logger:     Nop,
	})
	if err != nil {
		t.Fatal(err)
	}
	cli.Close()
	if _, err := cli.DialTunnel(context.Background(), DialOptions{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("DialTunnel after Close = %v, want ErrClosed", err)
	}

	// Handshake timeout against a black hole must wrap ErrHandshakeTimeout.
	blackhole, err := NewClient(ClientConfig{
		// RFC 5737 TEST-NET-1: never routable, so every SYN is lost.
		ServerAddr: "192.0.2.1:36712",
		Passwords:  []string{"sentinel-psk"},
		Logger:     Nop,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer blackhole.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	if _, err := blackhole.DialTunnel(ctx, DialOptions{}); !errors.Is(err, ErrHandshakeTimeout) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DialTunnel to black hole = %v, want ErrHandshakeTimeout or DeadlineExceeded", err)
	}

	// ClientStats must report the spread geometry.
	if st := cli.Stats(); st.Sockets < 1 {
		t.Fatalf("Stats().Sockets = %d, want >= 1", st.Sockets)
	}
}

func TestAutoReconnectCloseCancelsHandshake(t *testing.T) {
	cli, err := NewClient(ClientConfig{
		ServerAddr: "192.0.2.1:36712",
		Passwords:  []string{"cancel-psk"},
		Logger:     Nop,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	tun := NewAutoReconnect(cli, DialOptions{}, nil)
	done := make(chan error, 1)
	go func() {
		_, err := tun.Write([]byte("blocked handshake"))
		done <- err
	}()
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	if err := tun.Close(); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Close took %v while handshake was in flight", elapsed)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("blocked Write unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("blocked Write was not cancelled")
	}
}
