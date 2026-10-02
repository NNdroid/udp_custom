package tunnel

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type signalledWriteConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func TestConcurrentServerStartIsIdempotent(t *testing.T) {
	srv, err := NewServerWithDialer(ServerConfig{ListenAddr: "127.0.0.1:0", TargetAddr: "tcp://echo:1", Passwords: []string{"start-test-secret"}, Logger: Nop}, func(context.Context, uint32, string, string) (net.Conn, error) {
		a, b := net.Pipe()
		go func() { defer b.Close(); _, _ = io.Copy(b, b) }()
		return a, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	var starts sync.WaitGroup
	for i := 0; i < 8; i++ {
		starts.Add(1)
		go func() {
			defer starts.Done()
			if err := srv.Start(); err != nil {
				t.Error(err)
			}
		}()
	}
	off := false
	c, err := NewClient(ClientConfig{ServerAddr: srv.conn.LocalAddr().String(), Passwords: []string{"start-test-secret"}, Logger: Nop, MtuProbe: &off})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := c.DialTunnel(ctx, DialOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	want := []byte("one reader per socket")
	if _, err = conn.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err = io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("stream corruption")
	}
	srv.Close()
	starts.Wait()
}

func (c *signalledWriteConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Write(p)
}

func TestStalledBackendDoesNotBlockSharedReceiver(t *testing.T) {
	started := make(chan struct{})
	var peersMu sync.Mutex
	var peers []net.Conn
	dial := func(ctx context.Context, sid uint32, network, address string) (net.Conn, error) {
		a, b := net.Pipe()
		peersMu.Lock()
		peers = append(peers, b)
		peersMu.Unlock()
		if address == "slow:1" {
			return &signalledWriteConn{Conn: a, started: started}, nil
		}
		go func() { defer b.Close(); _, _ = io.Copy(b, b) }()
		return a, nil
	}
	srv, err := NewServerWithDialer(ServerConfig{ListenAddr: "127.0.0.1:0", TargetAddr: "tcp://fast:1", AllowedTargets: []string{"tcp://slow:1"}, Passwords: []string{"stability-test-secret"}, Logger: Nop}, dial)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go srv.Start()
	defer func() {
		peersMu.Lock()
		defer peersMu.Unlock()
		for _, p := range peers {
			p.Close()
		}
	}()
	off := false
	c, err := NewClient(ClientConfig{ServerAddr: srv.conn.LocalAddr().String(), Passwords: []string{"stability-test-secret"}, Logger: Nop, MtuProbe: &off, FEC: &off})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	slow, err := c.DialTunnel(context.Background(), DialOptions{Target: "tcp://slow:1"})
	if err != nil {
		t.Fatal(err)
	}
	defer slow.Close()
	if _, err = slow.Write([]byte("never read by backend")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("slow backend write not reached")
	}
	fast, err := c.DialTunnel(context.Background(), DialOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer fast.Close()
	fast.SetDeadline(time.Now().Add(time.Second))
	want := []byte("unrelated session stays responsive")
	if _, err = fast.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err = io.ReadFull(fast, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("echo=%q", got)
	}
}

func TestStalledApplicationDoesNotBlockSharedReceiver(t *testing.T) {
	srv, err := NewServerWithDialer(ServerConfig{ListenAddr: "127.0.0.1:0", TargetAddr: "tcp://echo:1", Passwords: []string{"stability-test-secret"}, Logger: Nop}, func(context.Context, uint32, string, string) (net.Conn, error) {
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
	c, err := NewClient(ClientConfig{ServerAddr: srv.conn.LocalAddr().String(), Passwords: []string{"stability-test-secret"}, Logger: Nop, MtuProbe: &off, FEC: &off})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	slow, err := c.DialTunnel(context.Background(), DialOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer slow.Close()
	if _, err = slow.Write([]byte("application does not read this echo")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		pending := false
		c.sessions.Range(func(_, v any) bool {
			s := v.(*clientSession)
			s.delivery.mu.Lock()
			pending = pending || len(s.delivery.pending) > 0
			s.delivery.mu.Unlock()
			return true
		})
		if pending {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("slow application did not receive pending data")
		}
		time.Sleep(time.Millisecond)
	}
	fast, err := c.DialTunnel(context.Background(), DialOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer fast.Close()
	fast.SetDeadline(time.Now().Add(time.Second))
	want := []byte("same client socket remains responsive")
	if _, err = fast.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err = io.ReadFull(fast, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q", got)
	}
}

func TestRecoveryNegotiationFallback(t *testing.T) {
	for _, which := range []string{"client", "server", "both"} {
		t.Run(which, func(t *testing.T) {
			off := false
			sc := ServerConfig{ListenAddr: "127.0.0.1:0", TargetAddr: "tcp://echo:1", Passwords: []string{"compatibility-secret"}, Logger: Nop}
			if which == "server" || which == "both" {
				sc.Recovery = &off
			}
			srv, err := NewServerWithDialer(sc, func(context.Context, uint32, string, string) (net.Conn, error) {
				a, b := net.Pipe()
				go func() { defer b.Close(); _, _ = io.Copy(b, b) }()
				return a, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer srv.Close()
			go srv.Start()
			cc := ClientConfig{ServerAddr: srv.conn.LocalAddr().String(), Passwords: sc.Passwords, Logger: Nop, MtuProbe: &off}
			if which == "client" || which == "both" {
				cc.Recovery = &off
			}
			c, err := NewClient(cc)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			conn, err := c.DialTunnel(context.Background(), DialOptions{})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			c.sessions.Range(func(_, v any) bool {
				if v.(*clientSession).flow != nil {
					t.Error("unnegotiated recovery enabled")
				}
				return true
			})
			srv.sessions.Range(func(_, v any) bool {
				if v.(*ServerSession).flow != nil {
					t.Error("server enabled unnegotiated recovery")
				}
				return true
			})
			conn.SetDeadline(time.Now().Add(time.Second))
			msg := []byte("legacy wire layout still works")
			_, err = conn.Write(msg)
			if err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(msg))
			if _, err = io.ReadFull(conn, got); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(msg, got) {
				t.Fatal("stream mismatch")
			}
		})
	}
}
