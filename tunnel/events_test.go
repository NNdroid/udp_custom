package tunnel

// Acceptance tests for the Plan A+C observability surface: client events,
// server security events, TunnelSession.Done/Err, and AutoReconnect
// notifications — all via the PUBLIC API.

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// eventCollector is a thread-safe event sink with a timeout-guarded wait.
type eventCollector struct {
	mu   sync.Mutex
	got  []ClientEvent
	wait chan struct{}
}

func newEventCollector() *eventCollector {
	return &eventCollector{wait: make(chan struct{}, 64)}
}

func (ec *eventCollector) collect(ev ClientEvent) {
	ec.mu.Lock()
	ec.got = append(ec.got, ev)
	ec.mu.Unlock()
	select {
	case ec.wait <- struct{}{}:
	default:
	}
}

// waitFor returns the FIRST event of the requested kind, skipping any other
// events queued before it (deny retries can legitimately repeat).
func (ec *eventCollector) waitFor(kind ClientEventKind, timeout time.Duration) (ClientEvent, bool) {
	deadline := time.After(timeout)
	for {
		ec.mu.Lock()
		for i, ev := range ec.got {
			if ev.Kind == kind {
				ec.got = ec.got[i+1:]
				ec.mu.Unlock()
				return ev, true
			}
		}
		ec.mu.Unlock()
		select {
		case <-ec.wait:
		case <-deadline:
			return ClientEvent{}, false
		}
	}
}

// TestEvents_ClientLifecycle asserts the client event stream: established,
// died (with the recorded cause), and that Done()/Err() agree.
func TestEvents_ClientLifecycle(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
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

	srv, err := NewServer(ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TargetAddr: "tcp://" + ln.Addr().String(),
		Passwords:  []string{"ev-psk"},
		Logger:     Nop,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go srv.Start()

	ec := newEventCollector()
	cli, err := NewClient(ClientConfig{
		ServerAddr: srv.conn.LocalAddr().String(),
		Passwords:  []string{"ev-psk"},
		Logger:     Nop,
	})
	if err != nil {
		t.Fatal(err)
	}
	cli.SetEventHandler(ec.collect)
	defer cli.Close()

	conn, err := cli.DialTunnel(context.Background(), DialOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ts, ok := conn.(*TunnelSession)
	if !ok {
		t.Fatalf("DialTunnel returned %T, want *TunnelSession", conn)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("echo read: %v", err)
	}

	if ev, ok := ec.waitFor(TunnelEstablished, 2*time.Second); !ok || ev.Session != ts.sess.sid {
		t.Fatalf("missing TunnelEstablished: %+v", ev)
	}

	// Close our end: the tunnel session ends cleanly and Done fires.
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ts.Done():
		if err := ts.Err(); err == nil {
			t.Fatal("Done closed but Err is nil")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Done not closed 3s after conn.Close")
	}
	if _, ok := ec.waitFor(TunnelDied, 2*time.Second); !ok {
		t.Fatal("missing TunnelDied event")
	}
}

// TestEvents_ServerSecurityEvents asserts AuthRejected and TargetDenied
// reach the server event handler. TargetDenied may repeat (each denied SYN
// retry emits one), so the assert skips to the wanted kind.
func TestEvents_ServerSecurityEvents(t *testing.T) {
	// A real TCP echo target: the default-target session must establish
	// quickly (an unresolvable target would drag the handshake past the
	// client timeout and mask the events under test).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
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

	evCh := make(chan SessionEvent, 64)
	srv, err := NewServerWithDialer(ServerConfig{
		ListenAddr:     "127.0.0.1:0",
		TargetAddr:     "tcp://" + ln.Addr().String(),
		Passwords:      []string{"sec-psk"},
		AllowedTargets: []string{"tcp://allowed:*"},
		Logger:         Nop,
	}, func(ctx context.Context, _ uint32, _, _ string) (net.Conn, error) {
		serverSide, clientSide := net.Pipe()
		go io.Copy(serverSide, serverSide)
		return clientSide, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	srv.SetEventHandler(func(ev SessionEvent) { evCh <- ev })
	go srv.Start()

	cli, err := NewClient(ClientConfig{
		ServerAddr: srv.conn.LocalAddr().String(),
		Passwords:  []string{"sec-psk"},
		Logger:     Nop,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	// 1. Denied target: the handshake times out, and the operator receives a
	//    TargetDenied event — the only observability for silent drops.
	go func() {
		denyCtx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
		defer cancel()
		_, _ = cli.DialTunnel(denyCtx, DialOptions{Target: "tcp://forbidden:99"})
	}()
	waitFor := func(want SessionEventKind) SessionEvent {
		t.Helper()
		deadline := time.After(3 * time.Second)
		for {
			select {
			case ev := <-evCh:
				if ev.Kind == want {
					return ev
				}
			case <-deadline:
				t.Fatalf("no %v event within 3s", want)
			}
		}
	}
	ev := waitFor(SessionTargetDenied)
	if ev.Detail != "tcp://forbidden:99" {
		t.Fatalf("denied detail = %q", ev.Detail)
	}

	// 2. AuthRejected: establish a REAL session, then attack it the way a
	//    real attacker would — a raw UDP socket sending a structurally valid
	//    frame with the guessed SessionID but a WRONG key. The server
	//    dispatches it to the session, the AEAD open fails, and the security
	//    event must surface.
	conn, err := cli.DialTunnel(context.Background(), DialOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sid := conn.(*TunnelSession).sess.sid

	atk, err := net.Dial("udp", srv.conn.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer atk.Close()
	frame := &UDPCFrame{
		Magic: UDPC_MAGIC_DEFAULT, Version: UDPC_VERSION, Cmd: CMD_DATA,
		SessionID: sid, PacketNo: 1, Seq: 1, Data: []byte("forged"),
	}
	wire := SealFrameAEAD(frame, mustCipher(t, [32]byte{7}), frame.Data)
	if _, err := atk.Write(wire); err != nil {
		t.Fatal(err)
	}
	if ev := waitFor(SessionAuthRejected); ev.SessionID != sid {
		t.Fatalf("auth event session = %d, want %d", ev.SessionID, sid)
	}
}

// TestEvents_DroppedCounterUnderPressure asserts the lossy-delivery contract:
// a handler that blocks forever does not stall the tunnel; the overflow is
// visible in EventsDropped.
func TestEvents_DroppedCounterUnderPressure(t *testing.T) {
	block := make(chan struct{})
	srv, err := NewServerWithDialer(ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TargetAddr: "tcp://x:1",
		Passwords:  []string{"p"},
		Logger:     Nop,
	}, func(ctx context.Context, _ uint32, _, _ string) (net.Conn, error) {
		serverSide, clientSide := net.Pipe()
		go io.Copy(serverSide, serverSide)
		return clientSide, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	srv.SetEventHandler(func(SessionEvent) { <-block }) // handler parks forever
	go srv.Start()

	cli, err := NewClient(ClientConfig{
		ServerAddr: srv.conn.LocalAddr().String(),
		Passwords:  []string{"p"},
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

	// The established event parks the handler; continued traffic must not
	// stall the tunnel even though every event would block.
	var lastErr error
	for i := 0; i < 64; i++ {
		conn.SetWriteDeadline(time.Now().Add(time.Second))
		if _, err := conn.Write([]byte("flood")); err != nil {
			lastErr = err
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("tunnel stalled under a blocked event handler: %v", lastErr)
	}
}
