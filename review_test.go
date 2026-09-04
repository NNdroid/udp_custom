package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDecodeUDPCFrameRejectsInvalidEnvelope(t *testing.T) {
	base := (&UDPCFrame{
		Magic: UDPC_MAGIC_DEFAULT, Version: UDPC_VERSION, Cmd: CMD_DATA,
		SessionID: 1, Seq: 1, Data: []byte("payload"),
	}).Encode()

	tests := []struct {
		name string
		wire []byte
	}{
		{name: "trailing bytes", wire: append(append([]byte(nil), base...), 0)},
		{name: "unsupported version", wire: func() []byte {
			p := append([]byte(nil), base...)
			p[4]++
			return p
		}()},
		{name: "unknown command", wire: func() []byte {
			p := append([]byte(nil), base...)
			p[5] = 0xff
			return p
		}()},
		{name: "oversized packet", wire: (&UDPCFrame{
			Magic: UDPC_MAGIC_DEFAULT, Version: UDPC_VERSION, Cmd: CMD_DATA,
			Data: make([]byte, UDPC_MAX_PKT-UDPC_HDR_SIZE-4+1),
		}).Encode()},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeUDPCFrame(tc.wire, UDPC_MAGIC_DEFAULT); err == nil {
				t.Fatal("expected malformed frame to be rejected")
			}
		})
	}
}

func TestDecodeUDPCFrameRejectsChecksumMismatch(t *testing.T) {
	wire := (&UDPCFrame{
		Magic: UDPC_MAGIC_DEFAULT, Version: UDPC_VERSION, Cmd: CMD_DATA,
		SessionID: 1, Seq: 1, Data: []byte("payload"),
	}).Encode()
	wire[UDPC_HDR_SIZE] ^= 0xff
	if _, err := DecodeUDPCFrame(wire, UDPC_MAGIC_DEFAULT); err == nil {
		t.Fatal("expected checksum mismatch")
	}
}

func TestDecodeOwnershipModes(t *testing.T) {
	wire := (&UDPCFrame{
		Magic: UDPC_MAGIC_DEFAULT, Version: UDPC_VERSION, Cmd: CMD_DATA,
		Data: []byte("owned"),
	}).Encode()

	public, err := DecodeUDPCFrame(wire, UDPC_MAGIC_DEFAULT)
	if err != nil {
		t.Fatal(err)
	}
	var borrowed UDPCFrame
	if err := decodeUDPCFrame(wire, UDPC_MAGIC_DEFAULT, &borrowed); err != nil {
		t.Fatal(err)
	}
	wire[UDPC_HDR_SIZE] = 'X'
	if string(public.Data) != "owned" {
		t.Fatalf("public decoder must own Data, got %q", public.Data)
	}
	if borrowed.Data[0] != 'X' {
		t.Fatal("internal decoder should borrow the read buffer")
	}
}

func TestNoiseControlFramesCannotHijackSession(t *testing.T) {
	rig := newTestRig(t, true)
	evil := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 9999}

	rig.sess.unacked[1] = &unackedPkt{firstSent: time.Now(), sentTime: time.Now()}
	rig.sess.activeMu.Lock()
	lastActive := rig.sess.lastActive
	rig.sess.activeMu.Unlock()

	rig.sess.handleIncomingFrame(&UDPCFrame{Cmd: CMD_ACK, Ack: 1}, evil, 45678)
	if len(rig.sess.unacked) != 1 {
		t.Fatal("unauthenticated cross-IP ACK removed an in-flight frame")
	}
	rig.sess.handleIncomingFrame(&UDPCFrame{Cmd: CMD_FIN}, evil, 45678)
	if atomic.LoadInt32(&rig.sess.closed) != 0 {
		t.Fatal("unauthenticated cross-IP FIN closed a Noise session")
	}
	if !sameAddr(rig.sess.getRemoteAddr(), rig.clientAddr) {
		t.Fatalf("attacker changed remote address to %v", rig.sess.getRemoteAddr())
	}
	if _, ok := rig.sess.pathAddrs[45678]; ok {
		t.Fatal("attacker installed a reply path")
	}
	rig.sess.activeMu.Lock()
	activeChanged := !rig.sess.lastActive.Equal(lastActive)
	rig.sess.activeMu.Unlock()
	if activeChanged {
		t.Fatal("rejected control frames must not keep a session alive")
	}

	// A bad DATA frame must not be able to install the same poisoned path.
	rig.sess.handleDataFromPath(rig.makeDataFrame(1, []byte("bad"), false), evil, 45678)
	if _, ok := rig.sess.pathAddrs[45678]; ok {
		t.Fatal("undecryptable DATA installed a reply path")
	}
}

func TestNoiseSameIPControlAllowsPortRebinding(t *testing.T) {
	rig := newTestRig(t, true)
	rebound := &net.UDPAddr{IP: append(net.IP(nil), rig.clientAddr.IP...), Port: rig.clientAddr.Port + 1}
	rig.sess.unacked[1] = &unackedPkt{firstSent: time.Now(), sentTime: time.Now()}

	rig.sess.handleIncomingFrame(&UDPCFrame{Cmd: CMD_ACK, Ack: 1}, rebound, 45679)
	if len(rig.sess.unacked) != 0 {
		t.Fatal("same-IP ACK should be accepted for NAT rebinding")
	}
	if !sameAddr(rig.sess.getRemoteAddr(), rebound) {
		t.Fatalf("remote address = %v, want %v", rig.sess.getRemoteAddr(), rebound)
	}
	if got := rig.sess.pathAddrs[45679]; !sameAddr(got, rebound) {
		t.Fatalf("rebound path = %v, want %v", got, rebound)
	}
}

func TestNoiseRejectsPoisonedOutOfOrderSlot(t *testing.T) {
	rig := newTestRig(t, true)

	rig.sess.handleData(rig.makeDataFrame(2, []byte("poison"), false), rig.clientAddr)
	if _, ok := rig.sess.recvQueue[2]; ok {
		t.Fatal("undecryptable out-of-order frame entered the reorder queue")
	}
	rig.sess.handleData(rig.makeDataFrame(2, []byte("second"), true), rig.clientAddr)
	if _, ok := rig.sess.recvQueue[2]; !ok {
		t.Fatal("authenticated out-of-order frame was not queued")
	}
	rig.sess.handleData(rig.makeDataFrame(1, []byte("first"), true), rig.clientAddr)
	if got := string(rig.waitForTargetBytes(11, time.Second)); got != "firstsecond" {
		t.Fatalf("target got %q", got)
	}
	if ack := rig.recvFrame(time.Second); ack.Ack != 2 {
		t.Fatalf("ACK = %d, want 2", ack.Ack)
	}
}

type recordingConn struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *recordingConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *recordingConn) Close() error                     { return nil }
func (c *recordingConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *recordingConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *recordingConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingConn) SetWriteDeadline(time.Time) error { return nil }
func (c *recordingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}
func (c *recordingConn) Bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf.Bytes()...)
}

func TestClientConcurrentDuplicateDeliveredOnce(t *testing.T) {
	conn := &recordingConn{}
	client := &Client{
		magic: UDPC_MAGIC_DEFAULT, logLevel: LogLevelError,
		dialer: &SpreadDialer{closed: 1},
	}
	sess := &clientSession{
		client: client, sid: 7, conn: conn, sendSeq: 1, recvSeq: 1,
		recvQueue: make(map[uint32][]byte), closeChan: make(chan struct{}),
		lastActive: time.Now(),
	}
	frame := &UDPCFrame{Cmd: CMD_DATA, SessionID: 7, Seq: 1, Data: []byte("once")}

	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			sess.handleData(frame)
		}()
	}
	close(start)
	wg.Wait()
	if got := string(conn.Bytes()); got != "once" {
		t.Fatalf("application received %q, want one copy", got)
	}
}

type oneByteWriter struct{ out []byte }

func (w *oneByteWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	w.out = append(w.out, p[0])
	return 1, nil
}

func TestWriteAllHandlesShortWrites(t *testing.T) {
	w := &oneByteWriter{}
	if err := writeAll(w, []byte("complete")); err != nil {
		t.Fatal(err)
	}
	if string(w.out) != "complete" {
		t.Fatalf("wrote %q", w.out)
	}
}

func TestDecryptStunURIRejectsMalformedEnvelopes(t *testing.T) {
	encode := func(env shareEnvelope) string {
		b, err := json.Marshal(env)
		if err != nil {
			t.Fatal(err)
		}
		return "stun://" + base64.StdEncoding.EncodeToString(b)
	}
	validSalt := base64.StdEncoding.EncodeToString(make([]byte, shareSaltLen))
	validIV := base64.StdEncoding.EncodeToString(make([]byte, shareIvLen))
	validCT := base64.StdEncoding.EncodeToString(make([]byte, 16))

	cases := []string{
		"stun://not-base64",
		encode(shareEnvelope{V: 1, G: 2, S: validSalt, I: validIV, C: validCT}),
		encode(shareEnvelope{V: 1, S: base64.StdEncoding.EncodeToString([]byte{1}), I: validIV, C: validCT}),
		encode(shareEnvelope{V: 1, S: validSalt, I: base64.StdEncoding.EncodeToString([]byte{1}), C: validCT}),
		encode(shareEnvelope{V: 1, S: validSalt, I: validIV, C: base64.StdEncoding.EncodeToString([]byte{1})}),
	}
	for i, payload := range cases {
		if _, err := decryptStunURI(payload, "123456"); err == nil {
			t.Fatalf("case %d: expected malformed envelope to fail", i)
		}
	}

	compressed, err := gzipData(make([]byte, shareMaxSize+1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gunzipData(compressed); err == nil {
		t.Fatal("expected decompressed size limit to be enforced")
	}
}

func TestParseNoiseKeyErrorDoesNotEchoSecret(t *testing.T) {
	secret := "not-a-key-but-do-not-log-me"
	if _, err := ParseNoiseKey(secret); err == nil || bytes.Contains([]byte(err.Error()), []byte(secret)) {
		t.Fatalf("error should reject without echoing key material: %v", err)
	}
}

func TestNewPortRangeValidatesAndDeduplicates(t *testing.T) {
	pr, err := NewPortRange([]int{10, 11, 10, 12, 12})
	if err != nil {
		t.Fatal(err)
	}
	if pr.Total() != 3 || pr.String() != "10-12" {
		t.Fatalf("range = %s total=%d, want 10-12 total=3", pr, pr.Total())
	}
	for _, ports := range [][]int{{0}, {65536}, {1, 70000}} {
		if _, err := NewPortRange(ports); err == nil {
			t.Fatalf("expected invalid ports %v to fail", ports)
		}
	}
}

func TestPickPortsFromLargeRangeIsUnique(t *testing.T) {
	ports := make([]int, 65535)
	for i := range ports {
		ports[i] = i + 1
	}
	pr, err := NewPortRange(ports)
	if err != nil {
		t.Fatal(err)
	}
	got := pickPortsFromRange(pr, 64)
	if len(got) != 64 {
		t.Fatalf("picked %d ports, want 64", len(got))
	}
	seen := make(map[int]bool, len(got))
	for _, port := range got {
		if port < 1 || port > 65535 || seen[port] {
			t.Fatalf("invalid or duplicate selected port %d", port)
		}
		seen[port] = true
	}
}

func TestSpreadDialerResolvesHostnameOnce(t *testing.T) {
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.LocalAddr().(*net.UDPAddr).Port
	d, err := NewSpreadDialer(net.JoinHostPort("localhost", strconv.Itoa(port)), 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := d.Send([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	_ = listener.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := listener.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "ok" {
		t.Fatalf("received %q", buf[:n])
	}
}

func TestSpreadDialerSupportsIPv6(t *testing.T) {
	listener, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer listener.Close()
	port := listener.LocalAddr().(*net.UDPAddr).Port
	d, err := NewSpreadDialer(net.JoinHostPort("::1", strconv.Itoa(port)), 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := d.Send([]byte("v6")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	_ = listener.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := listener.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "v6" {
		t.Fatalf("received %q", buf[:n])
	}
}

func FuzzDecodeUDPCFrameNeverPanics(f *testing.F) {
	valid := (&UDPCFrame{Magic: UDPC_MAGIC_DEFAULT, Version: UDPC_VERSION, Cmd: CMD_DATA, Data: []byte("seed")}).Encode()
	f.Add(valid)
	f.Add([]byte{})
	f.Add(make([]byte, UDPC_MAX_PKT+1))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeUDPCFrame(data, UDPC_MAGIC_DEFAULT)
	})
}

func BenchmarkDecodeUDPCFrameBorrowed(b *testing.B) {
	wire := (&UDPCFrame{
		Magic: UDPC_MAGIC_DEFAULT, Version: UDPC_VERSION, Cmd: CMD_DATA,
		SessionID: 1, Seq: 1, Data: benchPayload,
	}).Encode()
	var frame UDPCFrame
	b.ReportAllocs()
	b.SetBytes(int64(len(benchPayload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := decodeUDPCFrame(wire, UDPC_MAGIC_DEFAULT, &frame); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPickPortsFromLargeRange(b *testing.B) {
	pr := &PortRange{intervals: []portInterval{{lo: 1, hi: 65535}}, total: 65535}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if got := pickPortsFromRange(pr, 32); len(got) != 32 {
			b.Fatal("unexpected selection")
		}
	}
}
