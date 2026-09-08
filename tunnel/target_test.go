package tunnel

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// --- wildcard matcher ---------------------------------------------------------

func TestMatchTargetPattern(t *testing.T) {
	cases := []struct {
		pattern  string
		endpoint string
		want     bool
	}{
		{"tcp://127.0.0.1:22", "tcp://127.0.0.1:22", true},
		{"tcp://127.0.0.1:22", "tcp://127.0.0.1:23", false},
		{"tcp://127.0.0.1:*", "tcp://127.0.0.1:443", true},
		{"tcp://127.0.0.1:*", "tcp://127.0.0.2:443", false},
		{"tcp://*.internal:22", "tcp://host1.internal:22", true},
		{"tcp://*.internal:22", "tcp://host1.external:22", false},
		// '*' spans dots and any sequence:
		{"tcp://*:22", "tcp://a.b.c.d:22", true},
		{"udp://*:51820", "udp://10.0.0.5:51820", true},
		{"udp://*:51820", "tcp://10.0.0.5:51820", false}, // network must match
		{"tcp://db?.prod:5432", "tcp://db1.prod:5432", true},
		{"tcp://db?.prod:5432", "tcp://db12.prod:5432", false},
		{"tcp://127.0.0.1:*", "udp://127.0.0.1:22", false},
		{"TCP://EXAMPLE.com:*", "tcp://example.COM:8080", true}, // case-insensitive host
	}
	for _, tc := range cases {
		if got := matchTargetPattern(tc.pattern, tc.endpoint); got != tc.want {
			t.Errorf("matchTargetPattern(%q, %q) = %v, want %v", tc.pattern, tc.endpoint, got, tc.want)
		}
	}
}

func TestTargetAllowedEmptyListDeniesEverything(t *testing.T) {
	if targetAllowed("tcp://127.0.0.1:22", nil) {
		t.Fatal("empty allowed_targets must deny every request")
	}
	if targetAllowed("tcp://127.0.0.1:22", []string{"  "}) {
		t.Fatal("blank pattern entries must not allow anything")
	}
	if !targetAllowed("tcp://127.0.0.1:22", []string{"tcp://127.0.0.1:*"}) {
		t.Fatal("matching pattern must allow the request")
	}
}

// --- TLV codec ----------------------------------------------------------------

func TestTargetTLVRoundTripAndBounds(t *testing.T) {
	if got := appendTargetTLV(nil, ""); len(got) != 0 {
		t.Fatalf("empty target must encode to no TLV, got %x", got)
	}
	payload := appendTargetTLV(nil, "tcp://127.0.0.1:22")
	got, ok := parseTargetTLV(payload)
	if !ok || got != "tcp://127.0.0.1:22" {
		t.Fatalf("round trip = %q ok=%v", got, ok)
	}
	// Truncated, zero-length, over-long and overshooting length prefixes all
	// fail the strict parse.
	for i, bad := range [][]byte{
		{0x00},
		{0x00, 0x05, 'a'},
		{0x00, 0x00},
		{0x01, 0x00, 'x'},
	} {
		if _, ok := parseTargetTLV(bad); ok {
			t.Fatalf("case %d: malformed TLV %x accepted", i, bad)
		}
	}
	oversize := make([]byte, 2+TargetMaxLen+1)
	binary.BigEndian.PutUint16(oversize, TargetMaxLen+1)
	if _, ok := parseTargetTLV(oversize); ok {
		t.Fatal("oversize target TLV must be rejected")
	}
}

func TestSplitSynPayloadWithAndWithoutTarget(t *testing.T) {
	var nonce [clientNonceSize]byte
	base := make([]byte, synPayloadBase)
	copy(base, nonce[:])

	// Base only: default target, no noise.
	target, msg1, err := splitSynPayload(base, false)
	if err != nil || target != "" || msg1 != nil {
		t.Fatalf("base-only syn: target=%q msg1=%v err=%v", target, msg1, err)
	}

	// Target TLV appended after base.
	withTLV := append(append([]byte(nil), base...), requestedTargetTLV("tcp://127.0.0.1:8080")...)
	target, msg1, err = splitSynPayload(withTLV, false)
	if err != nil || target != "tcp://127.0.0.1:8080" || msg1 != nil {
		t.Fatalf("tlv syn: target=%q err=%v", target, err)
	}

	// Noise msg1 sits AFTER the TLV and is peeled off the tail.
	msg1 = make([]byte, noiseMsg1Size)
	full := append(append([]byte(nil), withTLV...), msg1...)
	target, gotMsg1, err := splitSynPayload(full, true)
	if err != nil || target != "tcp://127.0.0.1:8080" || len(gotMsg1) != noiseMsg1Size {
		t.Fatalf("tlv+noise syn: target=%q msg1Len=%d err=%v", target, len(gotMsg1), err)
	}

	// Garbage between base and (optional) msg1 is rejected.
	junk := append(append([]byte(nil), base...), 0xde, 0xad)
	if _, _, err := splitSynPayload(junk, false); err == nil {
		t.Fatal("junk payload must be rejected")
	}
}

// --- e2e: per-session target selection ----------------------------------------

// buildTestSYNWithTarget is buildTestSYN plus a target request TLV.
func buildTestSYNWithTarget(tb testing.TB, psk, target string, noiseMsg1 []byte) ([]byte, [clientNonceSize]byte, PSKHandshakeKeys) {
	tb.Helper()
	wire, clientNonce, keys := buildTestSYN(tb, psk, noiseMsg1)
	// Rebuild with the TLV: the frame MAC covers the payload, so the sealed
	// bytes must be produced with the target already in place.
	frame, err := DecodeUDPCFrame(wire, UDPC_MAGIC_DEFAULT)
	if err != nil {
		tb.Fatal(err)
	}
	payload := make([]byte, 0, len(frame.Data)+2+len(target))
	payload = append(payload, frame.Data[:synPayloadBase]...)
	payload = appendTargetTLV(payload, target)
	payload = append(payload, frame.Data[synPayloadBase:]...)
	wire = SealFrameMAC(&UDPCFrame{
		Magic: UDPC_MAGIC_DEFAULT, Version: UDPC_VERSION,
		Cmd: CMD_HANDSHAKE_SYN, Data: payload,
	}, &keys.SynMAC)
	return wire, clientNonce, keys
}

// parseTestHandshakeACKWithTarget authenticates an ACK that may carry the
// granted-target TLV (which parseTestHandshakeACK's strict length check would
// reject) and returns frame, server nonce and granted target.
func parseTestHandshakeACKWithTarget(tb testing.TB, wire []byte, keys PSKHandshakeKeys, clientNonce [clientNonceSize]byte) (*UDPCFrame, [serverNonceSize]byte, string) {
	tb.Helper()
	frame, err := DecodeUDPCFrame(wire, UDPC_MAGIC_DEFAULT)
	if err != nil {
		tb.Fatalf("decode handshake ACK: %v", err)
	}
	if frame.Cmd != CMD_HANDSHAKE_ACK || frame.SessionID == 0 {
		tb.Fatalf("invalid handshake ACK cmd=%d sid=%08x", frame.Cmd, frame.SessionID)
	}
	if err := VerifyFrameAuth(frame.Raw(), &keys.AckMAC); err != nil {
		tb.Fatalf("authenticate handshake ACK: %v", err)
	}
	if len(frame.Data) < ackPayloadBase {
		tb.Fatalf("handshake ACK payload %d too short", len(frame.Data))
	}
	var echoed [clientNonceSize]byte
	copy(echoed[:], frame.Data[:clientNonceSize])
	if echoed != clientNonce {
		tb.Fatal("handshake ACK echoed the wrong client nonce")
	}
	var serverNonce [serverNonceSize]byte
	copy(serverNonce[:], frame.Data[clientNonceSize:ackPayloadBase])
	granted, _, err := splitAckPayload(frame.Data, false)
	if err != nil {
		tb.Fatalf("split granted target: %v", err)
	}
	return frame, serverNonce, granted
}

func echoServe(t *testing.T, ln net.Listener) {
	t.Helper()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				io.Copy(conn, conn)
			}(c)
		}
	}()
}

func startTestServer(t *testing.T, cfg ServerConfig) *Server {
	t.Helper()
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

func readUDPFrame(t *testing.T, conn net.Conn, timeout time.Duration) []byte {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	return append([]byte(nil), buf[:n]...)
}

func sealTestDataFrame(t *testing.T, sid uint32, seq uint64, payload []byte, send *NoiseCipherState) []byte {
	t.Helper()
	wire := SealFrameAEAD(&UDPCFrame{
		Magic: UDPC_MAGIC_DEFAULT, Version: UDPC_VERSION, Cmd: CMD_DATA,
		SessionID: sid, PacketNo: seq, Seq: seq, Data: payload,
	}, send, payload)
	if wire == nil {
		t.Fatal("failed to seal test DATA frame")
	}
	return wire
}

func testSessionCount(srv *Server) uint32 {
	n := uint32(0)
	srv.sessions.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}

// A client requesting a target inside allowed_targets gets a session to THAT
// endpoint, and the ACK echoes the granted endpoint.
func TestHandshakeRequestedTargetGranted(t *testing.T) {
	echoA, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoA.Close()
	echoB, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoB.Close()
	go echoServe(t, echoA)
	go echoServe(t, echoB)

	srv := startTestServer(t, ServerConfig{
		ListenAddr:     "127.0.0.1:0",
		TargetAddr:     echoA.Addr().String(), // default
		Passwords:      []string{"psk-target"},
		LogLevel:       "error",
		AllowedTargets: []string{"tcp://127.0.0.1:*"},
	})

	target := "tcp://" + echoB.Addr().String()
	synWire, clientNonce, keys := buildTestSYNWithTarget(t, "psk-target", target, nil)

	cConn, err := net.Dial("udp", srv.conn.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cConn.Close()
	if _, err := cConn.Write(synWire); err != nil {
		t.Fatal(err)
	}

	ack := readUDPFrame(t, cConn, 2*time.Second)
	frame, serverNonce, granted := parseTestHandshakeACKWithTarget(t, ack, keys, clientNonce)
	if granted != target {
		t.Fatalf("ACK granted %q, want %q", granted, target)
	}

	// Data must reach echoB, not the default echoA. Skip any interleaved
	// ACK/PING control frames; the echo DATA is what identifies the backend.
	keys2 := testClientFrameKeys(t, "psk-target", clientNonce, serverNonce, frame.SessionID)
	msg := []byte("which backend am I talking to?")
	if _, err := cConn.Write(sealTestDataFrame(t, frame.SessionID, 1, msg, keys2.Send)); err != nil {
		t.Fatal(err)
	}
	var f *UDPCFrame
	deadline := time.Now().Add(2 * time.Second)
	for {
		wire := readUDPFrame(t, cConn, time.Until(deadline))
		got, err := DecodeUDPCFrame(wire, UDPC_MAGIC_DEFAULT)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := OpenFrameAEAD(got, keys2.Recv)
		if err != nil {
			t.Fatalf("open frame cmd=%d: %v", got.Cmd, err)
		}
		got.Data = plain
		if got.Cmd == CMD_DATA {
			f = got
			break
		}
	}
	if string(f.Data) != string(msg) {
		t.Fatalf("want DATA echo %q, got cmd=%d data=%q", msg, f.Cmd, f.Data)
	}
}

// A client requesting a target OUTSIDE allowed_targets is silently dropped:
// no ACK, no session.
func TestHandshakeDeniedTargetDropsSYN(t *testing.T) {
	srv := startTestServer(t, ServerConfig{
		ListenAddr:     "127.0.0.1:0",
		TargetAddr:     "tcp://127.0.0.1:1",
		Passwords:      []string{"psk-target"},
		LogLevel:       "error",
		AllowedTargets: []string{"tcp://127.0.0.1:*"}, // UDP requests are denied by network mismatch
	})

	synWire, _, _ := buildTestSYNWithTarget(t, "psk-target", "udp://127.0.0.1:51820", nil)
	cConn, err := net.Dial("udp", srv.conn.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cConn.Close()
	if _, err := cConn.Write(synWire); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	cConn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := cConn.Read(buf); err == nil {
		t.Fatalf("denied target got a reply")
	}
	if n := testSessionCount(srv); n != 0 {
		t.Fatalf("denied target created %d session(s)", n)
	}
}

// No TLV = default target: the pre-existing single-target behaviour keeps
// working unchanged, and the ACK carries no granted-target TLV.
func TestHandshakeWithoutTargetUsesDefault(t *testing.T) {
	echoA, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoA.Close()

	srv := startTestServer(t, ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TargetAddr: echoA.Addr().String(),
		Passwords:  []string{"psk-target"},
		LogLevel:   "error",
		// No AllowedTargets: only the default is reachable.
	})

	synWire, clientNonce, keys := buildTestSYN(t, "psk-target", nil)
	cConn, err := net.Dial("udp", srv.conn.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cConn.Close()
	if _, err := cConn.Write(synWire); err != nil {
		t.Fatal(err)
	}
	ack := readUDPFrame(t, cConn, 2*time.Second)
	frame, _, granted := parseTestHandshakeACKWithTarget(t, ack, keys, clientNonce)
	if granted != "" {
		t.Fatalf("default-target ACK must carry no TLV, got %q", granted)
	}
	if frame.SessionID == 0 {
		t.Fatal("no session established")
	}
}
