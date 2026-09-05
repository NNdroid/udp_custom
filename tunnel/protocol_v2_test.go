package tunnel

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// buildTestSYN constructs the only handshake form accepted by protocol v2.
func buildTestSYN(tb testing.TB, psk string, noiseMsg1 []byte) ([]byte, [clientNonceSize]byte, PSKHandshakeKeys) {
	tb.Helper()
	var clientNonce [clientNonceSize]byte
	if _, err := rand.Read(clientNonce[:]); err != nil {
		tb.Fatal(err)
	}
	payload := make([]byte, synPayloadBase+len(noiseMsg1))
	copy(payload[:clientNonceSize], clientNonce[:])
	binary.BigEndian.PutUint64(payload[clientNonceSize:synPayloadBase], uint64(time.Now().Unix()))
	copy(payload[synPayloadBase:], noiseMsg1)
	keys := DerivePSKHandshakeKeys(psk, clientNonce)
	wire := SealFrameMAC(&UDPCFrame{
		Magic: UDPC_MAGIC_DEFAULT, Version: UDPC_VERSION,
		Cmd: CMD_HANDSHAKE_SYN, Data: payload,
	}, &keys.SynMAC)
	if len(wire) == 0 {
		tb.Fatal("failed to seal test SYN")
	}
	return wire, clientNonce, keys
}

// parseTestHandshakeACK authenticates an ACK and extracts its server nonce and
// optional Noise message.
func parseTestHandshakeACK(tb testing.TB, wire []byte, keys PSKHandshakeKeys, clientNonce [clientNonceSize]byte, noise bool) (*UDPCFrame, [serverNonceSize]byte, []byte) {
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
	want := ackPayloadBase
	if noise {
		want += noiseMsg2Size
	}
	if len(frame.Data) != want {
		tb.Fatalf("handshake ACK payload=%d, want %d", len(frame.Data), want)
	}
	var echoed [clientNonceSize]byte
	copy(echoed[:], frame.Data[:clientNonceSize])
	if echoed != clientNonce {
		tb.Fatal("handshake ACK echoed the wrong client nonce")
	}
	var serverNonce [serverNonceSize]byte
	copy(serverNonce[:], frame.Data[clientNonceSize:ackPayloadBase])
	return frame, serverNonce, frame.Data[ackPayloadBase:]
}

func testClientFrameKeys(tb testing.TB, psk string, clientNonce [clientNonceSize]byte, serverNonce [serverNonceSize]byte, sid uint32) *FrameKeys {
	keys := DerivePSKSessionKeys(psk, clientNonce, serverNonce, sid)
	fk, err := keys.ClientFrameCiphers()
	if err != nil {
		tb.Fatalf("client frame ciphers: %v", err)
	}
	return fk

}

func TestProtocolV2HeaderRoundTrip64Bit(t *testing.T) {
	key := [32]byte{1, 2, 3, 4}
	want := &UDPCFrame{
		Magic: UDPC_MAGIC_DEFAULT, Version: UDPC_VERSION, Cmd: CMD_DATA,
		Flags: 0x1234, SessionID: 0xaabbccdd,
		PacketNo: 1<<48 + 7, Seq: 1<<40 + 8, Ack: 1<<39 + 9,
		WindowSize: 321, Data: []byte("v2-payload"),
	}
	wire := SealFrameMAC(want, &key)
	got, err := DecodeUDPCFrame(wire, UDPC_MAGIC_DEFAULT)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyFrameAuth(got.Raw(), &key); err != nil {
		t.Fatal(err)
	}
	if got.Magic != want.Magic || got.Version != want.Version || got.Cmd != want.Cmd ||
		got.Flags != want.Flags || got.SessionID != want.SessionID || got.PacketNo != want.PacketNo ||
		got.Seq != want.Seq || got.Ack != want.Ack || got.WindowSize != want.WindowSize ||
		!bytes.Equal(got.Data, want.Data) {
		t.Fatalf("round trip mismatch: got %+v, want %+v", got, want)
	}
}

func TestProtocolV2RejectsV1WithoutFallback(t *testing.T) {
	wire := (&UDPCFrame{Magic: UDPC_MAGIC_DEFAULT, Version: UDPC_VERSION, Cmd: CMD_ACK}).Encode()
	wire[4] = 1
	if _, err := DecodeUDPCFrame(wire, UDPC_MAGIC_DEFAULT); err == nil {
		t.Fatal("protocol v1 frame was accepted by the v2-only parser")
	}
}

func TestProtocolV2MACTamperMatrix(t *testing.T) {
	key := [32]byte{9, 8, 7, 6}
	wire := SealFrameMAC(&UDPCFrame{
		Magic: UDPC_MAGIC_DEFAULT, Version: UDPC_VERSION, Cmd: CMD_DATA,
		Flags: 3, SessionID: 11, PacketNo: 12, Seq: 13, Ack: 14,
		WindowSize: 15, Data: []byte("payload"),
	}, &key)
	if err := VerifyFrameAuth(wire, &key); err != nil {
		t.Fatalf("valid frame failed authentication: %v", err)
	}

	fields := map[string]int{
		"magic": 0, "version": 4, "command": 5, "flags": 6,
		"session": 8, "packet-number": 12, "sequence": 20,
		"ack": 28, "window": 36, "payload-length": 38,
		"payload": UDPC_HDR_SIZE, "tag": len(wire) - 1,
	}
	for name, offset := range fields {
		t.Run(name, func(t *testing.T) {
			mutated := append([]byte(nil), wire...)
			mutated[offset] ^= 1
			if err := VerifyFrameAuth(mutated, &key); err == nil {
				t.Fatal("tampered frame authenticated")
			}
		})
	}
}

func TestProtocolV2DirectionAndTranscriptKeySeparation(t *testing.T) {
	var clientNonce [clientNonceSize]byte
	var serverNonce [serverNonceSize]byte
	copy(clientNonce[:], "client-nonce-v2!")
	copy(serverNonce[:], "server-nonce-v2!")
	keys := DerivePSKSessionKeys("shared-secret", clientNonce, serverNonce, 7)
	if bytes.Equal(keys.C2S[:], keys.S2C[:]) {
		t.Fatal("client-to-server and server-to-client keys must differ")
	}

	clientKeys, err := keys.ClientFrameCiphers()
	if err != nil {
		t.Fatal(err)
	}
	serverKeys, err := keys.ServerFrameCiphers()
	if err != nil {
		t.Fatal(err)
	}

	// A record the client sealed must open server-side but never client-side:
	// the opposite-direction key cannot open a reflected frame.
	frame := &UDPCFrame{
		Magic: UDPC_MAGIC_DEFAULT, Version: UDPC_VERSION, Cmd: CMD_ACK,
		SessionID: 7, PacketNo: 1, Ack: 3,
	}
	wire := SealFrameAEAD(frame, clientKeys.Send, nil)
	parsed, err := DecodeUDPCFrame(wire, UDPC_MAGIC_DEFAULT)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFrameAEAD(parsed, serverKeys.Recv); err != nil {
		t.Fatalf("server could not open a client record: %v", err)
	}
	if _, err := OpenFrameAEAD(parsed, clientKeys.Recv); err == nil {
		t.Fatal("opposite-direction key opened a reflected frame")
	}

	otherNonce := serverNonce
	otherNonce[0] ^= 1
	otherTranscript := DerivePSKSessionKeys("shared-secret", clientNonce, otherNonce, 7)
	otherSession := DerivePSKSessionKeys("shared-secret", clientNonce, serverNonce, 8)
	if bytes.Equal(keys.C2S[:], otherTranscript.C2S[:]) || bytes.Equal(keys.C2S[:], otherSession.C2S[:]) {
		t.Fatal("session key was not bound to both nonces and SessionID")
	}
}

func TestProtocolV2EveryControlFrameIsAuthenticated(t *testing.T) {
	key := [32]byte{4, 3, 2, 1}
	cipher, err := newNoiseCipherState(key[:])
	if err != nil {
		t.Fatal(err)
	}
	for i, cmd := range []uint8{CMD_ACK, CMD_PING, CMD_PONG, CMD_FIN} {
		t.Run(commandName(cmd), func(t *testing.T) {
			wire := SealFrameAEAD(&UDPCFrame{
				Magic: UDPC_MAGIC_DEFAULT, Version: UDPC_VERSION, Cmd: cmd,
				SessionID: 99, PacketNo: uint64(i + 1), Ack: 8,
			}, cipher, nil)
			frame, err := DecodeUDPCFrame(wire, UDPC_MAGIC_DEFAULT)
			if err != nil {
				t.Fatal(err)
			}
			if !validSessionFrameShape(frame) {
				t.Fatal("valid control frame rejected by shape gate")
			}
			plain, err := OpenFrameAEAD(frame, cipher)
			if err != nil || len(plain) != 0 {
				t.Fatalf("valid control frame rejected: plain=%x err=%v", plain, err)
			}
			wire[len(wire)-1] ^= 1
			mutated, err := DecodeUDPCFrame(wire, UDPC_MAGIC_DEFAULT)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := OpenFrameAEAD(mutated, cipher); err == nil {
				t.Fatal("tampered control-frame tag opened")
			}
		})
	}
}

func TestProtocolV2NoiseControlFrameUsesHeaderAAD(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	sender, err := newNoiseCipherState(key)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := newNoiseCipherState(key)
	if err != nil {
		t.Fatal(err)
	}
	wire := SealFrameAEAD(&UDPCFrame{
		Magic: UDPC_MAGIC_DEFAULT, Version: UDPC_VERSION, Cmd: CMD_FIN,
		SessionID: 5, PacketNo: 1, Ack: 17,
	}, sender, nil)
	frame, err := DecodeUDPCFrame(wire, UDPC_MAGIC_DEFAULT)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := OpenFrameAEAD(frame, receiver)
	if err != nil || len(plain) != 0 {
		t.Fatalf("valid encrypted control frame failed: plaintext=%x err=%v", plain, err)
	}

	for _, offset := range []int{6, 8, 12, 28, len(wire) - 1} {
		mutated := append([]byte(nil), wire...)
		mutated[offset] ^= 1
		bad, err := DecodeUDPCFrame(mutated, UDPC_MAGIC_DEFAULT)
		if err != nil {
			t.Fatalf("mutation at %d should remain structurally parseable: %v", offset, err)
		}
		if _, err := OpenFrameAEAD(bad, receiver); err == nil {
			t.Fatalf("mutation at %d bypassed AEAD", offset)
		}
	}
}

func TestProtocolV2ReplayedControlFrameCannotRefreshSession(t *testing.T) {
	rig := newTestRig(t, true)
	ping := rig.makeWireFrame(&UDPCFrame{Cmd: CMD_PING, PacketNo: 1})
	if !rig.sess.processIncomingFrame(ping, rig.clientAddr, 0) {
		t.Fatal("fresh authenticated PING was rejected")
	}
	if pong := rig.recvFrame(time.Second); pong.Cmd != CMD_PONG {
		t.Fatalf("reply command = %d, want PONG", pong.Cmd)
	}
	rig.sess.activeMu.Lock()
	lastActive := rig.sess.lastActive
	rig.sess.activeMu.Unlock()

	if rig.sess.processIncomingFrame(ping, rig.clientAddr, 0) {
		t.Fatal("replayed PING was accepted")
	}
	rig.expectNoFrame(50 * time.Millisecond)
	rig.sess.activeMu.Lock()
	activeChanged := !rig.sess.lastActive.Equal(lastActive)
	rig.sess.activeMu.Unlock()
	if activeChanged {
		t.Fatal("replayed control frame refreshed session activity")
	}
}

func TestProtocolV2ClientRejectsForgedControlBeforeStateMutation(t *testing.T) {
	recvKey := [32]byte{1, 3, 3, 7}
	recvCipher, err := newNoiseCipherState(recvKey[:])
	if err != nil {
		t.Fatal(err)
	}
	wrongKey := [32]byte{9, 9, 9, 9}
	client := &Client{
		magic: UDPC_MAGIC_DEFAULT, logger: Nop,
		dialer: &SpreadDialer{closed: 1}, pendingAcks: make(map[[clientNonceSize]byte]*pendingHandshake),
		closeChan: make(chan struct{}),
	}
	sess := &clientSession{
		client: client, sid: 77, frameKeys: &FrameKeys{Recv: recvCipher},
		recvSeq: 1, recvQueue: make(map[uint64][]byte),
		unacked:    map[uint64]*unackedPkt{1: {sentTime: time.Now(), firstSent: time.Now()}},
		lastActive: time.Now(), closeChan: make(chan struct{}),
	}
	sess.unackedCond = sync.NewCond(&sess.unackedMu)
	client.sessions.Store(sess.sid, sess)

	lastActive := sess.lastActive
	for _, frame := range []*UDPCFrame{
		{Magic: UDPC_MAGIC_DEFAULT, Version: UDPC_VERSION, Cmd: CMD_ACK, SessionID: sess.sid, PacketNo: 1, Ack: 1},
		{Magic: UDPC_MAGIC_DEFAULT, Version: UDPC_VERSION, Cmd: CMD_FIN, SessionID: sess.sid, PacketNo: 2},
	} {
		// Forged under a wrong AEAD key AND under the (retired) HMAC form —
		// neither may reach session state.
		for _, wire := range [][]byte{
			SealFrameAEAD(frame, mustCipher(t, wrongKey), nil),
			SealFrameMAC(frame, &wrongKey),
		} {
			parsed, err := DecodeUDPCFrame(wire, UDPC_MAGIC_DEFAULT)
			if err != nil {
				t.Fatal(err)
			}
			client.dispatch(parsed)
		}
	}
	if len(sess.unacked) != 1 {
		t.Fatal("forged ACK removed an in-flight DATA frame")
	}
	if atomic.LoadInt32(&sess.closed) != 0 {
		t.Fatal("forged FIN closed the client session")
	}
	if !sess.lastActive.Equal(lastActive) {
		t.Fatal("forged control frame refreshed client session activity")
	}
}

// mustCipher builds a NoiseCipherState from a raw key (test helper).
func mustCipher(t *testing.T, key [32]byte) *NoiseCipherState {
	t.Helper()
	c, err := newNoiseCipherState(key[:])
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func commandName(cmd uint8) string {
	switch cmd {
	case CMD_ACK:
		return "ACK"
	case CMD_PING:
		return "PING"
	case CMD_PONG:
		return "PONG"
	case CMD_FIN:
		return "FIN"
	default:
		return "UNKNOWN"
	}
}

func FuzzVerifyFrameAuthNeverPanics(f *testing.F) {
	key := [32]byte{1}
	f.Add([]byte{})
	f.Add(make([]byte, UDPC_HDR_SIZE+UDPC_TRAILER_SIZE))
	f.Fuzz(func(t *testing.T, wire []byte) {
		_ = VerifyFrameAuth(wire, &key)
	})
}

// TestProtocolV2PSKOnlyPayloadIsConfidential proves PSK-only session records
// are ENCRYPTED, not just MAC'd: the payload must be unreadable on the wire
// and recoverable with the session keys. (Historical regression guard — the
// first PSK-only design authenticated with HMAC but sent plaintext.)
func TestProtocolV2PSKOnlyPayloadIsConfidential(t *testing.T) {
	var clientNonce [clientNonceSize]byte
	var serverNonce [serverNonceSize]byte
	copy(clientNonce[:], "confidentiality-c!")
	copy(serverNonce[:], "confidentiality-s!")
	keys := DerivePSKSessionKeys("wire-psk", clientNonce, serverNonce, 42)
	clientKeys, err := keys.ClientFrameCiphers()
	if err != nil {
		t.Fatal(err)
	}
	serverKeys, err := keys.ServerFrameCiphers()
	if err != nil {
		t.Fatal(err)
	}

	secret := []byte("PLAINTEXT-SECRET-do-not-ship: password=hunter2")
	wire := SealFrameAEAD(&UDPCFrame{
		Magic: UDPC_MAGIC_DEFAULT, Version: UDPC_VERSION, Cmd: CMD_DATA,
		SessionID: 42, PacketNo: 1, Seq: 1,
	}, clientKeys.Send, secret)
	if len(wire) == 0 {
		t.Fatal("failed to seal")
	}

	// The secret must not appear anywhere in header, payload, or tag.
	if bytes.Contains(wire, secret) {
		t.Fatal("sealed wire bytes contain the plaintext payload")
	}
	payload := wire[UDPC_HDR_SIZE : len(wire)-UDPC_TRAILER_SIZE]
	if bytes.Contains(payload, []byte("hunter2")) {
		t.Fatal("payload field contains plaintext fragments")
	}

	// The peer recovers it; a wrong-direction key does not.
	parsed, err := DecodeUDPCFrame(wire, UDPC_MAGIC_DEFAULT)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := OpenFrameAEAD(parsed, serverKeys.Recv)
	if err != nil || !bytes.Equal(plain, secret) {
		t.Fatalf("server could not recover the payload: %q err=%v", plain, err)
	}
	if _, err := OpenFrameAEAD(parsed, clientKeys.Recv); err == nil {
		t.Fatal("client-direction key opened a server-bound record")
	}
}
