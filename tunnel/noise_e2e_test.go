package tunnel

import (
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// Noise E2E: full handshake with an ephemeral pubkey, then encrypted DATA both
// ways with PacketNo-derived nonces.
func TestUDPCustom_Noise_E2E(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				io.Copy(conn, conn)
			}(c)
		}
	}()

	kp, err := GenerateNoiseKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	serverUDP := "127.0.0.1:0"
	srv, err := NewServer(ServerConfig{
		ListenAddr: serverUDP,
		TargetAddr: echoLn.Addr().String(),
		Passwords:  []string{"secret_psk"},
		PrivateKey: hexEncodeKey(kp.PrivateKey),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	serverUDP = srv.conn.LocalAddr().String()
	go srv.Start()
	defer srv.Close()

	cConn, err := net.Dial("udp", serverUDP)
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer cConn.Close()

	// Handshake payload: [16B client nonce][8B timestamp][48B Noise_NK msg1].
	// The fixed 16-byte trailer authenticates the complete SYN.
	clientNK, err := NewClientNK(kp.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	noiseMsg1, err := clientNK.Message1()
	if err != nil {
		t.Fatal(err)
	}
	synWire, clientNonce, handshakeKeys := buildTestSYN(t, "secret_psk", noiseMsg1)
	cConn.Write(synWire)

	respBuf := make([]byte, 2048)
	cConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := cConn.Read(respBuf)
	if err != nil {
		t.Fatalf("read handshake ack: %v", err)
	}
	ackFrame, _, noiseMsg2 := parseTestHandshakeACK(t, respBuf[:n], handshakeKeys, clientNonce, true)
	sid := ackFrame.SessionID

	// Complete Noise_NK with msg2, extracted after the echoed client nonce and
	// fresh server nonce in the authenticated ACK payload.
	clientNoise, err := clientNK.Finish(noiseMsg2)
	if err != nil {
		t.Fatalf("Noise_NK finish: %v", err)
	}
	// Encrypted request seq=1, packet number 1.
	msg := []byte("encrypted hello over udp_custom")
	dataFrame := &UDPCFrame{Magic: UDPC_MAGIC_DEFAULT, Version: UDPC_VERSION,
		Cmd: CMD_DATA, SessionID: sid, PacketNo: 1, Seq: 1, Data: msg}
	wire := SealFrameAEAD(dataFrame, clientNoise.SendCipher, msg)
	cConn.Write(wire)

	// Read ACK then the encrypted echo.
	readFrame := func() *UDPCFrame {
		t.Helper()
		cConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := cConn.Read(respBuf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		f, err := DecodeUDPCFrame(respBuf[:n], UDPC_MAGIC_DEFAULT)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		plain, err := OpenFrameAEAD(f, clientNoise.RecvCipher)
		if err != nil {
			t.Fatalf("frame AEAD (cmd=%d): %v", f.Cmd, err)
		}
		f.Data = plain
		return f
	}
	ack := readFrame()
	if ack.Cmd != CMD_ACK || ack.Ack != 1 {
		t.Fatalf("want ACK(1), got cmd=%d ack=%d", ack.Cmd, ack.Ack)
	}
	echo := readFrame()
	if echo.Cmd != CMD_DATA || echo.Seq != 1 {
		t.Fatalf("want DATA seq=1, got cmd=%d seq=%d", echo.Cmd, echo.Seq)
	}
	if string(echo.Data) != string(msg) {
		t.Fatalf("echo mismatch: got %q", echo.Data)
	}
}

func hexEncodeKey(k [32]byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 64)
	for i, b := range k {
		out[i*2] = digits[b>>4]
		out[i*2+1] = digits[b&0x0f]
	}
	return string(out)
}

// Replay idempotency E2E: resending the SAME SYN must return the same session
// ACK and must NOT open a second target connection (P1-2 / P1-3).
func TestUDPCustom_HandshakeReplay_Idempotent(t *testing.T) {
	var connCount int32 = 0
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&connCount, 1)
			go func(conn net.Conn) {
				defer conn.Close()
				io.Copy(conn, conn)
			}(c)
		}
	}()

	serverUDP := "127.0.0.1:0"
	srv, err := NewServer(ServerConfig{
		ListenAddr: serverUDP,
		TargetAddr: echoLn.Addr().String(),
		Passwords:  []string{"secret_psk"},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	serverUDP = srv.conn.LocalAddr().String()
	go srv.Start()
	defer srv.Close()

	cConn, err := net.Dial("udp", serverUDP)
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer cConn.Close()

	syn, clientNonce, handshakeKeys := buildTestSYN(t, "secret_psk", nil)

	respBuf := make([]byte, 2048)
	readAck := func() uint32 {
		t.Helper()
		cConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := cConn.Read(respBuf)
		if err != nil {
			t.Fatalf("read ack: %v", err)
		}
		f, _, _ := parseTestHandshakeACK(t, respBuf[:n], handshakeKeys, clientNonce, false)
		return f.SessionID
	}

	cConn.Write(syn)
	sid1 := readAck()
	cConn.Write(syn) // retransmission of the exact same SYN
	sid2 := readAck()

	if sid1 != sid2 {
		t.Fatalf("replayed SYN must be answered with the same session: %08X vs %08X", sid1, sid2)
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if got := atomic.LoadInt32(&connCount); got > 1 {
			t.Fatalf("replayed SYN opened a second target connection (%d)", got)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := atomic.LoadInt32(&connCount); got != 1 {
		t.Fatalf("expected exactly one target connection, got %d", got)
	}
}
