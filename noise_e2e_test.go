package main

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// Noise E2E: full handshake with an ephemeral pubkey, then encrypted DATA both
// ways with Seq-derived nonces. Guards the P0-2 fix on the wire.
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
	srv, err := NewUDPCServer(ServerConfig{
		ListenAddr: serverUDP,
		TargetAddr: echoLn.Addr().String(),
		Passwords:  []string{"secret_psk"},
		PrivateKey: hexEncodeKey(kp.PrivateKey),
	})
	if err != nil {
		t.Fatalf("NewUDPCServer: %v", err)
	}
	serverUDP = srv.conn.LocalAddr().String()
	go srv.Start()
	defer srv.Close()

	cConn, err := net.Dial("udp", serverUDP)
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer cConn.Close()

	// Handshake: [16B nonce][8B ts][32B HMAC][48B Noise_NK msg1]
	clientNK, err := NewClientNK(kp.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	noiseMsg1, err := clientNK.Message1()
	if err != nil {
		t.Fatal(err)
	}
	var nonce [16]byte
	rand.Read(nonce[:])
	now := time.Now().Unix()
	sig := ComputeAuthHMAC(nonce[:], "secret_psk", now)

	payload := make([]byte, 56+noiseMsg1Size)
	copy(payload[0:16], nonce[:])
	binary.BigEndian.PutUint64(payload[16:24], uint64(now))
	copy(payload[24:56], sig)
	copy(payload[56:], noiseMsg1)

	syn := &UDPCFrame{Magic: UDPC_MAGIC_DEFAULT, Version: UDPC_VERSION,
		Cmd: CMD_HANDSHAKE_SYN, Data: payload}
	cConn.Write(syn.Encode())

	respBuf := make([]byte, 2048)
	cConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := cConn.Read(respBuf)
	if err != nil {
		t.Fatalf("read handshake ack: %v", err)
	}
	ackFrame, err := DecodeUDPCFrame(respBuf[:n], UDPC_MAGIC_DEFAULT)
	if err != nil || ackFrame.Cmd != CMD_HANDSHAKE_ACK {
		t.Fatalf("handshake ack failed: %v, cmd: %d", err, ackFrame.Cmd)
	}
	sid := ackFrame.SessionID

	// Complete the Noise_NK handshake with the server's message 2. The ACK
	// Data carries ONLY msg2 (no port list); use it as-is.
	clientNoise, err := clientNK.Finish(ackFrame.Data)
	if err != nil {
		t.Fatalf("Noise_NK finish: %v", err)
	}

	// Encrypted request seq=1.
	msg := []byte("encrypted hello over udp_custom")
	ct := clientNoise.SendCipher.Encrypt(1, msg)
	dataFrame := &UDPCFrame{Magic: UDPC_MAGIC_DEFAULT, Version: UDPC_VERSION,
		Cmd: CMD_DATA, SessionID: sid, Seq: 1, Data: ct}
	cConn.Write(dataFrame.Encode())

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
	plain, err := clientNoise.RecvCipher.Decrypt(echo.Seq, echo.Data)
	if err != nil {
		t.Fatalf("echo decrypt failed: %v", err)
	}
	if string(plain) != string(msg) {
		t.Fatalf("echo mismatch: got %q", plain)
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
	srv, err := NewUDPCServer(ServerConfig{
		ListenAddr: serverUDP,
		TargetAddr: echoLn.Addr().String(),
		Passwords:  []string{"secret_psk"},
	})
	if err != nil {
		t.Fatalf("NewUDPCServer: %v", err)
	}
	serverUDP = srv.conn.LocalAddr().String()
	go srv.Start()
	defer srv.Close()

	cConn, err := net.Dial("udp", serverUDP)
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer cConn.Close()

	var nonce [16]byte
	rand.Read(nonce[:])
	now := time.Now().Unix()
	payload := make([]byte, 56)
	copy(payload[0:16], nonce[:])
	binary.BigEndian.PutUint64(payload[16:24], uint64(now))
	copy(payload[24:56], ComputeAuthHMAC(nonce[:], "secret_psk", now))
	syn := &UDPCFrame{Magic: UDPC_MAGIC_DEFAULT, Version: UDPC_VERSION,
		Cmd: CMD_HANDSHAKE_SYN, Data: payload}

	respBuf := make([]byte, 2048)
	readAck := func() uint32 {
		t.Helper()
		cConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := cConn.Read(respBuf)
		if err != nil {
			t.Fatalf("read ack: %v", err)
		}
		f, err := DecodeUDPCFrame(respBuf[:n], UDPC_MAGIC_DEFAULT)
		if err != nil || f.Cmd != CMD_HANDSHAKE_ACK {
			t.Fatalf("not an ACK: %v cmd=%d", err, f.Cmd)
		}
		return f.SessionID
	}

	cConn.Write(syn.Encode())
	sid1 := readAck()
	cConn.Write(syn.Encode()) // retransmission of the same SYN
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
