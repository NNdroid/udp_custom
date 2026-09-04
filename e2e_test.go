package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestUDPCustom_TCP_And_UDP_E2E(t *testing.T) {
	// 1. Echo server (TCP)
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	defer echoLn.Close()
	echoAddr := echoLn.Addr().String()

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

	// 2. Start UDPCServer
	serverUDP := "127.0.0.1:0"
	srv, err := NewUDPCServer(ServerConfig{
		ListenAddr: serverUDP,
		TargetAddr: echoAddr,
		Passwords:  []string{"secret_psk"},
	})
	if err != nil {
		t.Fatalf("NewUDPCServer: %v", err)
	}
	serverUDP = srv.conn.LocalAddr().String()
	go srv.Start()
	defer srv.Close()

	// 3. Client connection
	cConn, err := net.Dial("udp", serverUDP)
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer cConn.Close()

	// Perform Handshake
	var nonce [16]byte
	rand.Read(nonce[:])
	now := time.Now().Unix()
	sig := ComputeAuthHMAC(nonce[:], "secret_psk", now)

	handshakePayload := make([]byte, 56)
	copy(handshakePayload[0:16], nonce[:])
	binary.BigEndian.PutUint64(handshakePayload[16:24], uint64(now))
	copy(handshakePayload[24:56], sig)

	syn := &UDPCFrame{
		Magic:   UDPC_MAGIC_DEFAULT,
		Version: UDPC_VERSION,
		Cmd:     CMD_HANDSHAKE_SYN,
		Data:    handshakePayload,
	}
	cConn.Write(syn.Encode())

	respBuf := make([]byte, 2048)
	n, err := cConn.Read(respBuf)
	if err != nil {
		t.Fatalf("read handshake ack: %v", err)
	}
	ackFrame, err := DecodeUDPCFrame(respBuf[:n], UDPC_MAGIC_DEFAULT)
	if err != nil || ackFrame.Cmd != CMD_HANDSHAKE_ACK {
		t.Fatalf("handshake ack failed: %v, cmd: %d", err, ackFrame.Cmd)
	}
	sid := ackFrame.SessionID

	// Send Data
	testMsg := []byte("Hello UDPCustom over reliable UDP!")
	dataFrame := &UDPCFrame{
		Magic:     UDPC_MAGIC_DEFAULT,
		Version:   UDPC_VERSION,
		Cmd:       CMD_DATA,
		SessionID: sid,
		Seq:       1,
		Data:      testMsg,
	}
	cConn.Write(dataFrame.Encode())

	// Read ACK
	n, _ = cConn.Read(respBuf)
	// Read Echo data
	n, _ = cConn.Read(respBuf)
	echoFrame, err := DecodeUDPCFrame(respBuf[:n], UDPC_MAGIC_DEFAULT)
	if err != nil || echoFrame.Cmd != CMD_DATA {
		t.Fatalf("decode data failed: %v", err)
	}

	if !bytes.Equal(echoFrame.Data, testMsg) {
		t.Fatalf("echo mismatch: got %q, want %q", echoFrame.Data, testMsg)
	}
	t.Logf("✅ UDPCustom TCP Echo Passed!")
}
