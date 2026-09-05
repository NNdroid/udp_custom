package tunnel

import (
	"bytes"
	"io"
	"net"
	"testing"
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

	// 2. Start Server
	serverUDP := "127.0.0.1:0"
	srv, err := NewServer(ServerConfig{
		ListenAddr: serverUDP,
		TargetAddr: echoAddr,
		Passwords:  []string{"secret_psk"},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
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

	// Perform authenticated v2 handshake.
	syn, clientNonce, handshakeKeys := buildTestSYN(t, "secret_psk", nil)
	cConn.Write(syn)

	respBuf := make([]byte, 2048)
	n, err := cConn.Read(respBuf)
	if err != nil {
		t.Fatalf("read handshake ack: %v", err)
	}
	ackFrame, serverNonce, _ := parseTestHandshakeACK(t, respBuf[:n], handshakeKeys, clientNonce, false)
	sid := ackFrame.SessionID
	frameKeys := testClientFrameKeys(t, "secret_psk", clientNonce, serverNonce, sid)

	// Send Data
	testMsg := []byte("Hello UDPCustom over reliable UDP!")
	dataFrame := &UDPCFrame{
		Magic:     UDPC_MAGIC_DEFAULT,
		Version:   UDPC_VERSION,
		Cmd:       CMD_DATA,
		SessionID: sid,
		PacketNo:  1,
		Seq:       1,
		Data:      testMsg,
	}
	cConn.Write(SealFrameAEAD(dataFrame, frameKeys.Send, testMsg))

	// Read ACK
	n, _ = cConn.Read(respBuf)
	// Read Echo data
	n, _ = cConn.Read(respBuf)
	echoFrame, err := DecodeUDPCFrame(respBuf[:n], UDPC_MAGIC_DEFAULT)
	if err != nil || echoFrame.Cmd != CMD_DATA {
		t.Fatalf("decode data failed: %v", err)
	}
	plain, err := OpenFrameAEAD(echoFrame, frameKeys.Recv)
	if err != nil {
		t.Fatalf("open echo: %v", err)
	}

	if !bytes.Equal(plain, testMsg) {
		t.Fatalf("echo mismatch: got %q, want %q", plain, testMsg)
	}
	t.Logf("✅ UDPCustom TCP Echo Passed!")
}
