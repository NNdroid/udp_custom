//go:build linux

package tunnel

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// TestServerReceiveSocketsGroupE2E runs a real handshake + echo through a
// 4-socket SO_REUSEPORT receive group: the kernel spreads the client's
// datagrams across the group, and every frame must still authenticate, reorder
// and reply correctly.
func TestServerReceiveSocketsGroupE2E(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go echoServe(t, echoLn)

	srv := startTestServer(t, ServerConfig{
		ListenAddr:     "127.0.0.1:0",
		TargetAddr:     echoLn.Addr().String(),
		Passwords:      []string{"reuseport-psk"},
		LogLevel:       "error",
		ReceiveSockets: 4,
	})
	go srv.Start()
	if st := srv.Stats(); st.ReceiveSockets != 4 {
		t.Fatalf("ReceiveSockets = %d, want the full group of 4", st.ReceiveSockets)
	}

	cConn, err := net.Dial("udp", srv.conn.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cConn.Close()

	synWire, clientNonce, handshakeKeys := buildTestSYN(t, "reuseport-psk", nil)
	if _, err := cConn.Write(synWire); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	cConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := cConn.Read(buf)
	if err != nil {
		t.Fatalf("read handshake ack: %v", err)
	}
	ackFrame, serverNonce, _ := parseTestHandshakeACK(t, buf[:n], handshakeKeys, clientNonce, false)
	keys := testClientFrameKeys(t, "reuseport-psk", clientNonce, serverNonce, ackFrame.SessionID)

	// Round trip through the reuseport group: whichever socket receives the
	// DATA, the reply must authenticate and echo byte-for-byte.
	msg := []byte("echo through the SO_REUSEPORT receive group")
	dataWire := SealFrameAEAD(&UDPCFrame{
		Magic: UDPC_MAGIC_DEFAULT, Version: UDPC_VERSION, Cmd: CMD_DATA,
		SessionID: ackFrame.SessionID, PacketNo: 1, Seq: 1,
	}, keys.Send, msg)
	if _, err := cConn.Write(dataWire); err != nil {
		t.Fatal(err)
	}

	var got []byte
	deadline := time.Now().Add(3 * time.Second)
	for {
		cConn.SetReadDeadline(deadline)
		n, err := cConn.Read(buf)
		if err != nil {
			t.Fatalf("waiting for echo: %v", err)
		}
		f, err := DecodeUDPCFrame(buf[:n], UDPC_MAGIC_DEFAULT)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := OpenFrameAEAD(f, keys.Recv)
		if err != nil {
			continue // a control frame we can skip (ACK)
		}
		if f.Cmd == CMD_DATA {
			got = plain
			break
		}
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("echo mismatch: got %q", got)
	}
	_ = io.Discard
}
