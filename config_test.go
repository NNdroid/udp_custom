package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUDPCustom_JSONConfigParsing(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Array Passwords & Aliases
	jsonStr := `{
		"listen": ":38888",
		"target": "tcp://127.0.0.1:2222",
		"passwords": ["pass1", "pass2"],
		"token": "token_abc",
		"magic": "TEST",
		"privkey": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"log_level": "debug"
	}`
	confPath := filepath.Join(tempDir, "config.json")
	if err := os.WriteFile(confPath, []byte(jsonStr), 0644); err != nil {
		t.Fatalf("write config.json failed: %v", err)
	}

	cfg, err := loadConfigFile(confPath)
	if err != nil {
		t.Fatalf("load config failed: %v", err)
	}
	if cfg.Listen != ":38888" || cfg.Target != "tcp://127.0.0.1:2222" || cfg.Magic != "TEST" || cfg.LogLevel != "debug" {
		t.Fatalf("parsed config fields mismatch: %+v", cfg)
	}
	if len(cfg.Passwords) != 3 || cfg.Passwords[0] != "pass1" || cfg.Passwords[1] != "pass2" || cfg.Passwords[2] != "token_abc" {
		t.Fatalf("parsed passwords array mismatch: %+v", cfg.Passwords)
	}
}

func TestUDPCustom_LiveE2E_FromJSONConfig(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Echo Backend Target
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo backend failed: %v", err)
	}
	defer backendLn.Close()
	backendAddr := backendLn.Addr().String()

	go func() {
		for {
			conn, err := backendLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	// 2. Find free UDP port for UDPCustom Server
	dummyUDP, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen packet failed: %v", err)
	}
	udpPort := dummyUDP.LocalAddr().(*net.UDPAddr).Port
	dummyUDP.Close()
	udpAddr := fmt.Sprintf("127.0.0.1:%d", udpPort)

	// 3. Create Server JSON Config
	password := "json_psk_test_123"
	serverConf := fmt.Sprintf(`{
		"listen": "%s",
		"target": "tcp://%s",
		"passwords": ["%s"],
		"magic": "UDPC",
		"log_level": "debug"
	}`, udpAddr, backendAddr, password)
	serverConfPath := filepath.Join(tempDir, "udp_custom_e2e.json")
	if err := os.WriteFile(serverConfPath, []byte(serverConf), 0644); err != nil {
		t.Fatalf("write config failed: %v", err)
	}

	// 4. Start Server from loaded Config
	cfg, err := loadConfigFile(serverConfPath)
	if err != nil {
		t.Fatalf("load config failed: %v", err)
	}

	magicVal := parseMagicHeader(cfg.Magic)
	srvCfg := ServerConfig{
		ListenAddr: cfg.Listen,
		TargetAddr: cfg.Target,
		Passwords:  cfg.Passwords,
		Magic:      magicVal,
		PrivateKey: cfg.PrivKey,
		LogLevel:   cfg.LogLevel,
	}
	srv, err := NewUDPCServer(srvCfg)
	if err != nil {
		t.Fatalf("NewUDPCServer failed: %v", err)
	}
	defer srv.Close()

	go srv.Start()
	time.Sleep(100 * time.Millisecond)

	// 5. Connect Client and Perform Handshake
	cConn, err := net.Dial("udp", udpAddr)
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer cConn.Close()

	var nonce [16]byte
	rand.Read(nonce[:])
	now := time.Now().Unix()
	sig := ComputeAuthHMAC(nonce[:], password, now)

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

	// 6. Test Echo Data via JSON Config Server
	testMsg := []byte("Hello UDPCustom Server via JSON Config!")
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

	t.Logf("✅ Live E2E UDP Custom Tunnel via JSON Config PASSED!")
}
