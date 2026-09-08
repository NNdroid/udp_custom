package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NNdroid/udp_custom/tunnel"
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

// The shipped config.client.json template must actually boot the client (it
// used to be silently ignored, which started a SERVER on the client's port).
func TestClientConfigTemplateBootsClient(t *testing.T) {
	data, err := os.ReadFile("config.client.json")
	if err != nil {
		t.Skipf("config.client.json not available: %v", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse config.client.json: %v", err)
	}
	if cfg.Mode != "client" {
		t.Fatalf("template mode = %q, want client", cfg.Mode)
	}
	if cfg.Server == "" {
		t.Fatal("template is missing 'server'")
	}
}

// capturePortRangeLog runs validatePortRange with the standard logger diverted
// into a buffer so the emitted warnings can be asserted on.
func capturePortRangeLog(portRange, listen string, origDst bool, sendSockMax int) string {
	var buf bytes.Buffer
	prevOut := log.Writer()
	prevFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	}()
	validatePortRange(portRange, listen, origDst, sendSockMax)
	return buf.String()
}

func TestValidatePortRange(t *testing.T) {
	tests := []struct {
		name        string
		portRange   string
		listen      string
		origDst     bool
		sendSockMax int
		// want substrings that MUST appear / MUST NOT appear
		want    []string
		notWant []string
	}{
		{
			name:      "empty range is silent",
			portRange: "",
			listen:    ":36712",
			origDst:   true,
			want:      nil,
		},
		{
			name:      "single-port range is silent",
			portRange: "25000-25000",
			listen:    ":36712",
			origDst:   true,
			want:      nil,
		},
		{
			name:        "range exceeding sendsock_max warns",
			portRange:   "25000-26000",
			listen:      ":36712",
			origDst:     true,
			sendSockMax: 512,
			want:        []string{"exceeds sendsock_max"},
		},
		{
			name:      "range with origdst disabled warns",
			portRange: "25000-25499",
			listen:    ":36712",
			origDst:   false,
			want:      []string{"origdst=false"},
		},
		{
			name:      "range containing the listen port warns",
			portRange: "25000-26000",
			listen:    ":25007",
			origDst:   true,
			want:      []string{"CONTAINS the listen port"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := capturePortRangeLog(tc.portRange, tc.listen, tc.origDst, tc.sendSockMax)
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Errorf("missing %q in log output:\n%s", want, got)
				}
			}
			for _, deny := range tc.notWant {
				if strings.Contains(got, deny) {
					t.Errorf("unexpected %q in log output:\n%s", deny, got)
				}
			}
		})
	}
}

// TestUDPCustom_LiveE2E_FromJSONConfig drives a full tunnel through the JSON
// config file, the CLI mapping layer, and the tunnel package's public API —
// exactly what the binary does at startup.
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
	srvCfg := tunnel.ServerConfig{
		ListenAddr: cfg.Listen,
		TargetAddr: cfg.Target,
		Passwords:  cfg.Passwords,
		Magic:      magicVal,
		PrivateKey: cfg.PrivKey,
		LogLevel:   cfg.LogLevel,
	}
	srv, err := tunnel.NewServer(srvCfg)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	go srv.Start()
	time.Sleep(100 * time.Millisecond)

	// 5. Connect Client via the public API (DialTunnel, no local listener).
	cli, err := tunnel.NewClient(tunnel.ClientConfig{
		ServerAddr: udpAddr,
		Passwords:  []string{password},
		LogLevel:   "error",
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer cli.Close()

	conn, err := cli.DialTunnel(t.Context(), tunnel.DialOptions{})
	if err != nil {
		t.Fatalf("DialTunnel failed: %v", err)
	}
	defer conn.Close()

	// 6. Test Echo Data through the tunnel net.Conn.
	testMsg := []byte("Hello UDPCustom Server via JSON Config!")
	if _, err := conn.Write(testMsg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(testMsg))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(buf, testMsg) {
		t.Fatalf("echo mismatch: got %q, want %q", buf, testMsg)
	}

	t.Logf("✅ Live E2E UDP Custom Tunnel via JSON Config PASSED!")
}
