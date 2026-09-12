package tunnel

import (
	"strings"
	"testing"
	"time"
)

func TestResolveMaxPkt(t *testing.T) {
	cases := []struct {
		name       string
		configured int
		want       int
	}{
		{"absent falls back to the ceiling", 0, UDPC_MAX_PKT},
		{"negative falls back to the ceiling", -1200, UDPC_MAX_PKT},
		{"in range is kept verbatim", 1200, 1200},
		{"the IPv4 never-fragment value is kept", 548, 548},
		{"exactly the floor is kept", maxPktFloor, maxPktFloor},
		{"below the floor is clamped up", maxPktFloor - 1, maxPktFloor},
		{"a single byte below the ceiling is kept", UDPC_MAX_PKT - 1, UDPC_MAX_PKT - 1},
		{"above the ceiling is clamped down", UDPC_MAX_PKT + 1, UDPC_MAX_PKT},
		{"jumbo frames are clamped down", 9000, UDPC_MAX_PKT},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveMaxPkt(tc.configured, Nop); got != tc.want {
				t.Fatalf("resolveMaxPkt(%d) = %d, want %d", tc.configured, got, tc.want)
			}
		})
	}
}

func TestResolveMaxPktAcceptsNilLogger(t *testing.T) {
	// The clamp warnings must not panic when no logger is wired in (bare
	// literals in tests, embedders that pass Nop).
	if got := resolveMaxPkt(9000, nil); got != UDPC_MAX_PKT {
		t.Fatalf("resolveMaxPkt(9000, nil) = %d, want %d", got, UDPC_MAX_PKT)
	}
}

func TestPayloadCap(t *testing.T) {
	if got, want := payloadCap(UDPC_MAX_PKT), UDPC_MAX_DATA; got != want {
		t.Fatalf("payloadCap(%d) = %d, want %d", UDPC_MAX_PKT, got, want)
	}
	if got, want := payloadCap(548), 548-UDPC_HDR_SIZE-UDPC_TRAILER_SIZE; got != want {
		t.Fatalf("payloadCap(548) = %d, want %d", got, want)
	}
}

func TestEffectivePayloadCapFallsBackForBareLiterals(t *testing.T) {
	// A Server/Client built as a bare literal has maxPkt 0; deriving a
	// buffer size from it must not yield a negative slice length.
	if got, want := (&Server{}).maxPayload(), UDPC_MAX_DATA; got != want {
		t.Fatalf("bare Server maxPayload() = %d, want %d", got, want)
	}
	if got, want := (&Client{}).maxPayload(), UDPC_MAX_DATA; got != want {
		t.Fatalf("bare Client maxPayload() = %d, want %d", got, want)
	}
}

func TestDescribeMaxPkt(t *testing.T) {
	got := describeMaxPkt(UDPC_MAX_PKT)
	for _, want := range []string{
		"max_pkt=1450",
		"payload=1394",
		"IPv4 datagram 1478 B",
		"IPv6 1498 B",
		"1500:ok",
		"1492:ok",
		"1420:over",
		"1280:over",
		"576:over",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("describeMaxPkt(1450) = %q, missing %q", got, want)
		}
	}

	// 548 is the largest record that never fragments on IPv4 (576 - 20 - 8).
	got = describeMaxPkt(548)
	if !strings.Contains(got, "IPv4 datagram 576 B") || !strings.Contains(got, "576:ok") {
		t.Errorf("describeMaxPkt(548) = %q, want it to fit the 576 minimum", got)
	}
	// ...and it still does not fit the 576 MTU once IPv6 headers are used.
	if !strings.Contains(got, "IPv6 596 B") {
		t.Errorf("describeMaxPkt(548) = %q, missing the IPv6 datagram size", got)
	}
}

func TestNewServerAndClientHonourMaxPkt(t *testing.T) {
	srv, err := NewServer(ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TargetAddr: "tcp://127.0.0.1:1",
		Passwords:  []string{"psk"},
		LogLevel:   "error",
		MaxPkt:     300,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()
	if srv.maxPkt != 300 {
		t.Errorf("server maxPkt = %d, want 300", srv.maxPkt)
	}
	if got, want := srv.maxPayload(), 300-UDPC_HDR_SIZE-UDPC_TRAILER_SIZE; got != want {
		t.Errorf("server maxPayload() = %d, want %d", got, want)
	}

	cli, err := NewClient(ClientConfig{
		ServerAddr: "127.0.0.1:1",
		Passwords:  []string{"psk"},
		MaxPkt:     300,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer cli.Close()
	if cli.maxPkt != 300 {
		t.Errorf("client maxPkt = %d, want 300", cli.maxPkt)
	}
	if got, want := cli.maxPayload(), 300-UDPC_HDR_SIZE-UDPC_TRAILER_SIZE; got != want {
		t.Errorf("client maxPayload() = %d, want %d", got, want)
	}
}

// TestServerSendHonorsMaxPkt proves the runtime budget actually bounds what
// leaves the socket: with max_pkt=300 the server must emit 300-byte records
// (244-byte payloads) rather than the 1450-byte default.
func TestServerSendHonorsMaxPkt(t *testing.T) {
	const maxPkt = 300
	rig := newTestRig(t, false)
	rig.server.maxPkt = maxPkt

	payload := make([]byte, 1000)
	for i := range payload {
		payload[i] = byte(i)
	}
	go rig.sess.upstreamToUdpLoop()
	go func() { _, _ = rig.target.Write(payload) }()

	buf := make([]byte, 4096)
	deadline := time.Now().Add(5 * time.Second)
	largest, total := 0, 0
	for total < len(payload) && time.Now().Before(deadline) {
		if err := rig.client.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
		n, err := rig.client.Read(buf)
		if err != nil {
			continue // read deadline: keep waiting for the remaining frames
		}
		total += n - UDPC_HDR_SIZE - UDPC_TRAILER_SIZE
		if n > largest {
			largest = n
		}
	}
	if total == 0 {
		t.Fatal("no DATA frames received")
	}
	if largest > maxPkt {
		t.Fatalf("largest emitted record is %d bytes, exceeds max_pkt %d", largest, maxPkt)
	}
	if largest != maxPkt {
		t.Fatalf("largest emitted record is %d bytes, want exactly max_pkt %d (the budget should be filled)", largest, maxPkt)
	}
}
