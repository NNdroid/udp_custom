package tunnel

import (
	"runtime"
	"testing"
)

// TestReceiveSocketsClampedOnUnsupportedPlatform runs everywhere: a
// receive_sockets > 1 request must either bind the full group (Linux) or be
// clamped to one socket (everywhere else) — never fail startup.
func TestReceiveSocketsClampedOnUnsupportedPlatform(t *testing.T) {
	srv := startTestServer(t, ServerConfig{
		ListenAddr:     "127.0.0.1:0",
		TargetAddr:     "tcp://127.0.0.1:1",
		Passwords:      []string{"rp-psk"},
		LogLevel:       "error",
		ReceiveSockets: 4,
	})
	st := srv.Stats()
	switch runtime.GOOS {
	case "linux":
		if st.ReceiveSockets != 4 {
			t.Fatalf("ReceiveSockets = %d on linux, want the full group of 4", st.ReceiveSockets)
		}
	default:
		if st.ReceiveSockets != 1 {
			t.Fatalf("ReceiveSockets = %d on %s, want clamp to 1", st.ReceiveSockets, runtime.GOOS)
		}
	}
	if srv.bindPort == 0 {
		t.Fatal("server did not bind")
	}
}

// The cap must hold: asking for more than maxReceiveSockets clamps instead of
// exhausting file descriptors.
func TestReceiveSocketsCapped(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SO_REUSEPORT group is Linux-only")
	}
	srv := startTestServer(t, ServerConfig{
		ListenAddr:     "127.0.0.1:0",
		TargetAddr:     "tcp://127.0.0.1:1",
		Passwords:      []string{"rp-psk"},
		LogLevel:       "error",
		ReceiveSockets: 1000,
	})
	if st := srv.Stats(); st.ReceiveSockets != maxReceiveSockets {
		t.Fatalf("ReceiveSockets = %d, want the %d cap", st.ReceiveSockets, maxReceiveSockets)
	}
}
