package main

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"
	"time"
)

// benchPayload is a typical DATA payload: UDPC_MAX_DATA minus a header margin.
var benchPayload = make([]byte, 1300)

func init() { rand.Read(benchPayload) }

func benchCipherState(b *testing.B) *NoiseCipherState {
	b.Helper()
	key := make([]byte, 32)
	rand.Read(key)
	s, err := newNoiseCipherState(key)
	if err != nil {
		b.Fatal(err)
	}
	return s
}

// --- Noise (P0-2 hot path) ---------------------------------------------------

func BenchmarkNoiseEncrypt(b *testing.B) {
	s := benchCipherState(b)
	b.SetBytes(int64(len(benchPayload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Encrypt(uint32(i%1000+1), benchPayload)
	}
}

func BenchmarkNoiseDecrypt(b *testing.B) {
	s := benchCipherState(b)
	ct := s.Encrypt(1, benchPayload)
	b.SetBytes(int64(len(benchPayload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.Decrypt(1, ct); err != nil {
			b.Fatal(err)
		}
	}
}

// --- frame codec --------------------------------------------------------------

func BenchmarkFrameEncode(b *testing.B) {
	f := &UDPCFrame{
		Magic: UDPC_MAGIC_DEFAULT, Version: UDPC_VERSION, Cmd: CMD_DATA,
		SessionID: 0x12345678, Seq: 1, Ack: 0, WindowSize: 65535,
		Data: benchPayload,
	}
	b.SetBytes(int64(len(benchPayload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = f.Encode()
	}
}

func BenchmarkFrameDecode(b *testing.B) {
	f := &UDPCFrame{
		Magic: UDPC_MAGIC_DEFAULT, Version: UDPC_VERSION, Cmd: CMD_DATA,
		SessionID: 0x12345678, Seq: 1, Ack: 0, WindowSize: 65535,
		Data: benchPayload,
	}
	wire := f.Encode()
	b.SetBytes(int64(len(benchPayload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := DecodeUDPCFrame(wire, UDPC_MAGIC_DEFAULT); err != nil {
			b.Fatal(err)
		}
	}
}

// --- replay filter ------------------------------------------------------------

func BenchmarkReplayFilterAcceptSequential(b *testing.B) {
	rf := &ReplayFilter{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rf.Accept(uint32(i%0xFFFFFFF0 + 1))
	}
}

func BenchmarkReplayFilterSeenHit(b *testing.B) {
	rf := &ReplayFilter{}
	rf.Accept(42)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !rf.Seen(42) {
			b.Fatal("expected hit")
		}
	}
}

func BenchmarkReplayFilterCheckAndAddMiss(b *testing.B) {
	rf := &ReplayFilter{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rf.CheckAndAdd(uint32(i%0xFFFFFFF0 + 1))
	}
}

// --- port selector ------------------------------------------------------------

func benchPortRange(b *testing.B) *PortRange {
	b.Helper()
	ports, err := ParsePortRangeSpec("25000-25499")
	if err != nil {
		b.Fatal(err)
	}
	pr, err := NewPortRange(ports)
	if err != nil {
		b.Fatal(err)
	}
	return pr
}

func BenchmarkPortSelectorNextRandom(b *testing.B) {
	sel := NewPortSelector(benchPortRange(b), SelectorRandom)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sel.Next()
	}
}

func BenchmarkPortSelectorNextRoundRobin(b *testing.B) {
	sel := NewPortSelector(benchPortRange(b), SelectorRoundRobin)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sel.Next()
	}
}

// --- RTT estimator --------------------------------------------------------------

func BenchmarkRTTEstimatorSample(b *testing.B) {
	e := newRTTEstimator(200*time.Millisecond, 200*time.Millisecond, 10*time.Second)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Sample(time.Duration(20+i%40) * time.Millisecond)
	}
}

// --- send socket pool ------------------------------------------------------------

func BenchmarkSendSockPoolGetHit(b *testing.B) {
	// Find a free port, release it, then repeatedly hit the cached socket.
	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		b.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	probe.Close()

	pool := newSendSockPool(512, nil)
	if _, err := pool.Get(port); err != nil {
		b.Fatalf("prime pool: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := pool.Get(port); err != nil {
			b.Fatal(err)
		}
	}
}

// --- auth HMAC (handshake hot path) ---------------------------------------------

func BenchmarkVerifyAuthHMAC(b *testing.B) {
	var nonce [16]byte
	rand.Read(nonce[:])
	sig := ComputeAuthHMAC(nonce[:], "correct-psk", 1700000000)
	passwords := []string{"wrong1", "wrong2", "correct-psk", "wrong3"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !VerifyAuthHMAC(nonce[:], passwords, 1700000000, sig) {
			b.Fatal("verification failed")
		}
	}
}

// Silence unused import guards for bytes in case benchmarks change.
var _ = bytes.Equal
