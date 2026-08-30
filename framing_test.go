package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func TestFramingRoundTripSingle(t *testing.T) {
	msg := []byte("hello, framed tunnel")
	wire, err := EncodeMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) != FrameHeaderSize+len(msg) {
		t.Fatalf("wire length %d, want %d", len(wire), FrameHeaderSize+len(msg))
	}

	asm := NewMessageAssembler(0)
	msgs, err := asm.Feed(wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 || !bytes.Equal(msgs[0], msg) {
		t.Fatalf("got %q, want one message %q", msgs, msg)
	}
	if asm.Pending() != 0 {
		t.Fatalf("pending %d bytes after a complete message", asm.Pending())
	}
}

// The real-world case this exists for: one DATA frame carrying several messages
// (TCP coalescing) and one message split across several DATA frames.
func TestFramingHandlesCoalescedAndSplitStreams(t *testing.T) {
	want := [][]byte{
		[]byte("first"),
		[]byte("second message"),
		{}, // empty message is legal
		bytes.Repeat([]byte("x"), 5000),
	}
	stream, err := EncodeMessages(want...)
	if err != nil {
		t.Fatal(err)
	}

	// Feed one byte at a time (worst-case chunking by the server's TCP reads).
	asm := NewMessageAssembler(0)
	var got [][]byte
	for i := 0; i < len(stream); i++ {
		msgs, err := asm.Feed(stream[i : i+1])
		if err != nil {
			t.Fatalf("byte %d: %v", i, err)
		}
		got = append(got, msgs...)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d messages, want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("message %d mismatch: got %d bytes, want %d bytes", i, len(got[i]), len(want[i]))
		}
	}

	// And the other extreme: the whole stream in one chunk.
	asm2 := NewMessageAssembler(0)
	msgs, err := asm2.Feed(stream)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != len(want) {
		t.Fatalf("single-chunk: got %d messages, want %d", len(msgs), len(want))
	}
	for i := range want {
		if !bytes.Equal(msgs[i], want[i]) {
			t.Fatalf("single-chunk message %d mismatch", i)
		}
	}
}

// Split a message across chunks at every possible offset.
func TestFramingSplitAtEveryBoundary(t *testing.T) {
	msg := bytes.Repeat([]byte("abcdefgh"), 40) // 320 bytes
	stream, err := EncodeMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	for cut := 1; cut < len(stream); cut++ {
		asm := NewMessageAssembler(0)
		if _, err := asm.Feed(stream[:cut]); err != nil {
			t.Fatalf("cut %d first half: %v", cut, err)
		}
		if asm.Pending() != cut {
			t.Fatalf("cut %d: pending %d, want %d", cut, asm.Pending(), cut)
		}
		msgs, err := asm.Feed(stream[cut:])
		if err != nil {
			t.Fatalf("cut %d second half: %v", cut, err)
		}
		if len(msgs) != 1 || !bytes.Equal(msgs[0], msg) {
			t.Fatalf("cut %d: got %d messages", cut, len(msgs))
		}
	}
}

// An oversized length prefix must be rejected and must poison the assembler —
// resynchronising a desynced stream by guessing is worse than failing fast.
func TestFramingRejectsOversizedMessage(t *testing.T) {
	asm := NewMessageAssembler(1024)
	bad := make([]byte, FrameHeaderSize)
	bad[0] = 0x00
	bad[1] = 0x00
	bad[2] = 0x10 // 4096 > 1024
	bad[3] = 0x00
	if _, err := asm.Feed(bad); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("want ErrMessageTooLarge, got %v", err)
	}
	if _, err := asm.Feed([]byte("anything")); !errors.Is(err, ErrAssemblerBroken) {
		t.Fatalf("want ErrAssemblerBroken after a length error, got %v", err)
	}
	asm.Reset()
	good, err := EncodeMessage([]byte("ok"))
	if err != nil {
		t.Fatal(err)
	}
	msgs, err := asm.Feed(good)
	if err != nil || len(msgs) != 1 {
		t.Fatalf("after Reset: msgs=%d err=%v", len(msgs), err)
	}
}

func TestFramingEncodeRejectsOversizedPayload(t *testing.T) {
	if _, err := EncodeMessage(make([]byte, MaxFramedMessage+1)); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("want ErrMessageTooLarge, got %v", err)
	}
	// Exactly at the limit is fine.
	if _, err := EncodeMessage(make([]byte, MaxFramedMessage)); err != nil {
		t.Fatalf("message at the limit must encode: %v", err)
	}
}

// Property-ish test: random messages, random chunking — everything must come
// back in order and intact, which is exactly what the tunnel does to a stream.
func TestFramingRandomChunking(t *testing.T) {
	chunkBuf := make([]byte, 512)
	for iter := 0; iter < 200; iter++ {
		nMsgs := 1 + iter%8
		want := make([][]byte, 0, nMsgs)
		for i := 0; i < nMsgs; i++ {
			size := iter % 300 // includes 0-byte messages
			m := make([]byte, size)
			rand.Read(m)
			want = append(want, m)
		}
		stream, err := EncodeMessages(want...)
		if err != nil {
			t.Fatal(err)
		}

		asm := NewMessageAssembler(0)
		var got [][]byte
		off := 0
		for off < len(stream) {
			rand.Read(chunkBuf[:1])
			n := 1 + int(chunkBuf[0])%64
			if off+n > len(stream) {
				n = len(stream) - off
			}
			msgs, err := asm.Feed(stream[off : off+n])
			if err != nil {
				t.Fatalf("iter %d: %v", iter, err)
			}
			got = append(got, msgs...)
			off += n
		}
		if len(got) != len(want) {
			t.Fatalf("iter %d: got %d messages, want %d", iter, len(got), len(want))
		}
		for i := range want {
			if !bytes.Equal(got[i], want[i]) {
				t.Fatalf("iter %d message %d mismatch (%d vs %d bytes)", iter, i, len(got[i]), len(want[i]))
			}
		}
	}
}

// Framing must survive the tunnel's real chunk size: a large message arrives as
// many UDPC_MAX_PKT-sized DATA frames.
func TestFramingLargeMessageAcrossTunnelChunks(t *testing.T) {
	big := make([]byte, 100*1024) // 100 KiB, > 70 tunnel chunks
	rand.Read(big)
	stream, err := EncodeMessage(big)
	if err != nil {
		t.Fatal(err)
	}
	asm := NewMessageAssembler(0)
	var got [][]byte
	for off := 0; off < len(stream); off += UDPC_MAX_DATA {
		end := off + UDPC_MAX_DATA
		if end > len(stream) {
			end = len(stream)
		}
		msgs, err := asm.Feed(stream[off:end])
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, msgs...)
	}
	if len(got) != 1 || !bytes.Equal(got[0], big) {
		t.Fatalf("got %d messages, want the single 100KiB payload", len(got))
	}
}

// End-to-end through the real tunnel: the client frames 20 messages (several
// larger than one DATA frame), the server chops the target's stream however it
// likes, and the client must still recover every message intact and in order.
func TestFramingEndToEndThroughTunnel(t *testing.T) {
	target := newEchoTarget(t, 0)
	serverUDP := "127.0.0.1:39740"
	srv, err := NewUDPCServer(ServerConfig{
		ListenAddr: serverUDP,
		TargetAddr: target.addr(),
		Passwords:  []string{"psk"},
		LogLevel:   "error",
	})
	if err != nil {
		t.Fatalf("NewUDPCServer: %v", err)
	}
	go srv.Start()
	defer srv.Close()
	time.Sleep(100 * time.Millisecond)

	c := newFakeClient(t, "C", serverUDP, "psk", nil)
	defer c.close()

	// Messages of every shape: empty, small, and several spanning many frames.
	want := [][]byte{{}, []byte("ping")}
	for _, size := range []int{600, UDPC_MAX_DATA - 10, UDPC_MAX_DATA + 500, 40 * 1024} {
		m := make([]byte, size)
		rand.Read(m)
		want = append(want, m)
	}
	stream, err := EncodeMessages(want...)
	if err != nil {
		t.Fatal(err)
	}

	// Client send path: a framed message larger than one DATA frame must be
	// chunked by the client (EncodeUDPCFrame caps a frame at UDPC_MAX_DATA).
	sent := 0
	for off := 0; off < len(stream); off += UDPC_MAX_DATA {
		end := off + UDPC_MAX_DATA
		if end > len(stream) {
			end = len(stream)
		}
		c.send(stream[off:end])
		sent++
	}
	if sent < len(want) {
		t.Fatalf("unexpected: only %d frames for %d messages", sent, len(want))
	}

	// Client receive path: feed every DATA payload to the assembler; the tunnel
	// decides the chunking, not us.
	asm := NewMessageAssembler(0)
	var got [][]byte
	remaining := len(stream)
	for remaining > 0 {
		_, payload := c.readData(5 * time.Second)
		remaining -= len(payload)
		msgs, err := asm.Feed(payload)
		if err != nil {
			t.Fatalf("assemble: %v", err)
		}
		got = append(got, msgs...)
	}
	if remaining != 0 {
		t.Fatalf("stream truncated: %d bytes missing", -remaining)
	}
	if len(got) != len(want) {
		t.Fatalf("recovered %d messages, want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("message %d mismatch (%d vs %d bytes)", i, len(got[i]), len(want[i]))
		}
	}
}

// --- benchmarks ---------------------------------------------------------------

func BenchmarkEncodeMessage(b *testing.B) {
	msg := make([]byte, 1200)
	rand.Read(msg)
	b.SetBytes(int64(len(msg)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := EncodeMessage(msg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMessageAssemblerFeed(b *testing.B) {
	msgs := make([][]byte, 8)
	for i := range msgs {
		msgs[i] = bytes.Repeat([]byte{byte(i)}, 180)
	}
	stream, err := EncodeMessages(msgs...)
	if err != nil {
		b.Fatal(err)
	}
	chunk := make([]byte, len(stream))
	copy(chunk, stream)
	asm := NewMessageAssembler(0)
	b.SetBytes(int64(len(chunk)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := asm.Feed(chunk); err != nil {
			b.Fatal(err)
		}
	}
}
