package tunnel

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

func TestChunkPipeRoundTrip(t *testing.T) {
	app, sess := newChunkPipe()
	payload := bytes.Repeat([]byte{0xA5}, 3*chunkPipeChunk+17) // spans several queued pieces
	go func() {
		if _, err := sess.Write(payload); err != nil {
			t.Errorf("write: %v", err)
		}
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(app, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("round trip mismatch")
	}
}

func TestChunkPipeBackpressure(t *testing.T) {
	app, sess := newChunkPipe()
	done := make(chan error, 1)
	big := make([]byte, chunkPipeBuffer+chunkPipeChunk) // more than the buffer holds
	go func() {
		_, err := sess.Write(big)
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("write returned before any read: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	buf := make([]byte, chunkPipeChunk)
	if _, err := io.ReadFull(app, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("write after drain: %v", err)
	}
}

func TestChunkPipePartialReads(t *testing.T) {
	app, sess := newChunkPipe()
	go func() {
		sess.Write(bytes.Repeat([]byte{7}, 100))
	}()
	first := make([]byte, 13)
	if _, err := io.ReadFull(app, first); err != nil {
		t.Fatalf("read: %v", err)
	}
	rest := make([]byte, 87)
	if _, err := io.ReadFull(app, rest); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(append(first, rest...), bytes.Repeat([]byte{7}, 100)) {
		t.Fatal("partial read mismatch")
	}
}

func TestChunkPipeReadDeadline(t *testing.T) {
	app, sess := newChunkPipe()
	defer sess.Close()
	if err := app.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	st := time.Now()
	_, err := app.Read(make([]byte, 16))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("err=%v, want deadline exceeded", err)
	}
	if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatal("deadline error does not satisfy net.Error.Timeout")
	}
	if time.Since(st) > time.Second {
		t.Fatal("deadline fired late")
	}
}

func TestChunkPipeCloseUnblocksBothEnds(t *testing.T) {
	app, sess := newChunkPipe()
	writeDone := make(chan error, 1)
	go func() {
		// Fill the buffer so the write blocks, then close from the app side.
		_, err := sess.Write(make([]byte, chunkPipeBuffer+chunkPipeChunk))
		writeDone <- err
	}()
	time.Sleep(50 * time.Millisecond)
	app.Close()
	if err := <-writeDone; !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("blocked write err=%v, want io.ErrClosedPipe", err)
	}
	// Bytes already queued before the close stay readable (bufio-style drain),
	// and the queue then reports EOF.
	var drained int
	for {
		n, err := app.Read(make([]byte, 64*1024))
		drained += n
		if err != nil {
			if !errors.Is(err, io.EOF) {
				t.Fatalf("drain err=%v, want io.EOF", err)
			}
			break
		}
	}
	if drained < chunkPipeBuffer {
		t.Fatalf("drained %d bytes, want at least the filled buffer (%d)", drained, chunkPipeBuffer)
	}
	if _, err := sess.Write([]byte("x")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("write after close err=%v, want io.ErrClosedPipe", err)
	}
	// Double close is a no-op.
	if err := app.Close(); err != nil {
		t.Fatalf("double close: %v", err)
	}
}

func TestChunkPipeConcurrentExchange(t *testing.T) {
	app, sess := newChunkPipe()
	const payload = 4 << 20
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer sess.Close()
		data := bytes.Repeat([]byte{0x5A}, payload)
		if _, err := sess.Write(data); err != nil {
			t.Errorf("write: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		defer app.Close()
		buf := make([]byte, 64*1024)
		var got int
		for got < payload {
			n, err := app.Read(buf)
			if err != nil {
				t.Errorf("read at %d: %v", got, err)
				return
			}
			got += n
		}
	}()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("exchange deadlocked")
	}
}

// TestChunkPipePartialReadReleasesSpace pins the buffer accounting: reads
// smaller than a queued chunk leave a partially consumed head, and the byte
// occupancy must follow the CONSUMED amount. The pump's record-sized reads
// do exactly this at line rate — a leak here made every writer see a
// permanently full queue and blocked the application mid-stream.
func TestChunkPipePartialReadReleasesSpace(t *testing.T) {
	app, sess := newChunkPipe()
	done := make(chan error, 1)
	total := chunkPipeBuffer * 3
	go func() {
		_, err := sess.Write(bytes.Repeat([]byte{1}, total))
		done <- err
	}()
	buf := make([]byte, 1394) // sub-chunk-sized reads leave partial heads
	var got int
	for got < total {
		n, err := app.Read(buf)
		if err != nil {
			t.Fatalf("read at %d: %v", got, err)
		}
		got += n
	}
	if err := <-done; err != nil {
		t.Fatalf("write: %v", err)
	}
}
