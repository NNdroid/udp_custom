//go:build linux

package tunnel

import (
	"net"
	"sync"
	"testing"
)

// BenchmarkPacketReaderBurst isolates the server/client UDP receive hot path.
// The same benchmark source is copied into the baseline checkout by the
// benchmark workflow, so a PR compares the old recvmsg drain loop and the new
// recvmmsg batch backend with an identical harness.
func BenchmarkPacketReaderBurst(b *testing.B) {
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		b.Fatal(err)
	}
	defer srv.Close()
	_ = srv.SetReadBuffer(4 << 20)

	cli, err := net.DialUDP("udp", nil, srv.LocalAddr().(*net.UDPAddr))
	if err != nil {
		b.Fatal(err)
	}
	defer cli.Close()
	_ = cli.SetWriteBuffer(4 << 20)

	reader := newPacketReader(srv, nil, false)
	payload := make([]byte, 1200)

	// Prime the socket so the first measured receive does not include sender
	// startup scheduling. A small burst also gives recvmmsg a realistic chance
	// to return more than one datagram immediately.
	for i := 0; i < recvBatch*2; i++ {
		if _, err := cli.Write(payload); err != nil {
			b.Fatal(err)
		}
	}

	stop := make(chan struct{})
	var sender sync.WaitGroup
	sender.Add(1)
	go func() {
		defer sender.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := cli.Write(payload); err != nil {
				return
			}
		}
	}()

	b.ReportAllocs()
	var totalBytes int64
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkts, err := reader.next()
		if err != nil {
			b.Fatal(err)
		}
		for j := range pkts {
			totalBytes += int64(len(pkts[j].data))
		}
	}
	b.StopTimer()

	close(stop)
	_ = cli.Close()
	sender.Wait()

	if b.N > 0 {
		b.SetBytes(totalBytes / int64(b.N))
	}
}
