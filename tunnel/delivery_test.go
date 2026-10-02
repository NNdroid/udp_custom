package tunnel

import (
	"bytes"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestOrderedDeliveryBackpressureOwnershipAndOrder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		done := make(chan struct{})
		gate := make(chan struct{})
		var got bytes.Buffer
		d := newOrderedDelivery(4, done, func(p []byte) error { <-gate; got.Write(p); return nil }, func(err error) { t.Error(err) }, func(uint64) {})
		defer func() { d.close(); close(done) }()
		p := []byte("B")
		if !d.offer(2, p) || !d.offer(1, []byte("A")) {
			t.Fatal("admission failed")
		}
		p[0] = 'X'
		synctest.Wait()
		if d.delivered.Load() != 0 {
			t.Fatal("acknowledged before application read")
		}
		if !d.offer(4, []byte("D")) || !d.offer(3, []byte("C")) {
			t.Fatal("could not fill bounded queue")
		}
		if d.offer(5, []byte("E")) {
			t.Fatal("accepted beyond receive window")
		}
		if !d.offer(2, []byte("duplicate")) {
			t.Fatal("duplicate should be harmless")
		}
		close(gate)
		synctest.Wait()
		if got.String() != "ABCD" {
			t.Fatalf("got %q", got.String())
		}
		if ack, _, credit := d.snapshot(); ack != 4 || credit != 4 {
			t.Fatalf("ack=%d credit=%d", ack, credit)
		}
	})
}

func TestOrderedDeliveryConcurrentAdmission(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		done := make(chan struct{})
		gate := make(chan struct{})
		var got bytes.Buffer
		d := newOrderedDelivery(128, done, func(p []byte) error { <-gate; got.Write(p); return nil }, func(err error) { t.Error(err) }, func(uint64) {})
		defer func() { d.close(); close(done) }()
		var wg sync.WaitGroup
		for i := 1; i <= 128; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				if !d.offer(uint64(i), []byte{byte(i)}) {
					t.Errorf("rejected %d", i)
				}
			}(i)
		}
		wg.Wait()
		close(gate)
		synctest.Wait()
		if got.Len() != 128 {
			t.Fatalf("got %d bytes", got.Len())
		}
		for i, v := range got.Bytes() {
			if v != byte(i+1) {
				t.Fatalf("offset %d got %d", i, v)
			}
		}
	})
}

func TestDelayedACKSinglePairAndClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var d delayedACK
		acks := make(chan uint64, 8)
		send := func(n uint64) { acks <- n }
		d.queue(1, send)
		synctest.Wait()
		if len(acks) != 0 {
			t.Fatal("single frame ACK was not delayed")
		}
		time.Sleep(time.Millisecond)
		synctest.Wait()
		if len(acks) != 1 || <-acks != 1 {
			t.Fatal("single ACK did not flush")
		}
		d.queue(2, send)
		d.queue(3, send)
		if len(acks) != 1 || <-acks != 3 {
			t.Fatal("pair ACK did not coalesce")
		}
		d.queue(4, send)
		d.close()
		time.Sleep(2 * time.Millisecond)
		synctest.Wait()
		if len(acks) != 0 {
			t.Fatal("ACK after close")
		}
	})
}
