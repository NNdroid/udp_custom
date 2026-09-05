package tunnel

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func newTestCipherStates(t *testing.T) (send, recv *NoiseCipherState, key []byte) {
	t.Helper()
	key = make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand key: %v", err)
	}
	send, err := newNoiseCipherState(key)
	if err != nil {
		t.Fatalf("cipher state: %v", err)
	}
	recv, err = newNoiseCipherState(key)
	if err != nil {
		t.Fatalf("cipher state: %v", err)
	}
	return send, recv, key
}

// Round-trip at various sequence numbers, including high ones.
func TestNoiseEncryptDecryptRoundTrip(t *testing.T) {
	send, recv, _ := newTestCipherStates(t)
	plain := []byte("the quick brown fox jumps over the lazy dog")
	for _, seq := range []uint64{1, 2, 42, 0xFFFFFFFF, 0x7FFFFFFF, 1 << 40} {
		ct := send.Encrypt(seq, plain, nil)
		got, err := recv.Decrypt(seq, ct, nil)
		if err != nil {
			t.Fatalf("seq=%d decrypt: %v", seq, err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("seq=%d round-trip mismatch", seq)
		}
	}
}

// THE regression test for P0-2: frames may be decrypted out of order (the ARQ
// layer buffers and drains them), and each decryption must succeed regardless
// of the order in which it happens. The old counter-based nonce broke here.
func TestNoiseDecryptOutOfOrder(t *testing.T) {
	send, recv, _ := newTestCipherStates(t)
	plain := []byte("out-of-order delivery must not break the stream")

	// Encrypt seq 5..9 up front (client encryption order).
	cts := make(map[uint64][]byte, 5)
	for seq := uint64(5); seq <= 9; seq++ {
		cts[seq] = send.Encrypt(seq, plain, nil)
	}
	// Decrypt in arrival order 9,5,7,6,8 — every one must open.
	for _, seq := range []uint64{9, 5, 7, 6, 8} {
		got, err := recv.Decrypt(seq, cts[seq], nil)
		if err != nil {
			t.Fatalf("out-of-order decrypt seq=%d failed: %v", seq, err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("out-of-order decrypt seq=%d mismatch", seq)
		}
	}
}

// A retransmitted frame carries the same ciphertext; the receiver decrypts it
// again. With Seq-derived nonces this must succeed and leave no state behind.
func TestNoiseDecryptRetransmission(t *testing.T) {
	send, recv, _ := newTestCipherStates(t)
	plain := []byte("same ciphertext, same nonce, twice")
	ct := send.Encrypt(7, plain, nil)

	for i := 0; i < 3; i++ {
		got, err := recv.Decrypt(7, ct, nil)
		if err != nil {
			t.Fatalf("retransmission #%d decrypt failed: %v", i, err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("retransmission #%d mismatch", i)
		}
	}
}

// A frame opened under the wrong packet number must fail (that is what makes replay of a
// frame into a different slot detectable) and must not corrupt later frames.
func TestNoiseDecryptWrongSeqFails(t *testing.T) {
	send, recv, _ := newTestCipherStates(t)
	ct := send.Encrypt(5, []byte("payload"), nil)
	if _, err := recv.Decrypt(6, ct, nil); err == nil {
		t.Fatal("decrypt under wrong packet number should fail")
	}
	// The failed attempt must not have consumed anything: seq 5 still opens.
	if got, err := recv.Decrypt(5, ct, nil); err != nil || string(got) != "payload" {
		t.Fatalf("decrypt after failed attempt: %v", err)
	}
}

// Tampered ciphertext must fail to open (AEAD authentication).
func TestNoiseDecryptTamperedFails(t *testing.T) {
	send, recv, _ := newTestCipherStates(t)
	ct := send.Encrypt(3, []byte("authenticate me"), nil)
	ct[len(ct)-1] ^= 0x01
	if _, err := recv.Decrypt(3, ct, nil); err == nil {
		t.Fatal("tampered ciphertext should not decrypt")
	}
}

// The two keys of a session are independent: a frame sealed under kC2S must
// not open under kS2C's receiver and vice versa.
func TestNoiseKeySeparation(t *testing.T) {
	kC2S := make([]byte, 32)
	kS2C := make([]byte, 32)
	rand.Read(kC2S)
	rand.Read(kS2C)

	clientSend, _ := newNoiseCipherState(kC2S)
	serverRecv, _ := newNoiseCipherState(kC2S)
	serverSend, _ := newNoiseCipherState(kS2C)
	clientRecv, _ := newNoiseCipherState(kS2C)

	ct := clientSend.Encrypt(1, []byte("c2s"), nil)
	if got, err := serverRecv.Decrypt(1, ct, nil); err != nil || string(got) != "c2s" {
		t.Fatalf("c2s path broken: %v", err)
	}
	if _, err := clientRecv.Decrypt(1, ct, nil); err == nil {
		t.Fatal("c2s ciphertext must not open under the s2c key")
	}

	ct2 := serverSend.Encrypt(1, []byte("s2c"), nil)
	if got, err := clientRecv.Decrypt(1, ct2, nil); err != nil || string(got) != "s2c" {
		t.Fatalf("s2c path broken: %v", err)
	}
}

// Full Noise_NK key agreement: client and server derive matching transport
// cipher pairs, and the two directions are independent keys.
func TestNoiseSessionAgreement(t *testing.T) {
	kp, err := GenerateNoiseKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	clientNK, err := NewClientNK(kp.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	msg1, err := clientNK.Message1()
	if err != nil {
		t.Fatal(err)
	}
	server, msg2, err := NewServerNoiseSession(kp.PrivateKey, msg1)
	if err != nil {
		t.Fatal(err)
	}
	client, err := clientNK.Finish(msg2)
	if err != nil {
		t.Fatal(err)
	}
	if client.HandshakeHash != server.HandshakeHash {
		t.Fatal("channel binding mismatch")
	}

	ct := client.SendCipher.Encrypt(1, []byte("hello from client"), nil)
	got, err := server.RecvCipher.Decrypt(1, ct, nil)
	if err != nil || string(got) != "hello from client" {
		t.Fatalf("client->server failed: %v", err)
	}

	ct2 := server.SendCipher.Encrypt(1, []byte("hello from server"), nil)
	got2, err := client.RecvCipher.Decrypt(1, ct2, nil)
	if err != nil || string(got2) != "hello from server" {
		t.Fatalf("server->client failed: %v", err)
	}
}
