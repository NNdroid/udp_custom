package main

import (
	"bytes"
	"testing"

	"github.com/flynn/noise"
)

// These tests treat github.com/flynn/noise as an independent oracle for the
// Noise_NK_25519_ChaChaPoly_BLAKE2s handshake implemented in noise.go. If our
// transcript ordering, MixKey/Split derivation or AEAD usage ever drifts from
// the spec, these fail.
//
// flynn/noise is a TEST-ONLY dependency: the runtime implementation is the
// spec code in noise.go, which exposes the transport keys we need for the
// Seq-derived nonce scheme (see seqNonce).

func flynnSuite() noise.CipherSuite {
	return noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)
}

// The server's static keypair, used by both sides of every test.
func staticKeypair(t *testing.T) (*NoiseKeyPair, noise.DHKey) {
	t.Helper()
	kp, err := GenerateNoiseKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return kp, noise.DHKey{Private: kp.PrivateKey[:], Public: kp.PublicKey[:]}
}

// Our responder must accept a message 1 produced by the reference initiator,
// and the reference initiator must accept our message 2 — and vice versa.
func TestNK_InteropWithFlynnInitiator(t *testing.T) {
	kp, _ := staticKeypair(t)

	// flynn = initiator (client), we = responder (server).
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: flynnSuite(),
		Pattern:     noise.HandshakeNK,
		Initiator:   true,
		PeerStatic:  kp.PublicKey[:],
	})
	if err != nil {
		t.Fatalf("flynn handshake state: %v", err)
	}
	flynnMsg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("flynn WriteMessage: %v", err)
	}
	if len(flynnMsg1) != noiseMsg1Size {
		t.Fatalf("flynn msg1 is %d bytes, our spec says %d", len(flynnMsg1), noiseMsg1Size)
	}

	// Our responder consumes it.
	sess, msg2, err := NewServerNoiseSession(kp.PrivateKey, flynnMsg1)
	if err != nil {
		t.Fatalf("our responder rejected flynn msg1: %v", err)
	}
	if len(msg2) != noiseMsg2Size {
		t.Fatalf("our msg2 is %d bytes, want %d", len(msg2), noiseMsg2Size)
	}

	// ...and flynn accepts our msg2 and completes.
	if _, _, _, err := hs.ReadMessage(nil, msg2); err != nil {
		t.Fatalf("flynn rejected our msg2: %v", err)
	}
	if sess == nil {
		t.Fatal("no session")
	}
}

// Full two-way interop including transport key equality, verified by having
// flynn and our implementation seal/open each other's transport messages.
func TestNK_TransportKeysMatchFlynn(t *testing.T) {
	kp, _ := staticKeypair(t)

	// flynn initiator ↔ our responder.
	hsI, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: flynnSuite(),
		Pattern:     noise.HandshakeNK,
		Initiator:   true,
		PeerStatic:  kp.PublicKey[:],
	})
	if err != nil {
		t.Fatal(err)
	}
	msg1, _, _, err := hsI.WriteMessage(nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	serverSess, msg2, err := NewServerNoiseSession(kp.PrivateKey, msg1)
	if err != nil {
		t.Fatalf("responder: %v", err)
	}
	_, flynnSend, flynnRecv, err := hsI.ReadMessage(nil, msg2)
	if err != nil {
		t.Fatalf("flynn rejected msg2: %v", err)
	}
	if flynnSend == nil || flynnRecv == nil {
		t.Fatal("flynn did not return transport cipher states")
	}

	// flynnSend = initiator -> responder = our server's RecvCipher.
	// Transport nonce starts at 0, which is exactly seqNonce(0).
	payload := []byte("transport message from flynn")
	ct, err := flynnSend.Encrypt(nil, nil, payload)
	if err != nil {
		t.Fatal(err)
	}
	got, err := serverSess.RecvCipher.Decrypt(0, ct)
	if err != nil {
		t.Fatalf("our RecvCipher could not open flynn's transport message: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("transport mismatch: got %q", got)
	}

	// Reverse direction: our SendCipher ↔ flynnRecv (nonce 0).
	out := serverSess.SendCipher.Encrypt(0, payload)
	got2, err := flynnRecv.Decrypt(nil, nil, out)
	if err != nil {
		t.Fatalf("flynn could not open our transport message: %v", err)
	}
	if !bytes.Equal(got2, payload) {
		t.Fatalf("transport mismatch: got %q", got2)
	}
}

// The mirror image: our initiator ↔ flynn's responder. Proves our client side
// (ClientNK) is spec-conformant too.
func TestNK_OurInitiatorWithFlynnResponder(t *testing.T) {
	kp, flynnStatic := staticKeypair(t)

	hsR, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   flynnSuite(),
		Pattern:       noise.HandshakeNK,
		Initiator:     false,
		StaticKeypair: flynnStatic,
	})
	if err != nil {
		t.Fatal(err)
	}

	client, err := NewClientNK(kp.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	msg1, err := client.Message1()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := hsR.ReadMessage(nil, msg1); err != nil {
		t.Fatalf("flynn responder rejected our msg1: %v", err)
	}
	// flynn returns Split() unswapped: cs1 = hk1 (initiator's send / responder's
	// receive), cs2 = hk2 (responder's send / initiator's receive).
	msg2Resp, flynnRecvR, flynnSendR, err := hsR.WriteMessage(nil, nil)
	if err != nil {
		t.Fatalf("flynn WriteMessage (msg2): %v", err)
	}
	if len(msg2Resp) != noiseMsg2Size {
		t.Fatalf("flynn msg2 is %d bytes, our spec says %d", len(msg2Resp), noiseMsg2Size)
	}
	clientSess, err := client.Finish(msg2Resp)
	if err != nil {
		t.Fatalf("our initiator rejected flynn msg2: %v", err)
	}

	// Transport keys must agree (client -> server direction = flynnRecvR).
	payload := []byte("client transport message")
	ct := clientSess.SendCipher.Encrypt(0, payload)
	got, err := flynnRecvR.Decrypt(nil, nil, ct)
	if err != nil {
		t.Fatalf("flynn could not open our client transport message: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("transport mismatch: got %q", got)
	}

	// server -> client direction = flynnSendR.
	ct2, err := flynnSendR.Encrypt(nil, nil, payload)
	if err != nil {
		t.Fatal(err)
	}
	got2, err := clientSess.RecvCipher.Decrypt(0, ct2)
	if err != nil {
		t.Fatalf("our RecvCipher could not open flynn transport message: %v", err)
	}
	if !bytes.Equal(got2, payload) {
		t.Fatalf("transport mismatch: got %q", got2)
	}
}

// A corrupted / wrong-key handshake message must be rejected.
func TestNK_RejectsTamperedMessage(t *testing.T) {
	kp, _ := staticKeypair(t)
	client, err := NewClientNK(kp.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	msg1, err := client.Message1()
	if err != nil {
		t.Fatal(err)
	}
	other, _ := staticKeypair(t)
	tampered := append([]byte(nil), msg1...)
	tampered[0] ^= 0x01
	if _, _, err := NewServerNoiseSession(other.PrivateKey, tampered); err == nil {
		t.Fatal("tampered msg1 with a foreign key must be rejected")
	}
	// Untampered but with the wrong static key must also fail (different DH).
	wrongServer, _ := staticKeypair(t)
	if _, _, err := NewServerNoiseSession(wrongServer.PrivateKey, msg1); err == nil {
		t.Fatal("msg1 must not authenticate under an unrelated static key")
	}
	// And the right key accepts it.
	if _, _, err := NewServerNoiseSession(kp.PrivateKey, msg1); err != nil {
		t.Fatalf("valid msg1 rejected: %v", err)
	}
}

// Channel binding: both sides must end the handshake with the same transcript
// hash h, and it must depend on the ephemeral keys (i.e. differ per handshake).
func TestNK_ChannelBindingIsSharedAndUnique(t *testing.T) {
	kp, _ := staticKeypair(t)

	client, _ := NewClientNK(kp.PublicKey)
	msg1, _ := client.Message1()
	serverSess, msg2, err := NewServerNoiseSession(kp.PrivateKey, msg1)
	if err != nil {
		t.Fatal(err)
	}
	clientSess, err := client.Finish(msg2)
	if err != nil {
		t.Fatal(err)
	}
	if clientSess.HandshakeHash != serverSess.HandshakeHash {
		t.Fatalf("channel binding mismatch: client %x server %x",
			clientSess.HandshakeHash, serverSess.HandshakeHash)
	}
	var zero [32]byte
	if clientSess.HandshakeHash == zero {
		t.Fatal("channel binding must not be all zero")
	}

	// A second handshake over the same static key must produce a different h.
	client2, _ := NewClientNK(kp.PublicKey)
	msg1b, _ := client2.Message1()
	_, msg2b, _ := NewServerNoiseSession(kp.PrivateKey, msg1b)
	clientSess2, _ := client2.Finish(msg2b)
	if clientSess2.HandshakeHash == clientSess.HandshakeHash {
		t.Fatal("two handshakes produced the same channel binding (ephemerals not mixed in)")
	}
	if clientSess.SendCipher.Encrypt(1, []byte("x"))[0] == clientSess2.SendCipher.Encrypt(1, []byte("x"))[0] {
		t.Fatal("transport keys reused across sessions")
	}
}

// Our own client and server must interoperate without the flynn oracle.
func TestNK_OwnRoundTrip(t *testing.T) {
	kp, err := GenerateNoiseKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClientNK(kp.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	msg1, err := client.Message1()
	if err != nil {
		t.Fatal(err)
	}
	serverSess, msg2, err := NewServerNoiseSession(kp.PrivateKey, msg1)
	if err != nil {
		t.Fatal(err)
	}
	clientSess, err := client.Finish(msg2)
	if err != nil {
		t.Fatal(err)
	}
	if clientSess.HandshakeHash != serverSess.HandshakeHash {
		t.Fatal("channel binding mismatch")
	}

	// Both directions, with out-of-order (Seq-derived) nonces.
	for _, seq := range []uint32{3, 1, 2} {
		ct := clientSess.SendCipher.Encrypt(seq, []byte("up"))
		pt, err := serverSess.RecvCipher.Decrypt(seq, ct)
		if err != nil {
			t.Fatalf("up seq=%d: %v", seq, err)
		}
		if string(pt) != "up" {
			t.Fatalf("up seq=%d payload mismatch", seq)
		}
	}
	for _, seq := range []uint32{7, 5, 6} {
		ct := serverSess.SendCipher.Encrypt(seq, []byte("down"))
		pt, err := clientSess.RecvCipher.Decrypt(seq, ct)
		if err != nil {
			t.Fatalf("down seq=%d: %v", seq, err)
		}
		if string(pt) != "down" {
			t.Fatalf("down seq=%d payload mismatch", seq)
		}
	}
}
