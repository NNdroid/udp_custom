package main

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// This file implements the standard Noise protocol handshake
//
//	Noise_NK_25519_ChaChaPoly_BLAKE2s
//
// as specified by the Noise Protocol Framework (revision 34). The message
// layout, hashing order (transcript), key derivation and Split() all follow the
// spec exactly; nk_conformance_test.go cross-checks every step against
// github.com/flynn/noise as an independent oracle.
//
// NK pattern (one round trip, responder's static key is known out of band —
// here: the server's `privkey`, published to clients as the Noise public key):
//
//	-> e, es   (client msg1: ephemeral + DH with the server's static key)
//	<- e, ee   (server msg2: ephemeral + DH between the two ephemerals)
//
// Both sides then Split() the chaining key into two transport keys:
// k1 (client -> server) and k2 (server -> client).
//
// DOCUMENTED DEVIATION (transport phase only): the spec calls for a
// monotonically increasing internal nonce per transport message. This protocol
// retransmits frames, and a retransmitted frame is byte-identical, so the
// receiver must be able to open the same (key, nonce, ciphertext) triple twice.
// We therefore derive the nonce from the frame Seq — nonce = LE64(Seq) — which
// is exactly the QUIC/TLS record-protection pattern (RFC 9001 §5.3 derives a
// per-packet nonce from the packet number). Keys, cipher, transcript and AAD
// are unchanged; only the nonce source differs.
const (
	// 33 bytes, i.e. longer than BLAKE2s' 32-byte hash output, so the spec
	// requires h = HASH(protocol_name) rather than the name itself (names
	// shorter than the hash length are zero-padded instead).
	noiseProtocolName = "Noise_NK_25519_ChaChaPoly_BLAKE2s"

	// e (32) + AEAD tag over the (empty) payload (16).
	noiseMsg1Size = 32 + 16
	noiseMsg2Size = 32 + 16
)

type NoiseKeyPair struct {
	PrivateKey [32]byte
	PublicKey  [32]byte
}

func GenerateNoiseKeyPair() (*NoiseKeyPair, error) {
	var kp NoiseKeyPair
	if _, err := rand.Read(kp.PrivateKey[:]); err != nil {
		return nil, err
	}
	kp.PrivateKey[0] &= 248
	kp.PrivateKey[31] &= 127
	kp.PrivateKey[31] |= 64

	pub, err := curve25519.X25519(kp.PrivateKey[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	copy(kp.PublicKey[:], pub)
	return &kp, nil
}

func ParseNoiseKey(s string) ([32]byte, error) {
	var key [32]byte
	s = strings.TrimSpace(s)
	if len(s) == 64 {
		b, err := hex.DecodeString(s)
		if err == nil && len(b) == 32 {
			copy(key[:], b)
			return key, nil
		}
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err == nil && len(b) == 32 {
		copy(key[:], b)
		return key, nil
	}
	b, err = base64.RawStdEncoding.DecodeString(s)
	if err == nil && len(b) == 32 {
		copy(key[:], b)
		return key, nil
	}
	return key, errors.New("invalid key format: expected 32-byte hex or base64 key")
}

func FormatNoiseKey(key [32]byte) (hexStr, b64Str string) {
	return hex.EncodeToString(key[:]), base64.StdEncoding.EncodeToString(key[:])
}

func blake2sHash() hash.Hash {
	h, _ := blake2s.New256(nil)
	return h
}

// generateEphemeral returns a clamped Curve25519 keypair (GENERATE_KEYPAIR).
func generateEphemeral() (priv, pub [32]byte, err error) {
	if _, err = rand.Read(priv[:]); err != nil {
		return priv, pub, err
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	p, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return priv, pub, err
	}
	copy(pub[:], p)
	return priv, pub, nil
}

// dh performs DH and rejects a degenerate (all-zero) output, as required by
// the spec ("if the output is all-zero, abort").
func dh(priv, pub []byte) ([]byte, error) {
	out, err := curve25519.X25519(priv, pub)
	if err != nil {
		return nil, err
	}
	var zero [32]byte
	if subtleEqual(out, zero[:]) {
		return nil, errors.New("noise: degenerate DH output")
	}
	return out, nil
}

func subtleEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// symmetricState is the Noise SymmetricState (spec §5.1): chaining key,
// handshake hash, cryptographic key and the handshake message nonce.
type symmetricState struct {
	ck   [32]byte
	h    [32]byte
	aead cipher.AEAD // nil until InitializeKey
	n    uint64      // reset to 0 by every InitializeKey
}

// newSymmetricState implements InitializeSymmetric(protocol_name):
//
//	if len(protocol_name) <= HASHLEN: h = protocol_name zero-padded to HASHLEN
//	else:                            h = HASH(protocol_name)
//
// and ck = h.
func newSymmetricState() *symmetricState {
	var h [32]byte
	if len(noiseProtocolName) <= len(h) {
		copy(h[:], noiseProtocolName)
	} else {
		hh := blake2sHash()
		hh.Write([]byte(noiseProtocolName))
		copy(h[:], hh.Sum(nil))
	}
	s := &symmetricState{ck: h, h: h}
	// The spec initialises with h = protocol_name and then immediately
	// MixHash(prologue). Our prologue is empty, but the MixHash still runs and
	// hashes h once — skipping it silently diverges from every conformant
	// implementation. Note that MixHash only advances h; ck stays as it was.
	s.mixHash(nil)
	return s
}

// nkInit builds the NK SymmetricState:
//
//	h  = HASH(protocol_name)      (name is 33 bytes, longer than the hash)
//	h  = HASH(h || prologue)      (prologue is empty for us)
//	h  = HASH(h || rs)            (responder's static key is a pre-message)
//	ck = HASH(protocol_name)      (unchanged by MixHash)
//
// Both peers must run all three hashing steps — the pre-message is what binds
// the handshake to the server's long-term key.
func nkInit(responderStaticPub []byte) *symmetricState {
	s := newSymmetricState()
	s.mixHash(responderStaticPub)
	return s
}

// InitializeSymmetric is only used for the (unused here) prologue case; kept
// for spec completeness.
func (s *symmetricState) mixHash(data []byte) {
	h := blake2sHash()
	h.Write(s.h[:])
	h.Write(data)
	sum := h.Sum(nil)
	copy(s.h[:], sum)
}

// MixKey: HKDF(ck, ikm) → new ck + key (nonce resets to 0).
func (s *symmetricState) mixKey(ikm []byte) {
	kdf := hkdf.New(blake2sHash, ikm, s.ck[:], nil)
	out := make([]byte, 64)
	if _, err := io.ReadFull(kdf, out); err != nil {
		panic("noise: hkdf failed: " + err.Error())
	}
	copy(s.ck[:], out[:32])
	var key [32]byte
	copy(key[:], out[32:])
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		panic("noise: chacha20poly1305 failed: " + err.Error())
	}
	s.aead = aead
	s.n = 0
}

func (s *symmetricState) handshakeNonce() []byte {
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], s.n)
	return nonce[:]
}

// EncryptAndHash: ENCRYPT(k, n, ad=h, plaintext) then MixHash(ciphertext).
func (s *symmetricState) encryptAndHash(plaintext []byte) []byte {
	if s.aead == nil {
		out := append([]byte(nil), plaintext...)
		s.mixHash(out)
		return out
	}
	ct := s.aead.Seal(nil, s.handshakeNonce(), plaintext, s.h[:])
	s.n++
	s.mixHash(ct)
	return ct
}

// DecryptAndHash: DECRYPT(k, n, ad=h, ciphertext) then MixHash(ciphertext).
func (s *symmetricState) decryptAndHash(ciphertext []byte) ([]byte, error) {
	if s.aead == nil {
		s.mixHash(ciphertext)
		return ciphertext, nil
	}
	pt, err := s.aead.Open(nil, s.handshakeNonce(), ciphertext, s.h[:])
	if err != nil {
		return nil, err
	}
	s.n++
	s.mixHash(ciphertext)
	return pt, nil
}

// Split: HKDF(ck, empty) → k1 (initiator -> responder), k2 (responder -> initiator).
func (s *symmetricState) split() (k1, k2 []byte) {
	kdf := hkdf.New(blake2sHash, nil, s.ck[:], nil)
	out := make([]byte, 64)
	if _, err := io.ReadFull(kdf, out); err != nil {
		panic("noise: hkdf failed: " + err.Error())
	}
	return out[:32], out[32:]
}

// NoiseCipherState wraps one ChaCha20-Poly1305 transport key.
type NoiseCipherState struct {
	aead cipher.AEAD
}

func newNoiseCipherState(key []byte) (*NoiseCipherState, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &NoiseCipherState{aead: aead}, nil
}

// seqNonce derives the 12-byte AEAD nonce from the frame sequence number.
//
// Why not a spec-style local counter: the receiver decrypts frames in DELIVERY
// order, and the ARQ layer reorders (out-of-order frames are buffered and
// drained later) and re-delivers (retransmissions). A counter synced to
// decryption order desyncs from the sender's encryption order on the first
// reordered packet, after which every frame fails to open and the session is
// permanently stuck.
//
// Seq is unique per direction for the lifetime of a session (transport keys are
// per-session, and each key has exactly one encryptor), so Seq yields a
// replay-safe nonce: retransmissions reuse the same ciphertext AND the same
// nonce, which is exactly what the receiver expects.
func seqNonce(seq uint32) [12]byte {
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], uint64(seq))
	return nonce
}

// Encrypt seals plaintext under the nonce derived from seq. The caller must
// pass the same seq it puts into the frame header.
func (s *NoiseCipherState) Encrypt(seq uint32, plaintext []byte) []byte {
	nonce := seqNonce(seq)
	return s.aead.Seal(nil, nonce[:], plaintext, nil)
}

// Decrypt opens ciphertext under the nonce derived from seq. It is a pure
// function: calling it twice with the same input (a retransmitted frame)
// yields the same result and never advances hidden state.
func (s *NoiseCipherState) Decrypt(seq uint32, ciphertext []byte) ([]byte, error) {
	nonce := seqNonce(seq)
	return s.aead.Open(nil, nonce[:], ciphertext, nil)
}

// NoiseSession is the result of a completed handshake.
type NoiseSession struct {
	SendCipher *NoiseCipherState
	RecvCipher *NoiseCipherState

	// HandshakeHash is the final handshake transcript hash h — the Noise
	// channel-binding value. It can be logged or compared out of band to bind
	// this session to the handshake that produced it.
	HandshakeHash [32]byte
}

func newNoiseSession(sendKey, recvKey []byte, h [32]byte) (*NoiseSession, error) {
	sendCipher, err := newNoiseCipherState(sendKey)
	if err != nil {
		return nil, err
	}
	recvCipher, err := newNoiseCipherState(recvKey)
	if err != nil {
		return nil, err
	}
	return &NoiseSession{SendCipher: sendCipher, RecvCipher: recvCipher, HandshakeHash: h}, nil
}

// ClientNK is the initiator side of Noise_NK (the client). The server's static
// public key is known out of band.
type ClientNK struct {
	ss        *symmetricState
	ePriv     [32]byte
	ePub      [32]byte
	serverPub [32]byte
	msg1      []byte
	finished  bool
}

// NewClientNK starts the handshake: it generates the ephemeral keypair and
// processes the "e, es" tokens of message 1.
func NewClientNK(serverPub [32]byte) (*ClientNK, error) {
	c := &ClientNK{ss: nkInit(serverPub[:]), serverPub: serverPub}
	priv, pub, err := generateEphemeral()
	if err != nil {
		return nil, err
	}
	c.ePriv, c.ePub = priv, pub

	// -> e
	c.ss.mixHash(c.ePub[:])
	// -> es
	shared, err := dh(c.ePriv[:], serverPub[:])
	if err != nil {
		return nil, fmt.Errorf("noise: es: %w", err)
	}
	c.ss.mixKey(shared)
	return c, nil
}

// Message1 returns the 48-byte handshake message to send as the Noise part of
// the SYN payload (32B ephemeral + 16B AEAD tag over the empty payload).
func (c *ClientNK) Message1() ([]byte, error) {
	if c.msg1 == nil {
		tag := c.ss.encryptAndHash(nil)
		out := make([]byte, 0, noiseMsg1Size)
		out = append(out, c.ePub[:]...)
		out = append(out, tag...)
		if len(out) != noiseMsg1Size {
			return nil, fmt.Errorf("noise: unexpected msg1 size %d", len(out))
		}
		c.msg1 = out
	}
	return append([]byte(nil), c.msg1...), nil
}

// Finish processes msg2 ("e, ee"), verifies it, and returns the transport
// session. It must be called exactly once, with the ack payload the server
// sent in reply.
func (c *ClientNK) Finish(msg2 []byte) (*NoiseSession, error) {
	if c.finished {
		return nil, errors.New("noise: handshake already finished")
	}
	if len(msg2) != noiseMsg2Size {
		return nil, fmt.Errorf("noise: msg2 is %d bytes, want %d", len(msg2), noiseMsg2Size)
	}
	// <- e
	c.ss.mixHash(msg2[:32])
	// <- ee
	shared, err := dh(c.ePriv[:], msg2[:32])
	if err != nil {
		return nil, fmt.Errorf("noise: ee: %w", err)
	}
	c.ss.mixKey(shared)
	// payload (empty) — verifies the transcript up to here
	if _, err := c.ss.decryptAndHash(msg2[32:]); err != nil {
		return nil, fmt.Errorf("noise: msg2 authentication failed: %w", err)
	}
	k1, k2 := c.ss.split()
	sess, err := newNoiseSession(k1, k2, c.ss.h) // initiator: send k1, recv k2
	if err != nil {
		return nil, err
	}
	c.finished = true
	return sess, nil
}

// NewServerNoiseSession is the responder side of Noise_NK. It consumes the
// client's message 1 and returns the established session plus the 48-byte
// message 2 that must be delivered to the client (carried in the handshake ACK).
func NewServerNoiseSession(serverPrivkey [32]byte, msg1 []byte) (*NoiseSession, []byte, error) {
	if len(msg1) != noiseMsg1Size {
		return nil, nil, fmt.Errorf("noise: msg1 is %d bytes, want %d", len(msg1), noiseMsg1Size)
	}
	serverPub, err := curve25519.X25519(serverPrivkey[:], curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	ss := nkInit(serverPub)

	// -> e
	ss.mixHash(msg1[:32])
	// -> es
	shared, err := dh(serverPrivkey[:], msg1[:32])
	if err != nil {
		return nil, nil, fmt.Errorf("noise: es: %w", err)
	}
	ss.mixKey(shared)
	if _, err := ss.decryptAndHash(msg1[32:]); err != nil {
		return nil, nil, fmt.Errorf("noise: msg1 authentication failed: %w", err)
	}

	// <- e
	ePriv, ePub, err := generateEphemeral()
	if err != nil {
		return nil, nil, err
	}
	ss.mixHash(ePub[:])
	// <- ee
	shared, err = dh(ePriv[:], msg1[:32])
	if err != nil {
		return nil, nil, fmt.Errorf("noise: ee: %w", err)
	}
	ss.mixKey(shared)

	tag := ss.encryptAndHash(nil)
	msg2 := make([]byte, 0, noiseMsg2Size)
	msg2 = append(msg2, ePub[:]...)
	msg2 = append(msg2, tag...)

	k1, k2 := ss.split()
	sess, err := newNoiseSession(k2, k1, ss.h) // responder: send k2, recv k1
	if err != nil {
		return nil, nil, err
	}
	return sess, msg2, nil
}
