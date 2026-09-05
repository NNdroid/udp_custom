package tunnel

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/hkdf"
)

const (
	UDPC_MAGIC_DEFAULT = uint32(0x55445043) // "UDPC"

	// Protocol v2 intentionally has no v1 compatibility mode.
	UDPC_VERSION = uint8(0x02)

	// Command Types
	CMD_HANDSHAKE_SYN = uint8(0x01)
	CMD_HANDSHAKE_ACK = uint8(0x02)
	CMD_DATA          = uint8(0x03)
	CMD_ACK           = uint8(0x04)
	CMD_PING          = uint8(0x05)
	CMD_PONG          = uint8(0x06)
	CMD_FIN           = uint8(0x07)

	// Magic(4)+Version(1)+Cmd(1)+Flags(2)+SessionID(4)+PacketNo(8)+
	// Seq(8)+Ack(8)+Window(2)+PayloadLen(2), followed by payload and a fixed
	// 16-byte authentication tag.
	UDPC_HDR_SIZE     = 40
	UDPC_TRAILER_SIZE = 16
	UDPC_MAC_SIZE     = UDPC_TRAILER_SIZE

	UDPC_MAX_PKT = 1450
	// UDPC_MAX_DATA is the largest plaintext DATA payload: the wire budget
	// minus header and authentication tag (1450-40-16).
	UDPC_MAX_DATA = UDPC_MAX_PKT - UDPC_HDR_SIZE - UDPC_TRAILER_SIZE

	clientNonceSize = 16
	serverNonceSize = 16
	synPayloadBase  = clientNonceSize + 8
	ackPayloadBase  = clientNonceSize + serverNonceSize

	// Target-request TLVs. A SYN may append targetRequestTLVLen bytes
	// (2-byte BE length + requested endpoint, e.g. "tcp://127.0.0.1:22") after
	// the base payload; an ACK may append the endpoint actually granted. Both
	// ride INSIDE the authenticated frame payload, so a request cannot be
	// forged or stripped. No TLV = the server's default target (the fixed
	// single-target behaviour).
	targetRequestTLVLen = 2
	// TargetMaxLen bounds a requested/granted endpoint string. Generous: even
	// "tcp://very-long-hostname.example.internal:65535" is far below it.
	TargetMaxLen = 255
)

// UDPCFrame represents a single protocol packet frame.
//
// Raw is the complete wire form of a RECEIVED frame (header + payload +
// trailer). It borrows the socket read buffer in the internal decode path, so
// like Data it must not be retained past the dispatch. VerifyFrameAuth and the
// AEAD open both need it: the MAC input is Raw minus the trailer and the AEAD
// AAD is Raw's 40-byte header.
type UDPCFrame struct {
	Magic      uint32
	Version    uint8
	Cmd        uint8
	Flags      uint16
	SessionID  uint32
	PacketNo   uint64
	Seq        uint64
	Ack        uint64
	WindowSize uint16
	Data       []byte

	raw []byte
}

// Raw returns the received wire bytes of the frame (nil on frames that were
// built, not decoded).
func (f *UDPCFrame) Raw() []byte { return f.raw }

func (f *UDPCFrame) encodeHeaderInto(buf []byte, dataLen int) {
	binary.BigEndian.PutUint32(buf[0:4], f.Magic)
	buf[4] = f.Version
	buf[5] = f.Cmd
	binary.BigEndian.PutUint16(buf[6:8], f.Flags)
	binary.BigEndian.PutUint32(buf[8:12], f.SessionID)
	binary.BigEndian.PutUint64(buf[12:20], f.PacketNo)
	binary.BigEndian.PutUint64(buf[20:28], f.Seq)
	binary.BigEndian.PutUint64(buf[28:36], f.Ack)
	binary.BigEndian.PutUint16(buf[36:38], f.WindowSize)
	binary.BigEndian.PutUint16(buf[38:40], uint16(dataLen))
}

// MarshalBinary creates an unsealed wire frame. Its zeroed authentication
// trailer must be replaced by SealFrameMAC or SealFrameAEAD before sending.
func (f *UDPCFrame) MarshalBinary() ([]byte, error) {
	if f == nil {
		return nil, errors.New("nil frame")
	}
	if len(f.Data) > int(^uint16(0)) {
		return nil, errors.New("payload exceeds uint16 length")
	}
	total := UDPC_HDR_SIZE + len(f.Data) + UDPC_TRAILER_SIZE
	if total > UDPC_MAX_PKT {
		return nil, fmt.Errorf("frame exceeds maximum packet size: %d", total)
	}
	wire := make([]byte, total)
	f.encodeHeaderInto(wire[:UDPC_HDR_SIZE], len(f.Data))
	copy(wire[UDPC_HDR_SIZE:], f.Data)
	return wire, nil
}

// Encode is retained as a construction helper. Unsealed frames are never
// accepted by protocol v2 receive paths.
func (f *UDPCFrame) Encode() []byte {
	wire, _ := f.MarshalBinary()
	return wire
}

// fireAndForgetBufPool recycles send buffers for CONTROL frames (ACK/PING/
// PONG/FIN): they are sent synchronously and never retained, so the buffer
// goes straight back to the pool. DATA frames cannot use it — their wire
// bytes are retained in the unacked map for retransmission and must stay
// individually allocated.
var fireAndForgetBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, UDPC_MAX_PKT)
		return &b
	},
}

func getFireAndForgetBuf() []byte {
	return (*fireAndForgetBufPool.Get().(*[]byte))[:0]
}

func putFireAndForgetBuf(wire []byte) {
	if cap(wire) == UDPC_MAX_PKT {
		full := wire[:cap(wire)]
		fireAndForgetBufPool.Put(&full)
	}
}

// sealControlFrameAEAD seals an empty-payload control frame (ACK/PING/PONG/
// FIN, PacketNo already assigned) into a pooled buffer. The returned slice is
// only valid until putFireAndForgetBuf is called with it.
func sealControlFrameAEAD(f *UDPCFrame, c *NoiseCipherState) []byte {
	wire := getFireAndForgetBuf()
	wire = wire[:UDPC_HDR_SIZE+UDPC_TRAILER_SIZE]
	n := sealFrameAEADInto(wire, f, c, nil)
	return wire[:n]
}

func frameMACInto(dst []byte, key *[32]byte, msg []byte) {
	h := hmac.New(sha256.New, key[:])
	_, _ = h.Write(msg)
	var sum [sha256.Size]byte
	full := h.Sum(sum[:0])
	copy(dst, full[:UDPC_MAC_SIZE])
}

// macWire authenticates header plus payload with HMAC-SHA256-128.
func macWire(wire []byte, key *[32]byte) error {
	if key == nil {
		return errors.New("frame MAC key is required")
	}
	if len(wire) < UDPC_HDR_SIZE+UDPC_TRAILER_SIZE {
		return errors.New("frame too short")
	}
	msg := wire[:len(wire)-UDPC_TRAILER_SIZE]
	frameMACInto(wire[len(msg):], key, msg)
	return nil
}

func SealFrameMAC(f *UDPCFrame, key *[32]byte) []byte {
	wire, err := f.MarshalBinary()
	if err != nil || macWire(wire, key) != nil {
		return nil
	}
	return wire
}

// VerifyFrameAuth verifies an HMAC-protected handshake frame (SYN/ACK).
// Session frames are AEAD records (OpenFrameAEAD), not HMACs. Protocol v2 has no CRC or unauthenticated mode.
func VerifyFrameAuth(wire []byte, key *[32]byte) error {
	if key == nil {
		return errors.New("frame MAC key is required")
	}
	if len(wire) < UDPC_HDR_SIZE+UDPC_TRAILER_SIZE {
		return errors.New("frame too short")
	}
	msg := wire[:len(wire)-UDPC_TRAILER_SIZE]
	tag := wire[len(msg):]
	var expected [UDPC_MAC_SIZE]byte
	frameMACInto(expected[:], key, msg)
	if !hmac.Equal(tag, expected[:]) {
		return errors.New("frame MAC mismatch")
	}
	return nil
}

// FrameKeys holds the two per-direction record-protection cipher states of an
// established session, from the perspective of the holder: Send seals outgoing
// records (ChaCha20-Poly1305: confidentiality + authenticity), Recv opens
// incoming ones. Direction separation defeats reflection. Both PSK-only and
// Noise sessions use this same record format; they differ only in key
// material (PSK-derived vs forward-secret) — a PSK leak never enables
// forgery, but unlike Noise it does expose past traffic.
type FrameKeys struct {
	Send *NoiseCipherState
	Recv *NoiseCipherState
}

type PSKHandshakeKeys struct {
	SynMAC [32]byte
	AckMAC [32]byte
}

// PSKSessionKeys holds the ChaCha20-Poly1305 record keys of a PSK-only
// session. C2S authenticates AND encrypts client→server records, S2C the
// reverse direction; both are bound to the PSK, both handshake nonces and the
// SessionID. PSK-only records therefore use exactly the same wire format as
// Noise records (header as AAD, Poly1305 tag in the trailer) — they just lack
// Noise's forward secrecy, because the keys derive from the long-lived PSK.
type PSKSessionKeys struct {
	C2S [32]byte
	S2C [32]byte
}

const (
	handshakeKeysInfo = "udp_custom/v2/handshake-keys"
	sessionKeysInfo   = "udp_custom/v2/session-keys-aead"
)

// DerivePSKHandshakeKeys binds direction-separated SYN/ACK keys to the fresh
// client nonce.
func DerivePSKHandshakeKeys(psk string, clientNonce [clientNonceSize]byte) PSKHandshakeKeys {
	kdf := hkdf.New(sha256.New, []byte(psk), clientNonce[:], []byte(handshakeKeysInfo))
	var material [64]byte
	if _, err := io.ReadFull(kdf, material[:]); err != nil {
		panic("udpc: handshake HKDF failed: " + err.Error())
	}
	var out PSKHandshakeKeys
	copy(out.SynMAC[:], material[:32])
	copy(out.AckMAC[:], material[32:])
	return out
}

// DerivePSKSessionKeys binds traffic keys to both peers' nonces and SessionID.
func DerivePSKSessionKeys(psk string, clientNonce [clientNonceSize]byte, serverNonce [serverNonceSize]byte, sessionID uint32) PSKSessionKeys {
	var saltInput [clientNonceSize + serverNonceSize + 4]byte
	copy(saltInput[:clientNonceSize], clientNonce[:])
	copy(saltInput[clientNonceSize:clientNonceSize+serverNonceSize], serverNonce[:])
	binary.BigEndian.PutUint32(saltInput[clientNonceSize+serverNonceSize:], sessionID)
	salt := sha256.Sum256(saltInput[:])

	kdf := hkdf.New(sha256.New, []byte(psk), salt[:], []byte(sessionKeysInfo))
	var material [64]byte
	if _, err := io.ReadFull(kdf, material[:]); err != nil {
		panic("udpc: session HKDF failed: " + err.Error())
	}
	var out PSKSessionKeys
	copy(out.C2S[:], material[:32])
	copy(out.S2C[:], material[32:])
	return out
}

// ClientFrameCiphers builds the client-side FrameKeys: the client seals with
// C2S and opens with S2C.
func (k PSKSessionKeys) ClientFrameCiphers() (*FrameKeys, error) {
	send, err := newNoiseCipherState(k.C2S[:])
	if err != nil {
		return nil, err
	}
	recv, err := newNoiseCipherState(k.S2C[:])
	if err != nil {
		return nil, err
	}
	return &FrameKeys{Send: send, Recv: recv}, nil
}

// ServerFrameCiphers builds the server-side FrameKeys: the server seals with
// S2C and opens with C2S.
func (k PSKSessionKeys) ServerFrameCiphers() (*FrameKeys, error) {
	send, err := newNoiseCipherState(k.S2C[:])
	if err != nil {
		return nil, err
	}
	recv, err := newNoiseCipherState(k.C2S[:])
	if err != nil {
		return nil, err
	}
	return &FrameKeys{Send: send, Recv: recv}, nil
}

func matchSynPSK(wire []byte, passwords []string, clientNonce [clientNonceSize]byte) string {
	for _, psk := range passwords {
		keys := DerivePSKHandshakeKeys(psk, clientNonce)
		if VerifyFrameAuth(wire, &keys.SynMAC) == nil {
			return psk
		}
	}
	return ""
}

// DecodeUDPCFrame parses a frame and returns owned bytes. It does not
// authenticate the result; call VerifyFrameAuth or OpenFrameAEAD next.
func DecodeUDPCFrame(buf []byte, expectedMagic uint32) (*UDPCFrame, error) {
	var frame UDPCFrame
	if err := parseUDPCFrame(buf, expectedMagic, &frame); err != nil {
		return nil, err
	}
	dataLen := len(frame.Data)
	frame.raw = append([]byte(nil), frame.raw...)
	if dataLen > 0 {
		frame.Data = frame.raw[UDPC_HDR_SIZE : UDPC_HDR_SIZE+dataLen]
	}
	return &frame, nil
}

// decodeUDPCFrame is kept as an internal compatibility name while receive
// loops migrate to the explicit parse terminology.
func decodeUDPCFrame(buf []byte, expectedMagic uint32, dst *UDPCFrame) error {
	return parseUDPCFrame(buf, expectedMagic, dst)
}

// parseUDPCFrame performs structural parsing only and borrows buf.
func parseUDPCFrame(buf []byte, expectedMagic uint32, dst *UDPCFrame) error {
	if len(buf) < UDPC_HDR_SIZE+UDPC_TRAILER_SIZE {
		return errors.New("frame too short")
	}
	if len(buf) > UDPC_MAX_PKT {
		return errors.New("frame exceeds maximum packet size")
	}
	magic := binary.BigEndian.Uint32(buf[0:4])
	if expectedMagic != 0 && magic != expectedMagic {
		return errors.New("magic mismatch")
	}
	if buf[4] != UDPC_VERSION {
		return errors.New("unsupported protocol version")
	}
	if !validUDPCCommand(buf[5]) {
		return errors.New("unknown command")
	}
	dataLen := int(binary.BigEndian.Uint16(buf[38:40]))
	expectedLen := UDPC_HDR_SIZE + dataLen + UDPC_TRAILER_SIZE
	if len(buf) != expectedLen {
		return errors.New("invalid payload length")
	}

	*dst = UDPCFrame{
		Magic:      magic,
		Version:    buf[4],
		Cmd:        buf[5],
		Flags:      binary.BigEndian.Uint16(buf[6:8]),
		SessionID:  binary.BigEndian.Uint32(buf[8:12]),
		PacketNo:   binary.BigEndian.Uint64(buf[12:20]),
		Seq:        binary.BigEndian.Uint64(buf[20:28]),
		Ack:        binary.BigEndian.Uint64(buf[28:36]),
		WindowSize: binary.BigEndian.Uint16(buf[36:38]),
		raw:        buf[:len(buf)],
	}
	if dataLen > 0 {
		dst.Data = buf[UDPC_HDR_SIZE : UDPC_HDR_SIZE+dataLen]
	} else {
		dst.Data = nil
	}
	return nil
}

func validUDPCCommand(cmd uint8) bool {
	return cmd >= CMD_HANDSHAKE_SYN && cmd <= CMD_FIN
}

func validSessionFrameShape(frame *UDPCFrame) bool {
	if frame == nil || frame.SessionID == 0 || frame.PacketNo == 0 {
		return false
	}
	switch frame.Cmd {
	case CMD_DATA:
		return frame.Seq != 0
	case CMD_ACK, CMD_PING, CMD_PONG, CMD_FIN:
		return frame.Seq == 0 && len(frame.Data) == 0
	default:
		return false
	}
}

// appendTargetTLV appends the optional length-prefixed endpoint field
// (2-byte BE length + bytes) to a handshake payload. Empty target appends
// nothing, which is the wire form of "use the server's default target".
func appendTargetTLV(payload []byte, target string) []byte {
	if target == "" {
		return payload
	}
	if len(target) > TargetMaxLen {
		return payload // callers reject oversize requests before sealing
	}
	var l [targetRequestTLVLen]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(target)))
	payload = append(payload, l[:]...)
	payload = append(payload, target...)
	return payload
}

// parseTargetTLV decodes one optional target field. ok is false when field is
// empty (TLV absent) or malformed.
func parseTargetTLV(field []byte) (target string, ok bool) {
	if len(field) == 0 {
		return "", false
	}
	if len(field) < targetRequestTLVLen {
		return "", false
	}
	n := int(binary.BigEndian.Uint16(field[:targetRequestTLVLen]))
	if n == 0 || n > TargetMaxLen || len(field) != targetRequestTLVLen+n {
		return "", false
	}
	return string(field[targetRequestTLVLen:]), true
}

// splitSynPayload splits a SYN payload into the optional requested target and
// the optional Noise msg1 (which, when present, is exactly the LAST
// noiseMsg1Size bytes). Anything between the base payload and msg1 must be one
// well-formed target TLV. A payload of just the base part requests the default
// target.
func splitSynPayload(data []byte, hasNoise bool) (target string, msg1 []byte, err error) {
	if len(data) < synPayloadBase {
		return "", nil, errors.New("syn payload too short")
	}
	rest := data[synPayloadBase:]
	if hasNoise {
		if len(rest) < noiseMsg1Size {
			return "", nil, errors.New("syn missing noise msg1")
		}
		msg1 = rest[len(rest)-noiseMsg1Size:]
		rest = rest[:len(rest)-noiseMsg1Size]
	}
	if len(rest) > 0 {
		t, ok := parseTargetTLV(rest)
		if !ok {
			return "", nil, errors.New("invalid target request field")
		}
		target = t
	}
	return target, msg1, nil
}

// splitAckPayload splits a handshake ACK payload into the optional granted
// target and the optional Noise msg2 (the LAST noiseMsg2Size bytes when the
// session is encrypted). An ACK without the TLV grants the default target.
func splitAckPayload(data []byte, hasNoise bool) (granted string, msg2 []byte, err error) {
	if len(data) < ackPayloadBase {
		return "", nil, errors.New("ack payload too short")
	}
	rest := data[ackPayloadBase:]
	if hasNoise {
		if len(rest) < noiseMsg2Size {
			return "", nil, errors.New("ack missing noise msg2")
		}
		msg2 = rest[len(rest)-noiseMsg2Size:]
		rest = rest[:len(rest)-noiseMsg2Size]
	}
	if len(rest) > 0 {
		t, ok := parseTargetTLV(rest)
		if !ok {
			return "", nil, errors.New("invalid granted target field")
		}
		granted = t
	}
	return granted, msg2, nil
}
