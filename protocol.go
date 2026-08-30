package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash/crc32"
)

const (
	UDPC_MAGIC_DEFAULT = uint32(0x55445043) // "UDPC"
	UDPC_VERSION       = uint8(0x01)

	// Command Types
	CMD_HANDSHAKE_SYN = uint8(0x01)
	CMD_HANDSHAKE_ACK = uint8(0x02)
	CMD_DATA          = uint8(0x03)
	CMD_ACK           = uint8(0x04)
	CMD_PING          = uint8(0x05)
	CMD_PONG          = uint8(0x06)
	CMD_FIN           = uint8(0x07)

	// Header Sizes
	UDPC_HDR_SIZE = 24 // Magic(4)+Ver(1)+Cmd(1)+Flags(2)+SessionID(4)+Seq(4)+Ack(4)+Win(2)+Len(2)
	UDPC_MAX_PKT  = 1450
	UDPC_MAX_DATA = 1350
)

// UDPCFrame represents a single protocol packet frame
type UDPCFrame struct {
	Magic      uint32
	Version    uint8
	Cmd        uint8
	Flags      uint16
	SessionID  uint32
	Seq        uint32
	Ack        uint32
	WindowSize uint16
	Data       []byte
}

func (f *UDPCFrame) Encode() []byte {
	dataLen := len(f.Data)
	buf := make([]byte, UDPC_HDR_SIZE+dataLen+4) // +4 for CRC32
	binary.BigEndian.PutUint32(buf[0:4], f.Magic)
	buf[4] = f.Version
	buf[5] = f.Cmd
	binary.BigEndian.PutUint16(buf[6:8], f.Flags)
	binary.BigEndian.PutUint32(buf[8:12], f.SessionID)
	binary.BigEndian.PutUint32(buf[12:16], f.Seq)
	binary.BigEndian.PutUint32(buf[16:20], f.Ack)
	binary.BigEndian.PutUint16(buf[20:22], f.WindowSize)
	binary.BigEndian.PutUint16(buf[22:24], uint16(dataLen))
	if dataLen > 0 {
		copy(buf[UDPC_HDR_SIZE:], f.Data)
	}
	checksum := crc32.ChecksumIEEE(buf[:UDPC_HDR_SIZE+dataLen])
	binary.BigEndian.PutUint32(buf[UDPC_HDR_SIZE+dataLen:], checksum)
	return buf
}

func DecodeUDPCFrame(buf []byte, expectedMagic uint32) (*UDPCFrame, error) {
	if len(buf) < UDPC_HDR_SIZE+4 {
		return nil, errors.New("frame too short")
	}
	dataLen := int(binary.BigEndian.Uint16(buf[22:24]))
	if len(buf) < UDPC_HDR_SIZE+dataLen+4 {
		return nil, errors.New("invalid payload length")
	}

	checksum := binary.BigEndian.Uint32(buf[UDPC_HDR_SIZE+dataLen : UDPC_HDR_SIZE+dataLen+4])
	calculated := crc32.ChecksumIEEE(buf[:UDPC_HDR_SIZE+dataLen])
	if checksum != calculated {
		return nil, errors.New("checksum mismatch")
	}

	magic := binary.BigEndian.Uint32(buf[0:4])
	if expectedMagic != 0 && magic != expectedMagic {
		return nil, errors.New("magic mismatch")
	}

	frame := &UDPCFrame{
		Magic:      magic,
		Version:    buf[4],
		Cmd:        buf[5],
		Flags:      binary.BigEndian.Uint16(buf[6:8]),
		SessionID:  binary.BigEndian.Uint32(buf[8:12]),
		Seq:        binary.BigEndian.Uint32(buf[12:16]),
		Ack:        binary.BigEndian.Uint32(buf[16:20]),
		WindowSize: binary.BigEndian.Uint16(buf[20:22]),
	}
	if dataLen > 0 {
		frame.Data = make([]byte, dataLen)
		copy(frame.Data, buf[UDPC_HDR_SIZE:UDPC_HDR_SIZE+dataLen])
	}
	return frame, nil
}

// ComputeAuthHMAC generates an HMAC-SHA256 signature for handshake authentication
func ComputeAuthHMAC(nonce []byte, password string, timestamp int64) []byte {
	h := hmac.New(sha256.New, []byte(password))
	h.Write(nonce)
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(timestamp))
	h.Write(tsBuf[:])
	return h.Sum(nil)
}

// VerifyAuthHMAC validates HMAC signature against a list of valid passwords
func VerifyAuthHMAC(nonce []byte, validPasswords []string, timestamp int64, clientSig []byte) bool {
	for _, pass := range validPasswords {
		expected := ComputeAuthHMAC(nonce, pass, timestamp)
		if hmac.Equal(expected, clientSig) {
			return true
		}
	}
	return false
}
