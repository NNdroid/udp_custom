//go:build !linux

package tunnel

// newPacketReaderOOB returns nil outside Linux: no IP_RECVORIGDSTADDR, so the
// packet reader runs without ancillary data and reports origPort 0.
func newPacketReaderOOB(n int) [][]byte { return nil }

// msgTruncFlag is unused outside Linux (the reader has no OOB buffers there);
// it exists so the shared packet reader compiles on every platform.
const msgTruncFlag = 0

// msgTruncDataFlag is unused outside Linux: those platforms take the plain
// read path, which cannot report truncation. A datagram larger than the
// receive buffer therefore surfaces as an opaque MAC-authentication failure
// instead of a diagnosed MSG_TRUNC drop (the Linux reader logs it throttled
// and discards). Known platform limitation, not a parse bug.
const msgTruncDataFlag = 0
