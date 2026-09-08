//go:build !linux

package tunnel

// newPacketReaderOOB returns nil outside Linux: no IP_RECVORIGDSTADDR, so the
// packet reader runs without ancillary data and reports origPort 0.
func newPacketReaderOOB(n int) [][]byte { return nil }

// msgTruncFlag is unused outside Linux (the reader has no OOB buffers there);
// it exists so the shared packet reader compiles on every platform.
const msgTruncFlag = 0
