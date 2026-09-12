//go:build linux

package tunnel

import "syscall"

// newPacketReaderOOB allocates the ancillary-data buffers used on Linux to
// recover each datagram's pre-DNAT destination port (IP_RECVORIGDSTADDR).
// Other platforms return nil: the reader then uses plain reads and reports
// origPort 0 for every datagram.
func newPacketReaderOOB(n int) [][]byte {
	oob := make([][]byte, n)
	for i := range oob {
		oob[i] = make([]byte, 512)
	}
	return oob
}

// msgTruncFlag is syscall.MSG_CTRUNC — kept here (platform file) because the
// Windows syscall package does not define it and packet_reader is shared.
const msgTruncFlag = syscall.MSG_CTRUNC

// msgTruncDataFlag is MSG_TRUNC: set in the recvmsg flags when the DATAGRAM
// itself did not fit the buffer (as opposed to its control data). It means
// the peer sent a record larger than this end's frame budget, so the tail is
// gone and authentication can only fail — see packetReader.warnTruncated.
const msgTruncDataFlag = syscall.MSG_TRUNC
