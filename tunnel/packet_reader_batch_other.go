//go:build !linux

package tunnel

import "net"

// packetBatchState is intentionally empty off Linux. packetReader falls back
// to its portable immediate-deadline drain loop on these platforms.
type packetBatchState struct{}

func newPacketBatchState(_ *net.UDPConn, _ [][]byte, _ [][]byte) packetBatchState {
	return packetBatchState{}
}

func (packetBatchState) drain(_ *packetReader, start int) (end int, handled bool, err error) {
	return start, false, nil
}
