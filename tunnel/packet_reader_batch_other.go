//go:build !linux

package tunnel

// Non-Linux platforms retain the portable first-read + burst-drain backend.
type packetReaderBatch struct{}

func (r *packetReader) initPacketReaderBatch() {}

func (r *packetReader) next() ([]udpPacket, error) {
	return r.nextDrain()
}
