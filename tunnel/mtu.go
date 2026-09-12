package tunnel

import (
	"strconv"
	"strings"
)

// Frame size budget.
//
// A v2 record is 40 bytes of header plus the payload plus a 16-byte
// authentication tag, exactly as PROTOCOL_V2.md specifies. How LARGE that
// record may be is a deployment property, not a wire property: the peer's
// receive buffer and the path MTU decide it. Historically the budget was
// frozen at UDPC_MAX_PKT (1450), which produces a 1478-byte IPv4 datagram
// (1450 + 8 UDP + 20 IP) and therefore assumes a 1500-byte path MTU. On a
// tunnel with a smaller MTU — 1420 is typical of WireGuard and friends —
// those datagrams are fragmented in flight, and IPv4 fragments are routinely
// dropped by CGNATs. The symptom is small frames working while large ones
// stall: the ARQ retransmits the identical oversized bytes forever, because a
// retransmission must reuse the exact encoded frame (same packet number,
// nonce, ciphertext and tag) and therefore cannot be re-chunked.
//
// MaxPkt makes the budget configurable. Two rules keep that safe:
//
//  1. It only ever SHRINKS below the ceiling. All receive buffers keep the
//     ceiling size, so a peer that has NOT been reconfigured still receives
//     every frame we send. Lowering the value on one side alone is always
//     safe and never truncates.
//  2. It caps what we SEND — how much payload one DATA record carries. The
//     framing and AEAD layers keep validating against the compile-time
//     ceiling, so no wire-format primitive and no Tier-2 signature changes.
const (
	// maxPktCeiling is the largest record the receive path can accept: every
	// read buffer is sized by UDPC_MAX_PKT. A configured value above it is
	// clamped, because a larger frame would be silently truncated by the
	// peer and then fail authentication.
	maxPktCeiling = UDPC_MAX_PKT

	// maxPktFloor is the smallest record still worth sending: header, tag and
	// 64 bytes of payload. Below this the tunnel is pure overhead.
	maxPktFloor = UDPC_HDR_SIZE + UDPC_TRAILER_SIZE + 64

	// Datagram overhead on top of the UDP payload (the record itself):
	// IPv4 is a 20-byte IP header plus an 8-byte UDP header; IPv6 a 40-byte
	// one plus the same 8 bytes.
	ipv4DatagramOverhead = 28
	ipv6DatagramOverhead = 48

	// mtuProbeMaxPayload is the largest payload an MTU probe may carry: it
	// must always fit one record at the ceiling.
	mtuProbeMaxPayload = maxPktCeiling - UDPC_HDR_SIZE - UDPC_TRAILER_SIZE
)

// pathMTUCheckpoints are the reference path MTUs reported at startup so an
// operator can see at a glance which links the configured frame budget can
// traverse without IPv4 fragmentation (IPv6 never fragments — on those paths
// an oversized datagram is simply dropped).
var pathMTUCheckpoints = []int{1500, 1492, 1420, 1280, 576}

// resolveMaxPkt validates a configured record budget and returns the effective
// one. 0 (field absent) means the ceiling. Out-of-range values are clamped
// with a warning instead of rejected: a tunnel that boots with a safe size
// beats one that refuses to start over a typo.
func resolveMaxPkt(configured int, logger Logger) int {
	switch {
	case configured == 0:
		return maxPktCeiling
	case configured < 0:
		if logger != nil {
			logger.Warnf("max_pkt=%d is negative: using the default %d", configured, maxPktCeiling)
		}
		return maxPktCeiling
	case configured < maxPktFloor:
		if logger != nil {
			logger.Warnf("max_pkt=%d is below the usable minimum: clamping to %d", configured, maxPktFloor)
		}
		return maxPktFloor
	case configured > maxPktCeiling:
		if logger != nil {
			logger.Warnf("max_pkt=%d exceeds the receive budget %d (a larger frame would be truncated by the peer): clamping to %d",
				configured, maxPktCeiling, maxPktCeiling)
		}
		return maxPktCeiling
	}
	return configured
}

// payloadCap is the largest plaintext DATA payload one record may carry.
func payloadCap(maxPkt int) int {
	return maxPkt - UDPC_HDR_SIZE - UDPC_TRAILER_SIZE
}

// effectivePayloadCap resolves a possibly zero (unset / bare-literal) budget
// to the ceiling before deriving the payload cap. Structures built without
// going through NewServer / NewClient must never produce a negative buffer
// size.
func effectivePayloadCap(maxPkt int) int {
	if maxPkt <= 0 {
		return payloadCap(maxPktCeiling)
	}
	return payloadCap(maxPkt)
}

// describeMaxPkt renders the datagram sizes a record budget produces together
// with a per-path-MTU verdict, for the startup log line.
func describeMaxPkt(maxPkt int) string {
	v4 := maxPkt + ipv4DatagramOverhead
	var b strings.Builder
	b.WriteString("max_pkt=")
	b.WriteString(strconv.Itoa(maxPkt))
	b.WriteString(" payload=")
	b.WriteString(strconv.Itoa(payloadCap(maxPkt)))
	b.WriteString(" -> IPv4 datagram ")
	b.WriteString(strconv.Itoa(v4))
	b.WriteString(" B, IPv6 ")
	b.WriteString(strconv.Itoa(maxPkt + ipv6DatagramOverhead))
	b.WriteString(" B |")
	for _, mtu := range pathMTUCheckpoints {
		b.WriteByte(' ')
		b.WriteString(strconv.Itoa(mtu))
		if v4 <= mtu {
			b.WriteString(":ok")
		} else {
			b.WriteString(":over")
		}
	}
	return b.String()
}
