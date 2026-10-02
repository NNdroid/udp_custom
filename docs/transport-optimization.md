# Throughput and stability changes

Based on `perf/throughput-pipeline` at `c33f390`, retaining its Linux `x/net`
receive batching. The independent `perf/throughput-p0` raw syscall implementation
is not merged.

## Delivery and ownership

Each session has one application/backend writer. Socket readers authenticate and
copy accepted DATA into a queue bounded to 512 frames, including the write in
progress. Sequence distance is bounded as well, leaving room for a missing
prefix. Queue saturation rejects admission and rolls back DATA replay state so
the immutable retransmission can be retried. A slow session cannot park a shared
socket reader. UDP backend writes retain datagram boundaries.

`Server.Start` launches readers once, including concurrent/repeated calls. Two
readers on one socket could otherwise hold each other's read lock during batch
drain and delay a consumed packet until another packet arrives or the socket
closes. This was reproduced under the Linux reuseport acceptance test.

Delivery ACK advances only after the writer completes. SACK reports admission
separately; selectively acknowledged wire buffers remain retained until their
cumulative delivery ACK. This distinguishes reliable storage in a bounded queue
from application delivery. Queue buffers own their bytes and never retain a
socket/decryption scratch view.

## Recovery and compatibility

Handshake flag `1<<2` negotiates recovery independently of FEC. Only negotiated
sessions emit command `0x0e` (SACK). Its authenticated header carries the
cumulative delivery ACK; plaintext is a 2-byte receive credit followed by zero
to eight big-endian 64-bit words. Bits enumerate admitted sequences after ACK.
Trailing empty words are omitted. This covers the complete 512-frame window
without inflating normal empty-bitmap feedback.

Feedback is checked against the sent sequence range. Packet numbers prevent old
feedback from regressing credit. Three later admissions plus a quarter-RTT
reorder guard (at least 5ms) trigger repair of the gap. Timeout repair skips
admitted frames, sends in sequence order, backs off and caps each burst to 16.
Timers follow actual send deadlines and sleep up to one second when idle.
Credit/admission probes recover lost ACKs and window-opening feedback; zero
credit is probed even if a PONG drained the outstanding queue.

Both peers must opt into recovery. `recovery:false`, missing peer capability, or
an older peer preserves the legacy cumulative-ACK format and default 256-frame
window. FEC capability and record authentication remain unchanged. Explicit
`send_window` remains the fixed window with legacy peers, and is an upper bound
on the adaptive window (at most 512) with recovery peers.

## Scheduling, ACK and batching

The congestion window starts at at most 64, grows with acknowledged DATA, and
reduces on loss, at most once per RTT. Receive credit and a hard ceiling bound
outstanding memory. The pacer derives each burst's interval from measured RTT
and the congestion window; initial unknown RTT incurs no synthetic 200ms delay.
DATA, retransmissions and FEC use the same session pacer. Control feedback bypasses
it. This is a bounded TCP-like controller, not BBR or a bandwidth estimator.

Normal delivery ACKs coalesce two frames, with a maximum 1ms wait for a single
frame. Duplicate and gap feedback stays immediate. Immutable DATA/parity slices
enter a 32-frame transmit queue that drains ready frames without a batching
delay. Linux uses `sendmmsg` with `MSG_DONTWAIT`; other platforms use ordinary UDP
writes. Client batches group by source socket and preserve each chosen remote
port. Server batches pin reply sockets against LRU eviction. Partial sends only
fall back for the unsent suffix; permanent socket failures retain the existing
repair behavior.

FEC skips sender copies and timers after bootstrap on clean paths, reactivating
on local retransmission or remote loss feedback. Source lists and shard slabs
are pooled. Complete or unrecoverable receiver blocks avoid constructing shards.
Parity and recovered application payloads still receive independent ownership.

## Verification

Tests cover blocked backends and applications sharing a receiver, concurrent
ordered admission, queue ownership/saturation, ACK timers, full-window SACK,
stale/malformed feedback, lost credit updates, IPv4 partial batch sends,
IPv4/IPv6 socket repair and real UDP delay/loss/reorder/duplicate injection with FEC on/off.
Compatibility tests opt out on the client, server or both ends. Existing tests
accept ACK/DATA reordering and still validate authentication and payloads.

Performance measurements and verification results are recorded in
`validation/throughput-stability.md`. Loopback results do not establish WAN,
DNAT/CGNAT, Android or production throughput.
