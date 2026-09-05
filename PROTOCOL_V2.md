# udp_custom protocol v2

Protocol v2 is a deliberate, non-compatible replacement for v1. Both peers
must be upgraded together. Implementations must not silently accept v1 frames.

## What changed from v1

| Property | v1 | v2 |
| --- | --- | --- |
| Version byte | `0x01` | `0x02` |
| Fixed header | 24 bytes | 40 bytes |
| Integrity trailer | 4-byte CRC32 | 16-byte HMAC-SHA256-128 (handshake) or Poly1305 tag (session records) |
| DATA sequence and ACK | 32 bit | 64 bit |
| Record packet number | none | independent 64-bit per-direction `PacketNo` |
| ACK/PING/PONG/FIN | no cryptographic authentication | authenticated before any state change |
| PSK-only DATA | CRC only after handshake | **ChaCha20-Poly1305 encrypted** + authenticated, transcript-bound, direction-separated |
| Noise DATA | payload AEAD; header not bound | header is AAD; tag is the common trailer |
| Replay protection | DATA sequence only | every established record, 2048-packet window |
| Handshake ACK routing | no echoed nonce | echoes `ClientNonce`, enabling concurrent handshakes |
| Open mode | possible | removed; at least one non-blank PSK is mandatory |

## Wire record

All integer fields use network byte order. Every record is exactly
`40 + PayloadLen + 16` bytes.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | Magic |
| 4 | 1 | Version (`0x02`) |
| 5 | 1 | Command |
| 6 | 2 | Flags |
| 8 | 4 | SessionID |
| 12 | 8 | PacketNo |
| 20 | 8 | Seq |
| 28 | 8 | Ack |
| 36 | 2 | WindowSize |
| 38 | 2 | PayloadLen |
| 40 | variable | Payload |
| `40 + PayloadLen` | 16 | Authentication tag |

`PacketNo` is independent of ARQ `Seq`. Each direction starts established
records at 1 and increments once for every newly encoded DATA or control
record. A retransmission reuses the complete encoded bytes and therefore the
same packet number, nonce, ciphertext, and tag. Packet number 0 is reserved
for handshake records; exhausting the 64-bit space is fatal rather than
wrapping and reusing a nonce.

DATA requires non-zero `SessionID`, `PacketNo`, and `Seq`. ACK, PING, PONG, and
FIN require non-zero `SessionID` and `PacketNo`, zero `Seq`, and an empty
payload. `Ack` is cumulative and may be piggybacked on authenticated records.

## Authentication modes

SYN and handshake ACK always use HMAC-SHA256 truncated to 16 bytes. HKDF-SHA256
derives separate SYN and ACK keys from the PSK and `ClientNonce`.

For a PSK-only established session, HKDF-SHA256 derives separate client-to-
server and server-to-client **ChaCha20-Poly1305 record keys**. The derivation
binds the PSK, `ClientNonce`, `ServerNonce`, and `SessionID`. Every record —
DATA and control alike — is sealed like a Noise record: the 40-byte header is
the associated data, the payload is encrypted plaintext, and the Poly1305 tag
occupies the common 16-byte trailer. PSK-only traffic is therefore
**confidential and authenticated**, with the same record format as Noise; the
difference is key lifetime, not format. Unlike Noise there is no forward
secrecy: anyone who later obtains the PSK can decrypt past PSK-only traffic.
Deployments that need forward secrecy configure Noise (`privkey`/`pubkey`).

With Noise enabled, Noise_NK supplies separate transport keys. ChaCha20-
Poly1305 uses `00000000 || LE64(PacketNo)` as its 12-byte nonce, the 40-byte
header as associated data, the payload as plaintext/ciphertext, and the common
16-byte trailer as its tag. Control records encrypt an empty payload but still
authenticate the complete header.

## Handshake

The SYN payload is:

```text
ClientNonce[16] || UnixTimestamp[8] || [TargetTLV] || optional Noise msg1[48]
```

The handshake ACK payload is:

```text
ClientNonce[16] || ServerNonce[16] || [GrantedTargetTLV] || optional Noise msg2[48]
```

`TargetTLV` is `Length[2] || endpoint` where endpoint is an ASCII
`tcp://host:port` / `udp://host:port` string (at most 255 bytes). It is
optional: a SYN without it requests the server's default target, and an ACK
without it grants the default target. The TLVs ride inside the MAC-authenticated
payloads, so a request can neither be forged nor stripped.

The ACK MAC covers its header, including the assigned `SessionID`, and its
entire payload. A client routes candidate ACKs by echoed nonce, ignores invalid
MACs while continuing to wait, and only then creates session state. Repeated
authenticated SYNs reuse the cached ACK and session. The cache key includes a
PSK-derived identity so two configured credentials cannot collide by choosing
the same client nonce.

### Per-session target selection

A client MAY request a forwarding endpoint in the SYN (`target` field). The
server honors it only when it matches one of the configured `allowed_targets`
patterns (`*` matches any sequence, `?` one character, applied to the host and
the port; the network must be equal). An empty `allowed_targets` list means
only the default `target` is available. Denied requests are rejected with the
same silent-drop policy as every other handshake failure, so a denied client
simply never receives an ACK. The ACK echoes the endpoint actually granted
(granted TLV present iff the client requested one). Requested endpoints are
authenticated but not confidential: an on-path observer sees which backend a
client names.

## Receive-order invariant

For established records, the receiver applies checks in this order:

1. source-address policy for control records;
2. structural and command-shape validation;
3. HMAC verification or AEAD open;
4. per-direction `PacketNo` replay-window acceptance;
5. ACK, path, liveness, reorder-buffer, delivery, or close state changes.

Authentication failure and replay rejection do not refresh idle timers,
change reply paths, remove in-flight DATA, deliver payload, or close sessions.
