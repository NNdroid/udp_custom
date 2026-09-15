# Design doc, Option B: automatic MTU probing (probe + commit)

Status: **implemented** (`tunnel/mtuprobe.go`, `mtu_probe` config). The
prerequisite "Option D" landed first (`tunnel/mtu.go`: `max_pkt` is runtime
configurable, and the sender's chunking ceiling moved from a compile-time
constant to a runtime value) — this design only changes **how** that value is
filled in: from manual configuration to automatic probing.

---

## 1. Goals and non-goals

**Goal**: when a session is established, the client automatically discovers the
largest v2 record size the current path can carry, and both ends converge their
send-chunking ceiling on it. Zero manual configuration; the symptom of UDP
being black-holed by narrow-MTU paths (1420-byte tunnels etc.) self-heals.

**Non-goals**:
- No kernel-level PMTUD (`IP_RECVERR`/errqueue is not portable in Go, and IPv6
  paths have no fragmentation at all);
- No mid-session downgrade (see the hard constraint in §5: the cap is
  **immutable** for the session lifetime);
- No coverage of "path narrows mid-session" (re-probing happens only on new
  sessions / TTL expiry / reconnect).

## 2. Why it must be "new in-session commands", not a handshake TLV

`parseTargetTLV` (protocol.go) validates with **exact lengths**, and the server
explicitly rejects `trailing bytes in payload`. Appending any field to the SYN
would be rejected by older servers with
`[Handshake] Rejected SYN ... trailing bytes in payload`, failing the handshake
outright.

New commands are different: an older server drops unknown commands during the
structural check in `decodeUDPCFrame` → `validUDPCCommand` — **before MAC
verification** — which means "handshake and session are completely unaffected;
the probe simply never gets a reply → timeout falls back to the default". This
is the only naturally backward-compatible path.

## 3. Wire format (3 new commands, zero record-format changes)

The record format stays `40 + PayloadLen + 16`. Only command numbers and shapes
are added:

```go
CMD_MTU_PROBE       = 0x0A
CMD_MTU_PROBE_REPLY = 0x0B
CMD_MTU_COMMIT      = 0x0C
```

`validUDPCCommand`'s upper bound moves from `CMD_PATH_RESPONSE` to
`CMD_MTU_COMMIT`; `validSessionFrameShape` gains:

| Command | Seq | Payload |
| :--- | :--- | :--- |
| `MTU_PROBE` | 0 | `probeID[8] || zeros`, length = `N - 56` (`8 ≤ len ≤ ceiling-56`) |
| `MTU_PROBE_REPLY` | 0 | **byte-for-byte echo** of the request payload (same length, incl. probeID and padding) |
| `MTU_COMMIT` | 0 | exactly 2 bytes: `uint16 BE` of the converged record size N |

- All three are established-session records: `PacketNo != 0`, protected by the
  direction's AEAD + replay window. Probes are therefore **unforgeable**, and
  replays are rejected by the replay window (no amplification).
- probeID lets the client match replies (prevents cross-talk between concurrent
  probes); padding bytes exist to reach the length and carry no semantics.
- **Why COMMIT is needed**: the server only knows how large a probe it
  received; it cannot know whether its own REPLY arrived, so it cannot infer
  "how large downstream can be". The client is the only party that knows both
  directions' results and must publish it explicitly.

## 4. Information flow

```
Client                                   Server
  │ handshake ACK arrives (session keys exist)
  │ PROBE(N=1450) ──────────────────────► received ⇒ upstream ≥ N
  │                                       REPLY(echo N) ──┐
  │ ◄────────────────────────────────────┴─ received ⇒ downstream ≥ N
  │ N passed ⇒ try larger? (ladder already at top) ⇒ converge on N
  │ COMMIT(N) ──────────────────────────► sess.maxPkt = min(local, N)
  │ DATA chunked at N from now on         DATA chunked at N from now on
```

One successful probe validates both directions at once. A failure (timeout)
only says "one direction cannot carry N" — step down and retry.

## 5. Hard constraint: convergence must happen before the data path opens

Per the wire spec: retransmissions must reuse the **exact same** encoded bytes
(same PacketNo/nonce/ciphertext/tag) → an in-flight oversized frame **cannot be
re-chunked**. If probing started after the data pumps, the application's first
large writes would be encoded at 1450, black-holed by the path, and then
retransmitted verbatim until the session's retransmit budget is exhausted.

Therefore:
- **Client**: probing is inserted inside `establish()`, after `handshake()`
  returns and **before** the pump goroutines start, blocking until convergence
  or give-up.
- **Cap is immutable within a session**: `clientSession.sendCap` and
  `ServerSession.maxPkt` are fixed at establishment and never change.
  Re-probing only affects **new** sessions. This eliminates all the complexity
  of mid-session resizing (pump buffer reallocation, TCP/UDP chunking semantics
  changes, old-size frames in the unacked table).
- The server does not need to delay its pumps: the client sends no DATA before
  its pumps start, so the server's `upstreamToUdpLoop` simply idles, the
  target's TCP receive buffer absorbs naturally, and the tunnel already has
  send-window backpressure.

## 6. Client probe state machine

```
Ladder: [1450, 1200, 1000, 800, 548]   // 548 = 576 MTU - 20 IP - 8 UDP,
                                       // the largest never-fragmenting record on IPv4
Start   = min(configured max_pkt, ladder head)  // max_pkt is the ceiling; probing never exceeds it
Per rung: at most 2 probes, 300ms timeout each
Success:  stop at this rung ⇒ converged
Failure:  step down; bottom rung failing ⇒ converge on max_pkt ("probe useless, use config")
Worst:    5 rungs × 2 probes × 300ms ≈ 3s; typical (1500 path): 1 round trip, ≈ 0 extra latency
```

- **Cache**: lives on `Client` (one server address per client),
  `effectiveMaxPkt` + `probedAt`, TTL 10 minutes. `establish` checks the cache
  first; a hit costs nothing.
- **Re-probe triggers (v1)**: TTL expiry, `AutoReconnect` reconnect (hooked to
  the `Reconnecting` event), `Client` rebuild. A passive trigger on "consecutive
  large-frame first-send failures" is **not implemented** (ARQ does not bucket
  stats by size, and even if triggered it would only benefit new sessions —
  low value) — listed as future work.
- **Parallel with target dial**: probing needs session keys, so it cannot
  overlap with the SYN, but the target connection and probing can run in
  parallel (the server already dials the target during the handshake).

## 7. Server changes

1. The control-frame switch in `handleIncomingFrame` gains two cases:
   - `CMD_MTU_PROBE`: validate shape and length ceiling, reply with
     `CMD_MTU_PROBE_REPLY` (byte-for-byte payload echo, fresh PacketNo) via
     `sendToSession`;
   - `CMD_MTU_COMMIT`: `sess.maxPkt = clamp(uint16(N), maxPktFloor, min(local
     maxPkt, maxPktCeiling))`, INFO log.
2. `ServerSession` gains `maxPkt` (0 = no commit yet ⇒ use the local value);
   the `sendData` guard and `upstreamToUdpLoop` chunking use
   `sess.maxPayload()` = `min(server.maxPayload(), sess.maxPkt)`.
3. **Pump chunking semantics** (key): the read buffer stays sized by the
   **local** cap (never truncating the target's UDP datagrams); after reading,
   process against the session cap:
   - `tcp` target: one read chunk splits into k DATA frames (stream semantics
     unchanged);
   - `udp` target: one datagram = one DATA frame (datagram-boundary semantics
     must not be split); a datagram larger than the session cap is WARN +
     dropped — on a narrow path it could not have been delivered anyway, and
     now it is at least a visible log line.

## 8. Compatibility matrix

| Combination | Behavior |
| :--- | :--- |
| Old client + new server | Old client never probes ⇒ zero change; the new server's extra switch cases do not affect existing commands |
| New client + old server | `validUDPCCommand` upper bound not extended ⇒ probes are dropped at the **decode stage** (before auth) ⇒ 300ms×2 timeouts ⇒ every rung fails ⇒ fall back to `max_pkt`. Handshake and session unaffected; cost is ~3s extra on the first session (can be disabled with `mtu_probe=false`) |
| Both new | Full functionality |
| Probes swallowed by middleboxes | Same as above, fall back to the default (this is exactly today's behavior — never worse) |

**During mixed-version rollouts Option B effectively does not exist** — accepting
this design means both ends must be upgraded together for it to take effect.

## 9. Security analysis

- Probe/echo/commit all ride the session AEAD + PacketNo replay window:
  unforgeable, unreplayable.
- Downgrade inducement: an on-path attacker that persistently drops large
  probes can force the client to a low rung (reduced throughput), but that is
  the same DoS as "just drop the data" — no new attack surface. No extra
  countermeasure (e.g. cross-probe consistency voting) is implemented.
- Probe packets are "as large as possible legitimate records"; from a DPI
  perspective they are indistinguishable from ordinary large DATA frames.
- The server must enforce the PROBE length ceiling (≤ ceiling-56) so a forged
  oversized payload cannot drive `MarshalBinary` error paths.

## 10. Configuration surface

| Field | Side | Default | Semantics |
| :--- | :--- | :--- | :--- |
| `mtu_probe` | client | `true` | false = never probe, `max_pkt` applies verbatim (for debugging / known paths) |
| `mtu_probe` | server | `true` | false = drop probes, client auto-falls back (server-side kill switch) |
| `max_pkt` | both | `1450` | **probe ceiling + fallback value**; setting it explicitly does NOT disable probing (to "pin" the value use `max_pkt=X` + `mtu_probe=false` — no implicit traps) |

## 11. Implementation checklist (~600 lines incl. tests)

| File | Content |
| :--- | :--- |
| `tunnel/protocol.go` | 3 command constants, `validUDPCCommand` upper bound, 3 `validSessionFrameShape` cases, `mtuProbeBase`/`mtuCommitSize` |
| `tunnel/mtuprobe.go` (new) | Client prober state machine + `Client` cache + timeout/ladder logic (transport injected via `dialer.Send`, replaceable in tests) |
| `tunnel/client.go` | `establish()` wiring (after handshake, before pumps), `clientSession.sendCap`, `localToRemote`/`sendData` use sendCap, `ClientConfig.MtuProbe` |
| `tunnel/server.go` | `ServerSession.maxPkt`, two control cases, pump chunking (TCP split frames / UDP drop+warn), `ServerConfig.MtuProbe` |
| `main.go` + 2 config templates + README | Pass-through and documentation |
| Tests | Shape positive/negative cases; PROBE→REPLY echo assertions on the rig; DATA-size assertions after COMMIT; prober against a fake server (answers only ≤ X / never answers) to verify convergence and fallback; full regression + cross-compile matrix |

## 12. The 4 decisions the user had to make

1. **Ladder values** `1450/1200/1000/800/548` with 2 attempts per rung and a
   300ms timeout — accepted?
2. **Extra latency on the first session**: typically +1 RTT, worst case +3s in
   mixed-version deployments. Accept, or change "probe failure ⇒ give up" to
   "on failure skip the remaining ladder and fall back immediately" (faster but
   may miss intermediate rungs)?
3. **`mtu_probe` default**: on by default (recommended, mixed-version has the
   fallback safety net) or off by default (zero risk, but nobody would turn it
   on)?
4. **Oversized UDP-target datagrams**: WARN + drop (this design's choice) or
   WARN + still frame-split (breaks datagram-boundary semantics — not
   recommended)?

All four were resolved as recommended above; implemented per the §11 checklist.
The change touches the wire protocol, so both ends (including myssh pulling the
new tag) must upgrade together.
