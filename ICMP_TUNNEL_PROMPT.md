# ICMP Tunnel Implementation Prompt (udp_custom / tunnel)

The ICMP variant is **not a protocol rewrite** — it adds a **transport
profile** to `tunnel/`: the v2 record format, Noise/PSK encryption, ARQ, and
target forwarding are all reused; only the carrier changes from UDP to ICMP
Echo Request/Reply.

Part one below is a prompt you can paste directly to a coding agent; the
appendices explain *why each point must be in there* and map mechanisms over,
for your own review of the prompt.

---

## Part 1: The prompt (copy everything below)

```text
# Task

In the E:\GolandProjects\udp_custom repository, add an "ICMP transport
profile" to the tunnel/ package: carry complete udp_custom v2 records over
ICMP Echo Request/Reply, delivering capabilities equivalent to the existing
UDP profile (multi-session, per-session target forwarding, reliable ordered
delivery, encryption + authentication, NAT keepalive), so it can serve as an
alternative path on networks where UDP is blocked or rate-limited per
destination port.

Scope of this phase: server + Go client. Android/myssh clients are out of
scope.

# Background (read carefully, do not re-research)

- Wire spec: PROTOCOL_V2.md — fixed 40-byte header + 16-byte AEAD tag,
  cumulative Ack, per-direction PacketNo with an independent 2048 replay
  window, 64-bit Seq, HMAC-SHA256-128 handshake, ChaCha20-Poly1305 session
  records.
- The existing UDP profile's triad: client spread.go randomizes destination
  ports → firewall DNAT folds them onto a single listen port → server
  origdst_linux.go recovers the pre-DNAT destination port, and sendsock.go
  replies through a socket bound to that port (source-port mirroring). Replies
  pass CGNAT precisely because of this "mirror the observed key" principle.
- Framing/encryption/ARQ are already transport-agnostic: framing.go,
  noise.go, replayfilter, rtt_estimator.go do not depend on UDP — do not
  change their semantics.
- Injectable seams already exist: NewServerWithConn(cfg, conn, dial),
  NewServerWithDialer, TargetDialer, ClientConfig.ListenUDP (UDPListenFunc).
  The new transport must be injectable through these seams, or tests cannot run
  in non-root environments.
- Existing constants: UDPC_MAX_PKT = 1450, UDPC_HDR_SIZE = 40,
  UDPC_TRAILER_SIZE = 16, UDPC_MAX_DATA = 1394.

# Hard constraints (violation ⇒ rework)

1. Configuration must come only from -c <file>. No environment variables, no
   auto-scanning config.server.json, no default-path fallbacks.
2. All code comments and logs must be English; no mojibake.
3. No new third-party dependencies (stdlib + golang.org/x/crypto + existing
   go.mod).
4. Do not touch the v2 wire format's byte layout. The ICMP payload is the
   complete v2 record byte-for-byte; no ICMP-specific headers added.
5. port_range / origdst / sendsock_max / receive_sockets apply only to the UDP
   profile; the ICMP path must neither read them nor error/panic because of
   them.
6. On non-Linux or without CAP_NET_RAW, fail explicitly with actionable
   guidance — never silently pretend success.
7. Do not perform any git operations (no commit, no stash, no branch).
8. All changes must pass cross-compilation: linux amd64/arm64/arm/386,
   darwin amd64/arm64, windows amd64, android arm64.
9. Output the design and the file manifest only; wait for my approval before
   writing code.

# Design points you must decide yourself (do not ask — implement these conclusions)

1. Session demultiplexing. ICMP has no ports; the only native demux field in
   the Echo header is the 16-bit Identifier. Conclusion: the inner v2 SessionID
   is the sole authoritative session key; the Identifier is a cheap
   pre-filter only; the server state table keys on SessionID. Rationale: the
   Identifier is only 16 bits and gets rewritten by middlebox NATs.

2. Downlink direction. The only pattern almost every NAT/firewall allows on
   ICMP is request-reply. Conclusion: the client creates downlink
   opportunities via Echo Requests (poll + pacing), and the server places
   downlink data in Echo Reply payloads; reuse v2 PING/PONG for keepalive and
   polling. A "server-initiated Echo Request" reverse probe is permitted while
   the mapping is observed to be fresh, but it must be configurable and degrade
   gracefully on failure.

3. Reply mirroring. The server must mirror the received Identifier and Echo
   sequence number verbatim when constructing the Echo Reply — never assume the
   values the client chose (symmetric with the origdst "mirror the observed
   value" principle). The client must accept replies whose id/seq were
   rewritten by an intermediate NAT.

4. MTU and fragmentation. The ICMP payload ceiling is a profile parameter
   icmp.max_payload, default 1200, minimum supported 548 (conservative value
   for IPv4's 576-byte minimum reassembly). UDPC_MAX_PKT must NOT be changed
   globally (it would break the UDP profile); the frame-size ceiling must be
   taken per profile. CGNATs commonly drop IPv4 fragments, so the default path
   must not fragment.

5. Packet rate and throttling. ICMP is subject to net.ipv4.icmp_ratelimit /
   icmp_msgs_per_sec and middlebox rate limiting; loss can burst to 30–50%.
   Conclusion: send pacing is required (configurable icmp.pace_ms) plus more
   conservative retransmit backoff, and ARQ must keep making progress at that
   loss rate.

6. Raw sockets. On Linux use SOCK_RAW + IPPROTO_ICMP (requires CAP_NET_RAW /
   root). Do NOT use ping sockets (SOCK_DGRAM + IPPROTO_ICMP): the kernel
   rewrites the Identifier, and the client loses control over it. IPv4 first;
   ICMPv6 checksums need the pseudo-header (incl. destination address) — this
   phase leaves the interface only, no implementation.

7. Identifier spreading. This is the analogue of UDP's port spreading: a
   configurable id pool (icmp.id_range) replaces port_range to diversify the
   flow key in NAT/conntrack. Its benefit does NOT share a source with UDP's —
   the README must say so clearly; do not advertise it as an equivalent
   per-port rate-limit bypass.

# Deliverables

- tunnel/transport.go: transport abstraction (read / write / close / local &
  remote identity), satisfied by both the UDP and ICMP implementations.
- tunnel/icmp_linux.go + tunnel/icmp_other.go: separated by build tags; non-
  Linux returns an explicit unsupported error.
- tunnel/icmpprofile.go: Identifier selection and pool, pacing, payload budget,
  reply mirroring, poll scheduling.
- Wiring: ServerConfig / ClientConfig gain transport selection and ICMP fields
  (JSON tags, read via -c).
- Tests: tunnel/icmp_test.go with an injected fake transport, green in non-root
  environments; tunnel/icmp_raw_linux_test.go (//go:build linux) against real
  loopback, needs root, t.Skip when the capability is missing.
- Config templates config.server.json / config.client.json with the new fields;
  README gains an "ICMP transport profile" section; PROTOCOL_V2.md gains a
  "Transport profiles" section stating the record format is
  transport-independent.
- gen-icmp-rules helper command: emits iptables/nftables rules allowing echo
  requests, plus ratelimit tuning hints.
- A "UDP-only mechanisms that do not apply on the ICMP path" list: port_range
  spreading, DNAT, origdst, sendsock pool, reuseport receive scaling.

# Acceptance criteria

- go build ./... / go vet ./... / go test ./... all green, including non-root
  on the local machine.
- Cross-compilation matrix (constraint 8) all green.
- Client and server logs must distinguish three situations: ICMP path healthy /
  kernel or middlebox rate-limiting loss / middlebox total block — following
  the existing debug-log style.

# Output format

First deliver: design description (transport interface signatures + state
machine + interaction with ARQ) + changed-file manifest + phased plan.
Wait for my approval before starting implementation.
```

---

## Appendix A: why these 7 points must be nailed down

| Decision | Consequence of leaving it out of the prompt |
| --- | --- |
| SessionID is the real key | The agent would key sessions on the 16-bit Identifier; one NAT rewrite and traffic cross-talks |
| Downlink rides poll + Reply | The agent would let the server send Echo Requests directly to the client, failing silently through NAT |
| Mirror id/seq verbatim | The agent would assume the client-chosen id comes back unchanged; rewriting NATs lose everything |
| Payload ceiling per profile | The agent would edit `UDPC_MAX_PKT` outright, breaking the UDP profile in one stroke |
| Pacing + high-loss tolerance | The agent would blast Echo Requests back-to-back; the kernel `icmp_ratelimit` swallows them, presenting as "random stalls" |
| SOCK_RAW mandatory | The agent would use a ping socket; the kernel rewrites id ⇒ the spreading strategy silently fails and is hard to diagnose |
| Design output only | The agent would rewrite code immediately, conflicting with your "design first, implement after" workflow |

## Appendix B: UDP mechanism → ICMP mapping

| UDP profile today | ICMP counterpart | Equivalent? |
| --- | --- | --- |
| Destination-port spreading (`port_range`) | Echo Identifier pool (`icmp.id_range`, 16-bit) | Similar form, different benefit source |
| Firewall DNAT onto one port | Not needed — ICMP has no ports | N/A |
| `origdst` recovering the destination port | Not needed — the Identifier is right there in the ICMP header | N/A |
| `sendsock` per-port reply mirroring | Echo Reply mirroring id/seq verbatim | Equivalent |
| 5-tuple as path identity | Path = source IP + Identifier; session key = inner SessionID | Not equivalent — must be explicit |
| MTU budget 1450 / payload 1394 | Default 1200, conservative 548 | Smaller |
| `reuseport` multi-socket receive | Single raw socket + SessionID dispatch | Weaker |

Key difference: UDP per-port rate limits account **per (dest IP, dest port)**,
so spreading over N ports multiplies the budget N times; ICMP rate limits
account **per destination IP** (`icmp_ratelimit` / `icmp_msgs_per_sec`) plus a
global allowance, and id spreading only diversifies conntrack / middlebox flow
keys — it **cannot buy the same multiplier**. The main value of the ICMP mode
is "an available alternative path when UDP is blocked wholesale or suppressed
by DPI", not "a larger rate budget". Align expectations in the docs up front.

## Appendix C: Android reality

Non-root Android apps cannot obtain `CAP_NET_RAW` and cannot create raw ICMP
sockets, so the myssh client **cannot implement an ICMP tunnel** on stock
devices. Possible exits (all need empirical verification — do not treat as
settled):

1. If `net.ipv4.ping_group_range` covers the app UID, a
   `SOCK_DGRAM + IPPROTO_ICMP` ping socket works — but the kernel takes over
   the Identifier, so you can only trade "one id per socket" for limited
   spreading;
2. Root / system apps can use raw sockets;
3. VpnService cannot substitute: it only handles traffic entering the tun and
   cannot hand-craft outbound ICMP packets.

Conclusion: position the ICMP profile as a **desktop/server capability**; the
Android side stays on the UDP profile, and say so in the docs.

## Appendix D: Manual acceptance checklist

- [ ] Prompt rule 9 was honored: design + file manifest first, implementation approved after
- [ ] `icmp_test.go` green locally without root (proves the injection seam really exists)
- [ ] Cross-compilation matrix green, especially windows/darwin not failing due to missing build tags
- [ ] No configuration entry other than `-c` was introduced
- [ ] `port_range` / `origdst` / `sendsock_max` are never read on the ICMP path
- [ ] README explicitly states "ICMP mode does not provide an equivalent per-port rate-limit bypass"
- [ ] Real device / real server verification: `ping` works, tunnel works, `tcpdump -i any icmp` shows payloads inside Replies
