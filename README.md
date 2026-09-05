# udp_custom

High-Performance Custom UDP Stream Tunnel Server & Client with Authenticated Control Frames and Optional Noise Encryption.

## Features

- **Reliable UDP Stream Transmission**: ARQ with adaptive RTO (RFC 6298 + Karn's rule), cumulative ACKs, out-of-order buffering, a bounded send window (`send_window`) for backpressure, and 64-bit sequence numbers.
- **Authenticated Protocol v2 Records**: every DATA, ACK, PING, PONG, and FIN carries a 64-bit per-direction `PacketNo` plus a fixed 16-byte authentication tag. A 2048-packet sliding window rejects duplicates and too-old packets before they can mutate session state.
- **Hardened Handshake**: direction-separated PSK MAC keys protect both SYN and ACK; the ACK echoes `ClientNonce` and adds `ServerNonce`. Session keys bind both nonces and `SessionID`. A ±300s timestamp window, per-source-IP SYN rate limiting, target-dial concurrency cap, and PSK-isolated idempotency cache limit replay and resource exhaustion.
- **Dual Target Forwarding**: Proxies to both TCP (`tcp://host:port`) and UDP (`udp://host:port`) services.
- **Mandatory PSK Authentication & Encryption**: open/CRC-only mode no longer exists. Every session record — DATA and control frames alike — is **ChaCha20-Poly1305 encrypted and authenticated**, in PSK-only mode too (keys bound to the PSK, both handshake nonces, and the SessionID). Note: PSK-only mode has **no forward secrecy** — a leaked PSK exposes past PSK-only traffic. Configure Noise when that matters.
- **Optional Noise_NK Forward Secrecy**: standard **Noise_NK_25519_ChaChaPoly_BLAKE2s** handshake (transcript-bound, forward-secret, implicit authentication, channel binding) over Curve25519 → HKDF-BLAKE2s → ChaCha20-Poly1305 in both directions. Transport nonces are derived from `PacketNo`; the complete 40-byte header is AEAD associated data, and the Poly1305 tag occupies the common 16-byte trailer. Retransmission reuses the exact encoded record.
- **n:n Port Spreading**: clients may spread over **K local sockets × N server ports** (full 4-tuple space = K×N). The server supports this with no configuration change — see [n:n Spreading](#nn-spreading-k-local-sockets--n-server-ports).
- **Stun Node Sharing (`gen-uri`)**: One-click sharing URI (`stun://`, PIN-protected) with a real terminal QR code, plus a plaintext `udpc://` link for non-Stun clients.
- **Per-Packet Port Spreading (Rate-Limit Bypass)**: The server binds a single UDP port; clients dial a **port range** (e.g. `1.1.1.1:25000-25499`) and send every packet to a (different) port inside it, defeating per-destination-port UDP rate limiting. A firewall DNAT (`gen-iptables` / `gen-nftables`) redirects the whole range onto the internal listen port. On the return path the server mirrors each packet's original destination port (`origdst`), so replies survive NAT — see [Port Range](#port-range--per-packet-spreading-rate-limit-bypass).
- **Single-Source JSON Configuration**: `-c <file>` is the **only** supported configuration source. Every setting lives in the JSON file; there are no CLI flags or environment variables for server settings, so a running deployment is fully described by one file. (The `gen-*` subcommands take their own flags, since they only print output.)

Protocol v2 is intentionally incompatible with v1. Upgrade both ends together;
there is no downgrade or legacy parser. See [PROTOCOL_V2.md](PROTOCOL_V2.md) for
the exact wire format and migration differences.

---

## One-Key Management (Linux Server & Client)

### 1. Server Installation (Default)
```bash
curl -fsSL https://raw.githubusercontent.com/NNdroid/udp_custom/master/scripts/install.sh | sudo bash -s install server
```

### 2. Client Installation (Linux)
```bash
curl -fsSL https://raw.githubusercontent.com/NNdroid/udp_custom/master/scripts/install.sh | sudo bash -s install client
```

### 3. Pin a Release Version (Optional)
Leave `APP_VERSION` unset to install the latest release. To install a specific
raw-binary release, supply its tag (`v2.0.yyyyMMdd-<7-character-git-hash>`):
```bash
curl -fsSL https://raw.githubusercontent.com/NNdroid/udp_custom/master/scripts/install.sh | sudo env APP_VERSION=v2.0.20260904-1a2b3c4 bash -s install server
```

### 4. Upgrade / Uninstall
```bash
# One-key Upgrade (Keeps existing config.json)
curl -fsSL https://raw.githubusercontent.com/NNdroid/udp_custom/master/scripts/install.sh | sudo bash -s upgrade

# One-key Uninstall
curl -fsSL https://raw.githubusercontent.com/NNdroid/udp_custom/master/scripts/install.sh | sudo bash -s uninstall
```

### 5. Service Management
```bash
systemctl start udp_custom    # Start service
systemctl stop udp_custom     # Stop service
systemctl restart udp_custom  # Restart service
systemctl status udp_custom   # Check status
journalctl -u udp_custom -f   # View live logs
```

---

## Embedding as a Go Library (`tunnel` package)

The whole protocol — ARQ, v2 per-frame authentication, Noise, port spreading —
lives in the importable package `github.com/NNdroid/udp_custom/tunnel`. The
binary is a thin config-file shell around it. External programs get a
secure-by-default tunnel without touching the wire format:

```go
import "github.com/NNdroid/udp_custom/tunnel"

// SERVER: sessions obtain their backend through YOUR dialer, after the
// client's target request passed the allowed_targets filter.
srv, err := tunnel.NewServerWithDialer(tunnel.ServerConfig{
    ListenAddr:     ":36712",
    TargetAddr:     "tcp://127.0.0.1:22", // default target
    Passwords:      []string{"psk"},
    AllowedTargets: []string{"tcp://127.0.0.1:*", "tcp://*.internal:22"},
    Logger:         tunnel.Nop, // or your own tunnel.Logger
}, func(ctx context.Context, sessionID uint32, network, address string) (net.Conn, error) {
    return yourPool.Dial(ctx, network, address) // plain net.Dial by default
})
srv.SetEventHandler(func(ev tunnel.SessionEvent) { /* Established / Closed */ })
go srv.Start()

// CLIENT: each tunnel is one net.Conn — writes reach the target, reads return
// its responses. No local TCP listener needed.
cli, _ := tunnel.NewClient(tunnel.ClientConfig{
    ServerAddr: "1.2.3.4:25000-25499",
    Passwords:  []string{"psk"},
    Logger:     tunnel.Nop,
})
conn, err := cli.DialTunnel(ctx, tunnel.DialOptions{
    Target:    "tcp://127.0.0.1:2222", // optional; "" = server default
    OnGranted: func(granted string) { /* endpoint the server granted */ },
})
defer conn.Close()
conn.Write(...); conn.Read(...) // it is a net.Conn
```

Notes for embedders:

- The client config's `Target` (or `DialOptions.Target`) is REQUESTED in the
  handshake; the server only honors endpoints matching its `allowed_targets`
  and echoes the granted one. Denied requests never complete the handshake.
- `DialTunnel` respects `ctx` (cancellation aborts a pending handshake).
- `srv.Stats()` returns a `ServerStats` snapshot (live sessions, send-path
  mirroring counters, auth-failure/replay counters) — wire it into Prometheus
  or a health endpoint instead of parsing logs.
- Wire compatibility with the Stun Android/TV client is defined by
  [PROTOCOL_V2.md](PROTOCOL_V2.md); keep both sides on v2.

## Known Limitations & Future Directions

| Area | Status |
| :--- | :--- |
| Congestion control | ARQ with adaptive RTO + fixed send window (256 frames). No loss-based throttling: on a heavily lossy path retransmissions can be aggressive. A pacing/BBR-style mode is a possible future option. |
| Forward secrecy | PSK-only sessions are ChaCha20-Poly1305 encrypted but derive keys from the long-lived PSK — a leaked PSK exposes past PSK-only traffic. Noise (`privkey`/`pubkey`) gives forward secrecy. |
| Packet-number exhaustion | 64-bit per-direction counters; the session dies before a nonce can repeat. Theoretical. |
| Multi-threaded receive | ✅ Supported on Linux via `receive_sockets` (SO_REUSEPORT group, one read goroutine per socket, 4-tuple hash keeps per-session ordering). Other platforms are single-reader; `SO_REUSEPORT` on Windows/BSD has different semantics and is not attempted. |
| origdst port mirroring | Linux only (`IP_RECVORIGDSTADDR`). On macOS, pf `rdr` state does the reply translation (see [Windows & macOS](#windows--macos-how-the-range-reaches-the-listen-port)); on Windows use single-port mode or the WSL2 + NetNat recipe. |

---

## Client Mode (same binary)

The same binary also runs the **client**, which fronts local applications with a
plain TCP port and tunnels each connection to a udp_custom server:

```
app ──tcp──► udp_custom client (listen) ──udp_custom over UDP──► server ──tcp──► backend
```

```bash
# /etc/udp_custom/config.client.json   (see config.client.json)
{
  "mode": "client",
  "listen": "127.0.0.1:1080",
  "server": "1.2.3.4:25000-25499",   # port range = spreading
  "passwords": ["secret_psk_token_1"],
  "pubkey": "<server Noise public key>",  # optional: enables Noise_NK
  "sockets": 4,                           # optional: n:n local spreading
  "paths": 32,                            # optional: distinct remote ports picked from the range
  "log_level": "info"
}

udp_custom -c /etc/udp_custom/config.client.json
# or:  install.sh can set it up as a systemd service (install client)
```

Each local TCP connection becomes its own udp_custom session (own SessionID, own
backend connection at the server), with full ARQ: adaptive RTO, retransmission,
reorder buffering, cumulative ACKs, keepalive PINGs, FIN on close, optional
Noise_NK, and optional n:n spreading via `sockets` (local) x `paths` (remote
ports picked from the `server` range). `paths` is the number of distinct remote
ports the client randomly selects for the session; `0` (default) spreads every
packet across the entire range.

The Android/Stun client mirrors this with `udp_custom_paths`
（`udp_custom_paths` in its JSON config, default 32): it randomly picks that many
ports from the server's port range and opens one connected socket per port, then
load-balances over them. The server never tells the client which ports to use —
the client is the single source of truth for path selection.

⚠️ `mode` used to be silently ignored — the binary always booted as a server.
Keep `"mode": "client"` in the config.

## Configuration Reference (`config.json`)

| Field | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `listen` | `string` | `":36712"` | The **single** UDP port the server binds. The firewall DNATs the whole client port range (configured via `port_range`) onto this one port. The server NEVER binds the range itself — it relies on `origdst` to recover each packet's pre-DNAT destination port and reply from it. |
| `port_range` | `string` | `""` | **First-class server port range**, e.g. `"25000-26000"` (host optional). The firewall DNATs this whole range onto `listen`. Used at runtime to validate that every incoming packet's original destination port belongs to the range (a packet outside it signals a firewall/DNAT mismatch), and is the default `--range` for `gen-nftables`/`gen-iptables`. The server never binds these ports. |
| `target` | `string` | `"tcp://127.0.0.1:22"` | Server: the DEFAULT target (`tcp://127.0.0.1:22` or `udp://...`). Client: the endpoint REQUESTED in the handshake; empty/absent = server default. |
| `allowed_targets` | `array` | `[]` | **Server-only.** Client-requested per-session endpoints are honored only when they match one of these glob patterns (`*`/`?` in host and port; the network must match), e.g. `"tcp://127.0.0.1:*"`, `"tcp://*.internal:22"`. An empty list means only the default `target` is reachable; a denied request is silently dropped (the client simply never receives an ACK). The granted endpoint is echoed inside the authenticated handshake ACK. |
| `passwords` | `array|string` | required | One or more non-blank PSKs (or comma-separated string; aliases `token`/`psk`). Protocol v2 has no unauthenticated mode. |
| `magic` | `string` | `"UDPC"` | 4-byte custom protocol magic header. |
| `privkey` | `string` | `""` | Static private key for optional Noise_NK encryption. PSK-only sessions are already ChaCha20-Poly1305 encrypted but lack forward secrecy; adding `privkey` (client `pubkey`) upgrades sessions to forward-secret Noise keys. |
| `log_level` | `string` | `"info"` | Logging output level: `debug`, `info`, `warn`, `error`. |
| `origdst` | `bool` | `true` | **Required (Linux).** Enables `IP_RECVORIGDSTADDR` so the server recovers each client packet's original destination port (pre-DNAT) and replies FROM that exact port. Without it every reply leaves from `listen` and any NAT stricter than full-cone drops it. Ignored on non-Linux platforms. |
| `receive_sockets` | `int` | `1` | **Linux only.** Opens N UDP sockets sharing `listen` via `SO_REUSEPORT`, one read goroutine each — scales packet intake across cores. The kernel hashes the 4-tuple, so one client source socket always lands on the same receiver (per-session ordering preserved) while different clients spread across the group. 0/1 = single socket; non-Linux platforms clamp to 1 with a warning; hard cap 8. |
| `sendsock_max` | `int` | `512` | Per-port reply-socket pool cap (LRU). One socket is bound per distinct origdst port so the kernel stamps the reply's source port correctly. Set it >= the size of `port_range`. |
| `send_window` | `int` | `256` | Max DATA frames in flight awaiting an ACK. When the window is full the target read loop blocks (backpressure), bounding memory and the retransmit backlog for a slow or silent client. |

---

## Multi-Path via Firewall DNAT + Client-Chosen Random Ports (recommended)

The server binds **one** UDP port (`listen`). A firewall rule (nftables/iptables
DNAT) redirects the entire client port range (`port_range`, e.g. `25000-26000`) onto that single port.
The client randomly selects **N=32** ports from the range (configured client-side
via `sockets` × `paths`) and sends each packet to one of them; the firewall DNAT
collapses them all onto the server's listen port. The server recovers each packet's
pre-DNAT destination port via `IP_RECVORIGDSTADDR` and replies FROM a socket bound to
that exact port, so the reply's source port equals the port the client addressed —
which is what makes a CGNAT / symmetric NAT accept it.

- **Why it traverses CGNAT:** the reply source port always matches the port the
  client contacted. No fixed port, no full-cone assumption, no NAT-rebinding hacks.
- **Client is the single source of truth for path selection:** the server NEVER
  advertises a port list. The authenticated v2 handshake ACK carries the echoed
  `ClientNonce`, a fresh `ServerNonce`, and optional Noise msg2; it carries no port
  list. The client picks its own N ports from `port_range`.
- **Load balancing:** the client spreads writes across the N chosen ports (and, with
  `sockets` > 1, across N local sockets too) and the server fans replies back per
  path; keepalive traffic follows the active spread selection.
- **N=32** is a good default (see `config.server.json`).

> The earlier direct-bind multi-path design (server binding N ports and advertising
> them in the ACK) was abandoned: it could not recover from a behind-CGNAT
> deployment where the firewall already DNATs a range, and it tied the two sides to a
> hand-synced port list. The DNAT + `origdst` design above is now the only supported
> multi-path mode.

## Quick Start

### 1. Export Stun QR Code & Sharing Link
```bash
udp_custom gen-uri -c /etc/udp_custom/config.json
```

---

## Port Range / Per-Packet Spreading (Rate-Limit Bypass)

Some networks rate-limit UDP by the `(dst-IP, dst-port)` tuple. udp_custom defeats
this by having the **client** send every datagram to a *different* port inside an
advertised range, while the **server** keeps listening on a single internal port.
A firewall rule on the server host merges the range back onto that port.

Sessions are identified by `SessionID`, not by address, so the inbound direction
needs no special handling. The **return** direction does — see below.

### Why the return path needs help

Once the whole range is DNAT'd onto one internal port, every conntrack entry gets
the *same* reply tuple:

```text
original  clientIP:clientPort -> serverIP:25007     (differs per packet)
reply     serverIP:36712      -> clientIP:clientPort  (identical for every entry)
```

There is nothing for conntrack to disambiguate, so it cannot "reverse the DNAT
per packet". If the server replies from its single listening socket, **every**
reply leaves from `:36712` regardless of which port the packet arrived on. A
client behind anything stricter than full-cone NAT drops those replies, because
the mapping it opened for `:25007` only accepts traffic from `:25007`. That is
exactly the "handshake succeeds but the port range carries no traffic" symptom:
the handshake uses one fixed port, so it accidentally matches.

The fix is for the server to answer from the port the client addressed:

1. On the listening socket it enables `IP_RECVORIGDSTADDR` (`origdst`, Linux
   only). `recvmsg` then reports the original destination alongside each
   datagram, so the server knows "this one came to `:25007`".
2. Replies go out through a lazily-created socket bound to that exact port
   (`sendsock_max` caps the LRU cache). The source port then mirrors the
   destination port and the client's NAT accepts the packet.
3. If that socket cannot be used — non-Linux host, bind failure, cache pressure —
   the server falls back to the main socket. The source port then mismatches and
   the client may drop the packet, but a mismatched reply still beats silently
   discarding it, and non-spreading clients are unaffected.

Because replies carry their own source port, conntrack's reply tuple is simply
never matched, so nothing rewrites the source port behind the server's back.

That settles the **return** path for a `127.0.0.1` DNAT target (the `--to`
default) — there is no reverse translation to depend on. The **inbound** path is
a separate matter: Linux treats `127.0.0.0/8` as a martian address on any
non-loopback interface, so a datagram that arrives on a physical NIC and is
DNAT'd to `127.0.0.1` is **dropped by the kernel** unless you opt in:

```bash
sudo sysctl -w net.ipv4.conf.all.route_localnet=1
echo 'net.ipv4.conf.all.route_localnet=1' | sudo tee /etc/sysctl.d/99-udpc.conf
```

Symptom when it is missing: the handshake completes (it uses the primary port,
which is usually outside the DNAT'd range and so reaches the socket directly)
and then every spread packet disappears, i.e. a retransmission count several
times the send count. To avoid the sysctl entirely, DNAT to the NIC address
instead (`--to 10.0.12.7:36712`) and keep the server on `"listen": ":36712"`.

### Server side

1. Configure the internal listen port, the client port range, and the public host:

```json
{
  "listen": ":36712",
  "port_range": "25000-25499",
  "host": "203.0.113.10",
  "target": "tcp://127.0.0.1:22",
  "origdst": true,
  "sendsock_max": 512,
  "log_level": "debug"
}
```

Keep `log_level: "debug"` while validating the range. At startup you want to see:

```text
🎯 IP_RECVORIGDSTADDR enabled: replies reuse each packet's original destination port
```

If instead you see `⚠️ Could not enable IP_RECVORIGDSTADDR`, the kernel refused the
option — usually a container without `CAP_NET_RAW`, or a non-Linux host. The
range will not work in that mode.

### How big should the range be?

Two hard constraints, and both are easy to get wrong:

**1. The range must be a subset of what the firewall DNATs.** The server cannot
check this — it never sees the firewall rules. A client configured with
`25000-26000` while the rule only covers `25000-25499` sends half its packets
into a void: the server host has no listener on those ports and silently drops
them. The symptom is a successful handshake followed by endless retransmissions.

**2. Keep the port COUNT at or below `sendsock_max` (default 512).** The reply
socket pool is an LRU of that size, so with `N` range ports its steady-state
hit rate is roughly `min(1, 512 / N)`. Exceed the cap and every miss costs a
`socket()` + `bind()` + `close()`:

| Range | Ports | Hit rate |
| :--- | ---: | ---: |
| `25000-25063` | 64 | ~100% |
| `25000-25499` | 500 | ~100% |
| `25000-26000` | 1001 | ~51% |
| `25000-29999` | 5000 | ~10% |

A few hundred ports is already a few-hundred-fold multiplication of whatever the
per-port limit is, so going wider buys nothing once you are at the cap. **500
ports is a good default.** If you genuinely want more, raise `sendsock_max` to
match and remember that each entry costs a file descriptor and a conntrack entry.

To shrink an existing deployment, update `port_range` (and `host`), regenerate the
client address, and only then narrow the firewall rule:

```bash
# 1. narrow the port_range first
#    "port_range": "25000-25499"

# 2. re-issue the client config
udp_custom gen-uri -c /etc/udp_custom/config.json

# 3. only once every client has the new range, narrow the firewall rule
udp_custom gen-nftables --to 127.0.0.1:36712 --range 25000-25499 | sudo bash
```

Reversing steps 1 and 3 would black-hole every client that still holds the old
range.

<a id="deployment-invariants"></a>
### Deployment invariants (checked at startup)

`port_range` is the single source of truth for the client port range and the
firewall DNAT, so it is now validated at boot and warns (never fatal) on the
following violations:

| Invariant | Consequence if violated | Detected |
| :--- | :--- | :--- |
| Port count ≤ `sendsock_max` | Reply-socket LRU evicts on nearly every packet | ✅ startup warning |
| `origdst: true` when the range has >1 port | Every reply leaves from `listen`; strict NATs drop them | ✅ startup warning |
| Range must **not** contain the `listen` port | Packets sent there bypass the DNAT and hit the socket directly, so a fully broken firewall still looks "slow but working" and hides the real fault | ✅ startup warning |
| Range ⊆ firewall DNAT range | Out-of-range packets are black-holed | ❌ server cannot see firewall rules |
| `route_localnet=1` when DNATing to `127.0.0.1` | Kernel drops inbound spread packets as martian | ❌ check with `sysctl net.ipv4.conf.all.route_localnet` |

A healthy boot logs the configured range and nothing else:

```text
📣 [port_range] server expects client packets on port range 25000-25499 (500 ports); ensure the firewall DNATs this range onto 'listen'
🎯 IP_RECVORIGDSTADDR enabled: replies reuse each packet's original destination port
```

2. Generate the firewall rule that DNATs the range onto `:36712`. Pick **one**:

```bash
# nftables (recommended; handles arbitrary disjoint ranges)
udp_custom gen-nftables --to 127.0.0.1:36712 --range 25000-25499 | sudo bash

# iptables (REDIRECT, local only; multiport limited to 15 ranges)
udp_custom gen-iptables --port 36712 --range 25000-25499 | sudo bash
```

3. Emit the client dial address from config:

```bash
udp_custom gen-uri -c /etc/udp_custom/config.json
# => ProxyAddr / udpc://... will use 203.0.113.10:25000-25499
```

### Client side (integration contract)

The client parses the server address (host + port range) and calls `PortSelector.Next()` **once per
outgoing packet** — never once at connect time. Reference (also usable as a
standalone copy in the client repo):

```go
host, ports, err := ParseServerAddrWithRange("203.0.113.10:25000-25499")
if err != nil { /* ... */ }
pr, _ := NewPortRange(ports)
sel := NewPortSelector(pr, SelectorRandom) // or SelectorRoundRobin

// per packet:
dstPort := sel.Next()
dst := &net.UDPAddr{IP: net.ParseIP(host), Port: dstPort}
conn.WriteToUDP(encodedFrame, dst)
```

### Windows & macOS: how the range reaches the listen port

The DNAT/REDIRECT recipes above are Linux tooling (`iptables`/`nftables`), and
the return-path mirroring (`origdst`) is a Linux socket option. Windows and
macOS have no `IP_RECVORIGDSTADDR`, so the range must be merged onto `listen`
differently — and *something* must also translate the replies, or strict NATs
drop them.

**macOS — native, full feature set.** macOS ships pf, and one `rdr` rule with
state does BOTH halves of the job (redirect the range onto `listen` AND
translate replies back to the port the client addressed):

```bash
# /etc/pf.anchors/udpc — en0 = your external interface (`route -n get default`),
# 36712 = the `listen` port.
rdr pass on en0 proto udp from any to any port 25000:25499 -> 127.0.0.1 port 36712
```

```bash
sudo pfctl -f /etc/pf.anchors/udpc
sudo pfctl -e   # enable pf (first time only)
```

- `rdr pass` creates state, so a reply from `:36712` is translated back to
  `serverIP:<original destination port>` before it leaves — exactly what
  `origdst` does on Linux. `origdst` can stay `true` in the server config (it
  is ignored on non-Linux platforms); the client sees nothing unusual.
- Persist across reboots by adding `anchor` loading to `/etc/pf.conf`, or
  re-run the two commands.

**Windows — no native UDP range redirect.** Three dead ends, to save you the
search: `netsh interface portproxy` is TCP-only; `New-NetNat` NATs an entire
internal subnet (WSL/Hyper-V), not a host port range; Windows Firewall can
allow but not translate. Two workable routes:

1. **Single-port mode (simplest).** No DNAT, no spreading: point clients at
   the listen port directly — `"server": "203.0.113.10:36712"`. Everything
   works except the rate-limit bypass.
2. **Full spreading via a Linux guest (WSL2 / Hyper-V).** The guest runs Linux
   udp_custom on a single port; the Windows host maps the range one port at a
   time with NetNat. Each static mapping is bidirectional, so NetNat does the
   reply translation that `origdst` would have done — port spreading works
   end to end:

   ```powershell
   # Admin PowerShell. Guest (172.20.0.2) runs Linux udp_custom:
   #   listen ":36712", origdst false, port_range unset (no iptables inside).
   New-NetNat -Name udpc -InternalIPInterfaceAddressPrefix 172.20.0.0/24
   New-NetFirewallRule -DisplayName udpc-range -Direction Inbound -Protocol UDP `
     -LocalPort 25000-25499 -Action Allow
   foreach ($p in 25000..25499) {
     Add-NetNatStaticMapping -NatName udpc -Protocol UDP -ExternalIPAddress 0.0.0.0 `
       -ExternalPort $p -InternalIPAddress 172.20.0.2 -InternalPort 36712
   }
   ```

   Keep the range moderate — every mapped port is one NAT-table entry on the
   host. `Add-NetNatStaticMapping` requires Windows 10 1607+ / Server 2016+
   with admin rights.

In both recipes the client stays unchanged: it still dials
`host:25000-25499` and spreads per packet.

## Stream vs Message Boundaries (framing)

For **TCP** targets the tunnel is a **byte stream**, not a datagram service:

- client → target: each DATA frame becomes one TCP write, so the client's write
  boundary survives;
- target → client: the server reads the target socket in `UDPC_MAX_PKT`-sized
  chunks and ships each chunk as its own DATA frame, so a reply may arrive
  **split or coalesced** regardless of how the target wrote it.

TCP itself never preserves write boundaries either, so there is nothing the
server can do here — message semantics are an application concern. (With
`target = udp://` the tunnel **does** preserve datagram boundaries end to end:
one datagram in, one DATA frame out. Framing is only needed for stream targets.)

Reference client (`framing.go`, copyable into the client repo) — 4-byte
big-endian length prefix:

```go
// send: frame, then chunk so each piece fits one DATA frame
stream, _ := EncodeMessages(msg1, msg2)      // or EncodeMessage(m)
for off := 0; off < len(stream); off += UDPC_MAX_DATA {
    end := off + UDPC_MAX_DATA
    if end > len(stream) {
        end = len(stream)
    }
    client.sendData(stream[off:end])
}

// receive: the tunnel decides the chunking — just feed everything in
asm := NewMessageAssembler(MaxFramedMessage) // reject messages > 1 MiB
for {
    _, payload := client.readData()
    msgs, err := asm.Feed(payload)
    if err != nil { /* stream desynced: reset the session */ }
    for _, m := range msgs {
        handle(m)
    }
}
```

Notes:

- **Always cap `maxPayload`.** Without a limit a hostile or buggy peer makes the
  assembler buffer unboundedly. An oversized length prefix marks the assembler
  broken (resynchronising a desynced stream by guessing is worse than failing
  fast); call `Reset()` after restarting the stream.
- One assembler per stream, driven from a single receive loop — it is not
  concurrency-safe by design.
- Empty messages are legal; `EncodeMessages` batches several into one frame.

## n:n Spreading (K local sockets × N server ports)

1:n (one local socket × N remote ports) already spreads `(dstIP,dstPort)`. Many
carriers rate-limit on the **full 4-tuple** `(srcIP:srcPort, dstIP:dstPort)`
though, and a single local socket is capped by one kernel send buffer and one
lock. Opening **K local sockets** multiplies the tuple space to **K × N** and
parallelises the write path.

The server supports this **without any configuration change**:

- sessions are keyed by `SessionID`, not by address, so any number of source
  ports works;
- a **port-only change on the same IP** is treated as NAT rebinding only after
  the frame passes v2 authentication and replay checks — with K sockets the
  client's source port changes constantly, and the server simply follows it;
- replies always leave from the port the packet was addressed to (`origdst` +
  `sendSockPool`), so every `(srcPort_i, serverPort_j)` 4-tuple is symmetric and
  the client's NAT lets it back in.

Reference client (`spread.go`, copyable into the client repo):

```go
d, err := NewSpreadDialer("203.0.113.10:25000-25499", 4, 0) // 4 sockets × whole range (0 = no fixed subset)
if err != nil { /* ... */ }
defer d.Close()

// per packet — socket rotates round-robin, port comes from that socket's own
// selector, so the pair (socket, port) is what produces the n:n spread:
d.Send(encodedFrame)                 // or SendAt(idx, frame) to pin a socket

// Replies come back to the socket whose source port the server last saw, so
// run a read loop on EVERY socket and merge into one receive path:
for _, c := range d.Conns() {
    go recvLoop(c)
}
```

Notes:

- **K × N amplifies reordering** — exactly why the AEAD nonce is derived from
  the frame `PacketNo` instead of a receive-order counter. The 512-entry reorder
  buffer and 2048-packet replay window still cover a few-hundred-port setup.
- **conntrack**: each 4-tuple consumes an entry; keep `nf_conntrack_max` roomy.
- **`sendsock_max` only needs to cover N** (the server-side port count); it is
  independent of K.

### Verifying that mirroring actually works

With `log_level: "debug"`, each reply states which socket carried it:

```text
[Send] to=198.51.100.7:41234 via=port:25007 cmd=0x04 len=1042   ✅ mirrored
[Send] to=198.51.100.7:41234 via=main      cmd=0x04 len=1042   ⚠️ fell back
```

`via=port:N` is what you want. `via=main` means the packet left with the wrong
source port — the lines just above it say why (`no port-socket for port=N` or
`port-socket write failed`). Every 15 seconds a snapshot is printed too:

```text
[Stats] origdst=true sendsocks=311 viaPort=48210 viaMain=0 noPort=3 portChanges=29004
```

`sendsocks` climbing toward `sendsock_max` and `viaMain` staying at `0` is a
healthy spreading session. `viaMain` growing steadily means mirroring is not
working.

On the wire, confirm the source port tracks the destination port:

```bash
tcpdump -n -i ens5 "udp and src host <server-ip> and dst host <client-ip>"
```

And on the client (Stun / myssh), a reply from outside the configured range is
reported as a warning:

```text
⚠️ reply srcPort=36712 (from 203.0.113.10:36712) is OUTSIDE the configured range 25000-25499
```

That line is definitive: the server is not mirroring.
