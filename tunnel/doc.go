// Package tunnel implements the udp_custom protocol v2: a reliable,
// encrypted, authenticated UDP tunnel with per-session target selection and
// n:n port spreading, usable as an embeddable Go library.
//
// # Public API stability tiers
//
// Tier 1 — Embedding surface (stable across v2.x, semver-protected):
//
//	Server / NewServer / NewServerWithDialer / NewServerWithConn
//	Server.Start / Close / Stats / SetEventHandler
//	Client / NewClient / Start / Close / Stats / DialTunnel
//	NewAutoReconnect
//	ServerConfig, ClientConfig, DialOptions, TargetDialer,
//	SessionEvent, ServerStats, ClientStats, Logger, Nop,
//	StdLogger, NewLevelLogger, sentinel errors (ErrClosed,
//	ErrHandshakeTimeout, ErrNonceCollision, ErrNoRoute)
//	framing helpers (EncodeMessage, MessageAssembler, ...)
//
// Tier 2 — Wire-format primitives (exported for companion wire-spec work and
// exotic embedders; may gain methods but signatures are frozen for v2.x):
//
//	UDPCFrame, SealFrameMAC / SealFrameAEAD / SealFrameMAC,
//	VerifyFrameAuth, OpenFrameAEAD(Into), DecodeUDPCFrame,
//	DerivePSKHandshakeKeys / DerivePSKSessionKeys, FrameKeys,
//	PSKHandshakeKeys, PSKSessionKeys, TargetMaxLen, port-range and
//	spreading helpers (PortRange, PortSelector, SpreadDialer, ...)
//
// Everything else (ARQ session internals, packet reader, replay filter,
// control buffers) is an implementation detail: it can change in any minor
// release. Build against the tier-1 surface and your code survives.
//
// # Wire compatibility
//
// The on-the-wire contract is defined by the repository's wire-spec document.
// Any change to tier-2 types that alters bytes on the wire requires a major
// version bump and a matching update of the Stun Android/TV client.
package tunnel
