# GameBond.Core

Shared code for the GameBond client and server. It holds the bonded transport (GB03), the TCP stream
transport and gateway, and hardware monitoring. It is a library: it has no `main` and installs no
firewall or NAT rules of its own.

Used by [GameBond.Client](https://github.com/Dankular/GameBond.Client) and
[GameBond.Server](https://github.com/Dankular/GameBond.Server). A change to the wire protocol goes here
first, is tagged, and both repos then bump their `require` (the client has two modules, `native-edge`
and `netstack`, and both must be bumped).

| Package | Contents |
| --- | --- |
| `bond` | GB03 bonded multipath transport: codec, handshake, sender, receiver, FEC, BFD, QoS, session |
| `stream` | Reliable ordered byte stream over the bond, and the server-side `Gateway` that dials destinations |
| `buildinfo` | The build id (git commit) both sides report to each other |
| `hwmon` | Hardware sampling for the client UI and the server admin portal (Windows and Linux) |

## Where each function lives

Router, gateway and firewall functions are split across the repos. Only the "In Core" column is in this repo.

| | In Core | In GameBond.Server (`tools/container-entrypoint.sh`, `cmd/edge`) |
| --- | --- | --- |
| Router | Per-packet path scheduling, failover, flow pinning, striping, duplication | TUN device `gamebond0`, IPv4 forwarding, default route out of the container |
| Gateway | Stream `Gateway` (TCP proxy through the tunnel) and its destination filter | Starts the gateway; `GAMEBOND_STREAM`, `GAMEBOND_STREAM_ALLOW_PRIVATE` |
| Firewall | Authenticated encryption, replay window, source and destination checks, destination filter | nftables forward filter, masquerade NAT, UDP defragment rule, CAKE or fq_codel egress queue |

## Router: the bonded transport (`bond`)

Several physical links (slot 0 Ethernet, slot 1 a phone hotspot, and so on) are presented as one tunnel.
Each link is a UDP path to the server; the receiver reassembles one IPv4 packet stream.

**Path selection and redundancy**
- With two or more ready paths every packet is sent on one path and copied onto another from the first
  packet on. The receiver keeps whichever copy arrives first. Redundancy is not configurable and there are
  no presets (`protection.go`).
- A path leaves the primary set when it is not ready, has been silent for 3 s, or BFD reports it down.
  Redundancy copies still go to a BFD-down path, so a false failure cannot leave a single copy.
- Link roles per path: Primary, Secondary, Backup, Never; per-path upload and download rate limits
  (`PathPolicy`, `WirePacer`) negotiated with `LinkPolicy` and `LinkPolicyAck` frames.
- Loss steering: bulk traffic moves off a path whose smoothed loss reaches 4% while another path is
  cleaner, and may return below 2%.
- Heavy-flow striping (`SetStripeAbove`): a bulk flow above a sustained rate is striped across paths
  instead of duplicated, only while every path is calm, and it reverts at once on any spike.
- Flow pinning with fast reroute (`SetFlowPinning`, off by default): each bulk flow sticks to one path,
  with a precomputed backup it flips to on the next packet.
- Path hints (`SetPathHint`) let the client mark a local link degraded for a period.

**Failure detection**
- BFD: a frame per path every 50 ms. A path is up only while this end hears the peer and the peer reports
  hearing us, so one-way failures are caught at both ends. Any authenticated frame counts as hearing the
  peer, so lost BFD frames do not down a line that still delivers. A calm line is declared down after 150 ms;
  the limit widens to 1.5 times the longest gap the line itself produced recently (at most 500 ms) and falls
  back with a 5 s half-life. The hold-down after a failure grows from 250 ms to 4 s while a link flaps (30 s window).
- Probes and pongs give RTT and jitter per path. Passive ack-stall detection flags a busy path that hears
  nothing back, with no probe needed.
- Failover replay (`EnableFailover`): packets a path carried just before it went quiet are replayed on the
  best live path with their original sequence, so first arrival wins.
- Supervision frames (IEC 62439-3 style): each side reports its view of its own paths on a fixed cadence,
  announces a state change within 100 ms, and retries every 250 ms while the peer's announcement is overdue.
  A silent peer is aged out at 2.5 times the interval. This exposes asymmetric failures.
- Outage journal: timestamped record of every line transition and every full outage, with cause. It is
  bounded in memory and has a durable log.
- Health alarms for silent failures such as rejected feedback.
- Optional path MTU discovery per path (`MTUProbeKind`, `MTUAck`).

**Loss recovery**
- First-arrival elimination with a replay window of 131,072 sequence numbers shared by all paths and copies.
- Selective acknowledgement: receiver feedback carries a bitmap of recently received frames, and the receiver
  sends it at once when a frame reveals a gap (at most one per 10 ms per path) instead of waiting for its timer. The sender
  declares a frame lost when later frames arrived without it and resends at once on the other path, unless a
  sibling copy is still unaccounted for.
- Tail probing: frames unacknowledged for about one round trip are resent, which protects the end of a burst.
- Repair cache: recent TCP packets can be re-requested by the receiver (`Repair`, `RepairNA`). Repairs use
  fresh nonces and keep flow and sequence, so first arrival still wins. UDP is resent from SACK and tail
  probing only; the receiver does not request UDP repairs.
- Parity: XOR parity and Reed-Solomon over GF(256) per group of packets, with later rows delayed for time
  diversity. It is a fallback used while loss is being seen.
- Per-flow reorder buffer with a bounded wait (30 ms by default for UDP). Packets given up on are still
  asked for, and delivered late if they turn up.
- Copy ledger: records which expected path delivered each replicated packet, to measure per-link copy loss.

**Queueing and QoS**
- Urgent and bulk queues are separate and bounded in packets and bytes.
- Bulk traffic uses a deficit-round-robin fair queue per flow. Overload evicts from the largest flow.
- Per-flow CoDel with ECN marking (`EnableCoDel`, off by default), tuned for 50-150 ms satellite RTT.
- Per-path congestion budget with delay-based growth, a loss ceiling and a decaying base-RTT baseline.
- Classifier and adaptive QoS: DSCP classes `bulk` 0, `stream` 18, `call` 26 and `game` 46, each with a
  deadline (defaults 120 ms, 60 ms and 20 ms for stream, call and game), queue capacity and replication.
  A UDP game-port list marks game traffic. Priority hosts (a console behind a client LAN adapter) have UDP
  up to the tunnel MTU treated as game traffic. Per-flow policy is learned and expires after 120 s, and
  fragments are classified with their first fragment.
- Application-chosen flow profiles (`FlowProfiles`, `MarkDSCP`) override the DSCP-derived class.

## Firewall: what Core enforces

- **Authentication and encryption:** every frame is ChaCha20-Poly1305 with a key derived by HKDF-SHA256
  from the shared 32-byte key and the session id, one key per direction. Frames that fail authentication are
  dropped before any state changes. A client drops datagrams from any socket and endpoint it did not configure.
- **Handshake:** Hello, Challenge, Ready, Reset. Handshake input is accepted only from already authenticated
  packets, a challenge lives 2 s, and an old challenge cannot replace the live peer.
- **Replay protection:** the sliding window above. Duplicates, packets behind the window and absurd forward
  jumps are refused without changing state. Nonce exhaustion is an error, not a wrap.
- **Address checks (`Session`):** an inbound packet must have the client's tunnel address or a registered LAN
  device address as its source, and an outbound packet must be destined to one. IPv6, malformed packets and
  packets over the tunnel MTU are dropped. Each rejection has a counter (`WrongSource`, `WrongDestination`,
  `IPv6Unsupported`, `Malformed`, `MTUDrops`).
- **Stream gateway destination filter:** `AllowedDestination` and `SafeDial` allow only globally routable
  unicast IPv4. Loopback, RFC 1918, link-local, CGNAT, multicast, documentation and reserved ranges are
  refused, checked on the address actually connected to after name resolution.
  `GAMEBOND_STREAM_ALLOW_PRIVATE=1` turns the filter off. `Gateway.Allowed` is a hook for a custom allowlist.
- **Resource bounds:** 192 concurrent streams per endpoint, 10 s to send the target address, idle streams
  reaped after 2 minutes, and bounded queues, caches and reorder buffers.

## Gateway: the stream transport (`stream`)

A TCP-like reliable byte stream that runs over the bond so one connection can use every link.

- **Open and relay:** `Endpoint.Dial` opens a stream to a target address. The server `Gateway` accepts it,
  applies the destination filter, dials the target (8 s timeout), replies with a status byte and relays both
  directions, including half-close.
- **Loss and ordering:** every packet has its own number even when retransmitted, so an ack is never
  ambiguous. Loss is declared by a time threshold at least as large as the reorder window, not by duplicate
  acks, so a packet that took the slower link is not retransmitted.
- **Congestion control:** window and slow-start threshold with delay-based shrinking, pacing from the
  transport's per-path budgets, and 4 MiB send and receive buffers.
- **Observability:** the gateway logs a JSON line per active stream every 10 s
  (`GAMEBOND_STREAM_LOG_INTERVAL`) with window, packets in flight, smoothed RTT, retransmits, spurious
  retransmits, timeouts and receive-drop reasons, and a summary when a stream ends.

## Measurement and monitoring

- The sender, receiver and each path expose counters for copies, bulk duplicates, SACK losses and resends,
  tail losses, expired packets, RTT, jitter, probe loss, copy loss and feedback timeouts.
- `loss_causes` separates packets that never arrived (even after repair, parity and copies) from packets
  skipped after waiting that arrived late.
- `hwmon` samples hardware on one worker, so HTTP readers never enumerate processes, disks or GPU counters.
- Each side reports its build id to the other (`VersionReq`, `VersionInfo`), and the server can announce a
  state such as `updating` so clients can tell a planned restart from an outage.

## Standards

The design borrows from IEC 62439-3 (PRP/HSR) and IEEE 802.1CB: duplicate elimination with a history window,
supervision frames and per-path health. It is not certified, and it does not implement PRP or HSR frame
formats or the RCT trailer.

## Testing

`go test ./...` runs the suites. `stream` includes a two-link model (`twolink_test.go`) with latency, jitter
and loss. `bond` includes behaviour vectors generated from the original Python implementation.

## Changelog

Newest first. Versions are git tags; each entry was written from the diff between the tag and the one before it.
Add an entry under **Unreleased** with every change that alters behaviour, and move it under a version when the
tag is cut. Dates are the commit dates in git (UTC).

### Unreleased
- **BFD detects a dead line in 150 ms, down from 500 ms.** Interval 100 ms to 50 ms and multiplier 5 to 3. The
  limit widens to 1.5 times the longest inter-frame gap the line produced recently (cap 500 ms, 5 s half-life)
  so a jittery hotspot is not declared down by its own jitter, and it is evaluated on every `Tick` rather than
  only when a frame is sent. `detect_ms` in the BFD status now reports the live limit. (`7fa3202`)

### v0.1.17 - 2026-11-12
- **BFD: any authenticated frame counts as hearing the peer.** A loaded or lossy line can lose five BFD frames in
  a row, or hold them behind bulk traffic, while data, probes and feedback keep arriving; that line was being
  declared down and the live path thrown away. A line that really stopped delivers nothing, so it is still
  detected in the same time. (`0295a1c`)

### v0.1.16 - 2026-11-12
- **Gap feedback at once.** The receiver sends its SACK feedback inside the `Receive` that reveals a sequence gap
  (at most one per 10 ms per path, counted as `GapFeedback`), so the sender learns of a loss one way trip after it
  happens instead of after the 20-100 ms feedback timer. (`89623dc`)
- **Supervision timing through bursts.** Frames are anchored to a fixed cadence instead of drifting, a state
  change is announced within 100 ms, and while the peer's announcement is overdue (more than 2.5 intervals) the
  frame is retried every 250 ms. Entries are sorted by path and the change signature ignores RTT, skew and
  first-wins counters, which removes announcements caused by map iteration order. (`89623dc`)
- README lists the router, gateway and firewall features and where each lives. (`ef70921`)

### v0.1.15 - 2026-11-12
- **Fix: receiver feedback carries the SACK bitmap.** The sender could decode and act on the bitmap, but the
  receiving side never filled it in, so selective-ack loss detection was inactive in production. (`19bdec1`)

### v0.1.14 - 2026-11-12
- **Redundancy copies ignore BFD down and hold-down.** BFD only keeps first copies off a flapping line. A copy
  sent into a really dead line costs bandwidth and nothing else, whereas withholding it when BFD is wrong left a
  single copy, so any loss on that line was permanent. A path silent for 3 s is still left out. (`cea087a`)
- stream: gateway logs in-flight packets, timeouts and receive-drop reasons. (`2e7fb4c`)

### v0.1.13 - 2026-11-12
- **stream: ack processing no longer walks the whole history.** The first received range reaches back to the
  start of the connection, so each ack cost O(history); in-flight polling was O(in-flight). Both now only touch the
  head of the send order. (`18afeb1`)

### v0.1.12 - 2026-11-12
- stream: receive drops are counted by reason (`drop_window`, `drop_ooo`). (`b1ed656`)

### v0.1.11 - 2026-11-12
- **stream: gentler delay shrink.** Only a sustained inflation of twice the recent floor counts as a standing
  queue; the floor is taken over the last 10-20 s so a route change is not read as a queue forever; send and
  receive windows are 4 MiB. (`fe44e5d`)

### v0.1.10 - 2026-11-12
- **Striping only while every path is calm.** It ends at once, for every flow, the moment any path shows a spike,
  and a hold stops a flapping link from toggling the mode. (`74ca76d`)

### v0.1.9 - 2026-11-12
- Striped flows are protected by adaptive parity. (`1efc7ee`)

### v0.1.8 - 2026-11-12
- **Heavy-flow striping (`SetStripeAbove`, `stripe_above_mbps`).** A bulk flow that sustains more than the
  threshold is sent once, split across the paths, instead of duplicated, so a download is not capped at the slower
  link. Lost packets are still requested from the repair cache and the flow goes back to duplication when it
  slows down. 0 keeps every flow duplicated. (`508a752`)

### v0.1.7 - 2026-11-12
- **Bonded TCP first-arrival.** A TCP packet is delivered on its first copy instead of being held behind a hole,
  which is almost always the slower path's copy still in flight. Skipped numbers are repaired from the peer's
  cache if neither copy turns up, and the reorder wait is capped at the path spread plus jitter. (`0189930`)

### v0.1.6 - 2026-11-12
- **IEC 62439-3 / IEEE 802.1CB alignment.** Elimination window widened to 1<<17 sequence numbers (over 700 ms at
  1 Gbps with duplication, past the 400 ms PRP forget time), implemented as a ring so advancing is amortised O(1).
  UDP is delivered on first arrival. Each path records wins and the skew of the second copy, and a path that keeps
  delivering the second copy of nearly everything is flagged as a latent error. (`8684343`)
- **Supervision frame.** Each side reports its view of its own paths to the other, and a silent peer is aged out.
  (`8684343`)

### v0.1.5 - 2026-11-12
- **`stream` moves here from GameBond.Server** (1,889 lines: `Endpoint`, `Conn`, `Gateway`), so the edge server and
  the client netstack share one implementation. (`b6f617e`)

### v0.1.4 - 2026-11-12
- **Burst reduction.** The pacer may release at most 1 ms of backlog at once on a live path (2 ms on the
  reference clock); the sealed frame is allocated once and the sender reuses its scratch buffers; a reorder hold
  is capped at 100 ms because the second copy lands within the path skew. Adds a pacing burst profile and a
  transmit pump benchmark. (`2ec269f`, `566dcec`)

### v0.1.3 - 2026-11-12
- Assertive delay floor 10 ms to 40 ms, since a loaded LEO link sits at 20-40 ms on its own. A path that mostly
  carries redundancy copies can now grow when its wire is full and nearly all of it is delivered. (`2605164`)

### v0.1.2 - 2026-11-12
- The delay back-off cuts a fixed 10% instead of following the delivery rate, which was a ratchet that pinned the
  rate near the last achieved value. Bulk class limit raised to 2048 packets and the transmit queue to 4096
  packets / 8 MiB, so a TCP burst is no longer rejected. (`0f1d0e3`)

### v0.1.1 - 2026-11-12
- The rate controller keeps growing through random loss up to 5% (was 1%), and CoDel is sized for LEO paths
  (target 50 ms, interval 300 ms; was 12 ms and 120 ms), which treated every burst behind the rate limit as a
  standing queue and collapsed TCP. (`9b94a98`)

### v0.1.0 - 2026-11-12
- Initial import of `bond`, `buildinfo` and `hwmon` from GameBond.Client (94 files, 14,668 lines). (`0e9ea9f`)
