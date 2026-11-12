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
- BFD: a frame per path every 100 ms. A path is up only while this end hears the peer and the peer reports
  hearing us, so one-way failures are caught at both ends. The hold-down after a failure grows from 250 ms
  to 4 s while a link flaps (30 s window).
- Probes and pongs give RTT and jitter per path. Passive ack-stall detection flags a busy path that hears
  nothing back, with no probe needed.
- Failover replay (`EnableFailover`): packets a path carried just before it went quiet are replayed on the
  best live path with their original sequence, so first arrival wins.
- Supervision frames (IEC 62439-3 style): each side periodically reports its view of its own paths, and a
  silent peer is aged out at 2.5 times the interval. This exposes asymmetric failures.
- Outage journal: timestamped record of every line transition and every full outage, with cause. It is
  bounded in memory and has a durable log.
- Health alarms for silent failures such as rejected feedback.
- Optional path MTU discovery per path (`MTUProbeKind`, `MTUAck`).

**Loss recovery**
- First-arrival elimination with a replay window of 131,072 sequence numbers shared by all paths and copies.
- Selective acknowledgement: receiver feedback carries a bitmap of recently received frames. The sender
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
