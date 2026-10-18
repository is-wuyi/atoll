# atoll — peertransport prototype (phase B network prototype)

Isolated, runnable **application-layer PeerTransport prototype** for the Atoll
edge storage phase-A/B work. It runs a libp2p-based transport that carries the
existing `net/http` object-processing model (PUT/GET streaming) over libp2p
streams, with **explicit direct or forced CircuitRelay v2 paths**, per-peer
persistent Ed25519 identities, allowlist authorization, and finite resource
limits.

This directory is an **independent nested Go module** (`atoll/prototypes/peertransport`).
It does not import the production `atoll` module, does not modify the root
`go.mod`/`go.sum`, and is not wired into production `cmd/`/`master`/`node`/
`client`/`mount`. Nothing here is production code.

## Topology (all loopback, no TUN, no root, no EasyTier)

```
                 +-----------+
                 |  control  |  bootstrap/authorization role
                 +-----+-----+  (registry: PeerID -> current endpoints,
                       |         allowlist, relay endpoint)
     +-----------------+------------------+
     |                 |                  |
+----v----+       +-----v----+       +-----v----+
|  peer1  |       |  peer2   |       |  peer3   |   storage peers
+---------+       +----------+       +----------+
     \                 |                 /
      \                |                /
       +--------> [ relay ] <-----------+      independent CircuitRelay v2 hop
                                               (real /libp2p/circuit/relay/0.2.0/hop,
                                                NOT an HTTP proxy)
+----------------+
| peer4-unauth   |  negative test peer: not in any allowlist
+----------------+
```

Roles:

- **control** — bootstrap/control plane. Accepts connections from anyone and
  returns an explicit HTTP 403 to peers not in the join allowlist; serves the
  endpoint registry (`PeerID -> current mutable endpoints`), the authorized
  list and the relay address to authorized peers.
- **peer1..peer3** — storage peers. Persistent Ed25519 identity, listen on
  loopback TCP (+ optional QUIC), hold a CircuitRelay v2 **reservation** on the
  relay so others can reach them through it, and serve an atomic object store
  over `net/http` on top of libp2p streams.
- **relay** — standalone hop node. Real CircuitRelay v2 (`circuitv2/relay.New`)
  with ACL (only experiment peers may reserve/traverse) and **finite**
  per-circuit limits (duration + bytes per direction), reservation TTL, and
  global/per-peer reservation caps. `relay.WithInfiniteLimits` is never used.
- **peer4-unauth** — demonstrates rejection at relay, at the service
  connection gate, and at the control registry.

## Run

```bash
cd prototypes/peertransport
go test ./...                      # full test suite (~20 s)
go run ./cmd/demo                  # isolated run: private log dir + fresh demo-state
```

By default the demo creates its own private temp directory under the system
temp dir (`os.MkdirTemp`, e.g. `/tmp/atoll-peer-demo.a1b2c3`, or
`$TMPDIR/atoll-peer-demo.a1b2c3` on macOS) and prints that path at startup,
then puts `demo-state` inside it, so each run is isolated: no run reuses or
overwrites another run's identities, logs, or summary. To be reproducible across
runs, pass `-state DIR` to keep PeerIDs in a fixed directory (used verbatim,
with or without `-logdir`); pass `-logdir DIR` to reuse a specific log
directory. `-fresh` deletes everything under the effective `-state` path before
starting.

The demo prints a JSON pass summary (paths, checksums, payload byte counts —
never keys or tokens) and writes `network-demo.log` plus
`network-demo-summary.json` into its log directory. Test node logs are sent to
stderr inside the test process; `go test -v ./... >test.log 2>&1` captures the
combined test output. No test writes to a fixed log file.

## Design

- **Identity / endpoints separation** — `LoadOrCreateIdentity(dir)` creates
  `<dir>/identity.key` once with `O_CREATE|O_EXCL`, mode `0600`, and never
  overwrites it (a corrupt file is an error, not a regeneration). The PeerID
  derives from the key and is stable across restarts; listen endpoints are
  mutable and re-announced to the control registry on every start.
- **net/http preservation** — server side: a `net.Listener` adapter over
  libp2p streams feeds an unmodified `http.Server` (`/atoll/peerhttp/1`
  protocol). Client side: `http.Transport.DialContext` opens libp2p streams,
  so the ordinary `net/http` request/response model carries object data.
  Production code is untouched.
- **Explicit transport policy** — `PolicyDirect`, `PolicyForcedRelay`,
  `PolicyDirectThenRelay`. The dialer pins the peerstore address set per
  policy, tears down mismatched connections, and verifies the resulting
  connection: forced-relay must be a Limited connection whose
  `RemoteMultiaddr` contains `/p2p-circuit`; a direct request must NOT be on a
  circuit. Any fallback is recorded in `TransferStats.FallbackUsed` — there is
  no silent path switch.
- **Payload/circuit accounting** — every connection is wrapped in a counting
  `net.Conn`; `TransferStats` reports path, effective transport, remote
  multiaddr, `Limited` flag, and payload bytes read/written (for relayed
  conns these bytes are the circuit-carried bytes).
- **Authorization** — `Allowlist` of PeerIDs enforced in three layers:
  connection gater (outbound dials and inbound secured connections), stream
  listener (end-to-end PeerID check, which also covers relayed connections),
  and the relay ACL (reserve/connect). The control role additionally returns
  403 at the HTTP layer for unauthorized registrations. Infrastructure peers
  (e.g., an extra relay) can be authorized at the gater level only via
  `StoragePeer.AllowInfraPeer` — they never enter a service allowlist.
- **Data plane security** — libp2p Noise is the only registered security
  protocol on TCP (QUIC uses libp2p's embedded identity-locked TLS). The
  handshake is bound to the Ed25519 PeerID, giving end-to-end encrypted and
  authenticated channels; the dialer and listener reject peers without a
  verified public key. There is no plaintext transport in this configuration,
  so an unencrypted fallback is impossible by construction.
  **This is transport security only — it is not static disk encryption.**
- **No外联** — no DHT, no bootstrap, no peer discovery of any kind. Every
  connection is an explicit dial to an explicitly configured, allowlisted
  peer; the connection gater blocks dials to unknown peers.
- **Resource budget** — per-object cap (default 256 MiB) enforced with an
  atomic commit (temp file + rename after checksum match), per-request
  wall-clock deadline (default 120 s) via `http.ResponseController` — read
  deadlines for uploads, write deadlines for downloads —, a 64 KiB cap on
  control-plane registration bodies, per-host finite resource manager
  (`rcmgr` fixed limits), per-circuit relay limits (1 h / 256 MiB per
  direction by default), reservation TTL 30 min, max 16 reservations / 8
  circuits per peer (`MaxReservations` is the relay's GLOBAL reservation
  budget, `MaxCircuits` is per peer; both tested as actually enforced).
  Nothing in this prototype runs with unlimited duration or bytes.

## Test coverage (`go test ./...`)

| Test | What it proves |
|---|---|
| `TestIdentitySurvivesRestart` | PeerID stable across reload and node restart; key file mode 0600 |
| `TestIdentityCorruptFileNeverOverwritten` | corrupt key file errors out and is never regenerated |
| `TestDirectRequestChecksumRoundtrip` | 8 MiB direct push+fetch, sha256 match, direct path, no circuit |
| `TestNodeNodePushChainExchange` | complete object exchange across peer1→peer2→peer3, checksum stable at every hop |
| `TestDirectThenRelayFallbackAndPreference` | fallback to circuit is recorded when direct is unreachable; direct is preferred (no relay detour) when reachable |
| `TestForcedRelayLargeStreamHashMatch` | 72 MiB (well over 64 MiB) push+fetch over a real CircuitRelay v2 connection: `/p2p-circuit` in RemoteMultiaddr, `Limited` stat, hash match |
| `TestForcedRelayNoSilentDirectFallback` | gater-authorized dead relay ⇒ the relay dial itself fails with a real dial error; hard failure, zero connections to target (no silent direct fallback) |
| `TestRelayCircuitDataLimitFailsCleanly` | 9 MiB push over a real 4 MiB-limited circuit (both peers hold reservations): circuit opens, carries a partial transfer (~4 MiB), the per-circuit data limit cuts it mid-stream; no half object |
| `TestRelayReservationLimitsFinite` | relay limits are finite by construction |
| `TestRelayGlobalReservationCap` | the relay's GLOBAL reservation budget is enforced: with `MaxReservations=2` a third authorized peer is denied, existing holders keep working |
| `TestControlRegisterBodyCapped` | even an authorized peer cannot push an unbounded body into the control plane (explicit 413 over the 64 KiB cap) |
| `TestUnauthorizedRejectedRelayAndService` | unauthorized peer rejected at the service connection gate and at the relay |
| `TestControlRegisterForbidden` | control returns explicit 403 to unauthorized joiners |
| `TestTransferDeadlineNoHalfObject` | stalled upload aborted by the deadline; no half object |
| `TestStalledFetchAbortedByDeadline` | stalled DOWNLOAD (client stops reading mid-GET) aborted by the write deadline; stream released, peer keeps serving |
| `TestCancelMidTransferClean` | client cancellation aborts cleanly, store stays clean, next transfer works |
| `TestObjectSizeLimitNoHalfObject` | 9 MiB push into an 8 MiB-capped store rejected (413), nothing committed |
| `TestWrongExpectedPeerRejected` | dial with mismatched expected PeerID fails (identity-locked handshake) |
| `TestNoSilentUnencryptedFallback` | every connection shows a verified remote identity; secure flag recorded |
| `TestQUICOptionalDirect` | QUIC-only endpoint works for direct transport |

## Dependencies (pinned)

Go `1.26.7`. Direct requirements (see `go.mod`):

- `github.com/libp2p/go-libp2p v0.50.0` (latest stable at time of writing;
  chosen deliberately — pin stays until a deliberate upgrade)
- `github.com/multiformats/go-multiaddr v0.16.1`

Full module graph: 136 modules / 537 packages. Extracted module cache usage of
the heavy trees: go-libp2p ≈ 7.6 MB, quic-go ≈ 5.1 MB, multiformats ≈ 1.4 MB
(plus their transitive deps — pion/webrtc, prometheus, uber fx/zap, etc.).

## Honest limits — read before citing

- **Loopback only.** Every claim in this prototype was verified on
  `127.0.0.1`. **No WAN, NAT traversal, or hole-punching behavior has been
  verified.** `libp2p.EnableHolePunching()` is enabled on storage peers so the
  option plumbing is exercised — in go-libp2p v0.50.0 this starts the
  hole-punch service implementing the `/libp2p/dcutr` protocol (DCUtR), but on
  loopback it stays idle. AutoNAT reachability probing is NOT enabled
  (neither `EnableNATService` nor `EnableAutoNATv2`), so no peer acts as a
  reachability probe server and peers cannot LEARN whether they are WAN
  reachable. Both AutoNAT and real WAN hole punching remain untested and must
  be added and verified in a later phase before any NAT claim.
- **This is a prototype, not the production network migration.** It shares no
  code with the production `atoll` module (by design, to keep the boundary
  clean); migrating these mechanisms into production transport is future work.
- The relay holds reservations with a TTL; the prototype does not implement
  background reservation refresh for long-lived sessions (tests and demo are
  short-lived). Direct/circuit dialing currently uses the shared connect timeout
  (default 15 s); the `DirectTimeout` field is not yet applied. Concurrent dials
  with conflicting path policies to the same peer are not validated: path
  enforcement currently rewrites that peer's address set and closes other paths.
- E2E here means transport-level encrypted/authenticated channels between
  verified peers. It does not cover at-rest encryption, nor authorization
  beyond PeerID allowlists.
- Object store is a minimal per-peer store for transport validation, not the
  production storage engine. A successful transfer only tests process-visible
  atomic rename; the manifest is in memory and it does not implement durable
  restart recovery, disk fsync, concurrent overwrite publication, erasure coding
  or production replication/GC contracts.
- QUIC relay hopping works in the demo (the circuit addr may use the relay's
  QUIC endpoint), but path selection between the relay's TCP/QUIC addresses is
  whatever `host.Addrs()` lists first — not yet policy-driven.
