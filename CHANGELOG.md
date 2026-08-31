# Changelog

## v2.4.1-hotfix

Real device-testing found three bugs from v2.4.0-unbound that made the new Scan Host/CIDR and Terminal features effectively unusable:

- **App froze/went black on every "Start" tap** (Scan Host and Scan CIDR): `CellularNetworkBinder.bindToCellular()` blocks on a `CountDownLatch` for up to 4 seconds, and it was being called directly on the UI thread inside the button click handler — well past Android's ANR threshold. Moved off the UI thread.
- **App froze when loading a host/CIDR list from a file**: the file-picker result handler read and parsed the file synchronously on the UI thread. Moved to a background coroutine.
- **Terminal printed every command's output twice**: `CliInterpreter` was re-broadcasting command output onto the same event bus Terminal's new live-feed listener also reads from. Removed the redundant rebroadcast.

## v2.4.0-unbound

### Scan engine
- **No more /24 cap on CIDR scans.** `CidrRangeEngine` streams addresses lazily (a `Sequence`, not a materialized `List`) for any prefix `/0`–`/32` — a `/8` costs the same memory as a `/30`.
- **CIDR scanning is now two independently bounded-concurrency stages** (precheck → full plugin scan) instead of a sequential precheck loop that ignored the configured concurrency entirely.
- **Scan Host brought up to the same standard**: was still `hosts.map { async { ... } }.awaitAll()` (launches every host as a coroutine up front, regardless of list size). Now streams through `Flow.flatMapMerge(concurrency)`, same as CIDR.
- Concurrency ceiling raised from a hardcoded 64 to a configurable 4096 (still bounded on purpose — past a few thousand simultaneous sockets you hit OS fd/thread limits, not more throughput).
- Rolling per-/24 alias dedupe (0.80 cap) applied on the fly during CIDR streaming instead of only after materializing the full host list.
- Lightweight numeric-cursor checkpointing for CIDR resume (`CidrCheckpointRecord`) — doesn't store a full completed-hosts list, so resume cost doesn't scale with range size.
- Host-scan resume now checks set-membership against completed hosts instead of a raw list index (correct regardless of concurrent completion order).
- Fixed O(n²) result-reordering after a host scan (was `hosts.mapNotNull { results.find { ... } }`; now an O(n) map lookup).
- New `ScanEvent.RangeProgress` (Long-safe) and `foundCount` on `ScanEvent.Progress` — live scanned/remaining/found counts for both CIDR and host scans.
- Fixed a subscribe-before-emit race: every place that launched an event collector and immediately started a scan had no guarantee the collector had actually subscribed before the first event — could silently drop the initial "scan started" line. Now waits on `EventBus.subscriberCount` first.

### App UI
- Scan tab split into **Scan Host** / **Scan CIDR** sub-tabs, each supporting both manual paste and **file input** for host/range lists.
- New **Settings dialog**: concurrency (slider, ceiling 4096), ports, precheck timeout, DNS region, custom DNS servers.
- **Terminal now shows a live global feed**: a scan started from Home, Scan Host, or Scan CIDR streams into Terminal too (percent / scanned / remaining / found on a status line, verdicts and log lines in the scroll log) — not just terminal-issued commands.

### APK analyzer
- Real binary `AndroidManifest.xml` parser (`AxmlParser`) — package, version, min/target/compile SDK, every permission, every activity/service/receiver/provider with real `exported` resolution (explicit attribute, or the OS's actual pre-API31 default).
- Real DEX header parsing (`DexHeaderReader`) — actual class/method/string counts instead of guessing from printable-string extraction.
- Real signature inspection (`SignatureInspector`) — X.509 cert parsing for v1/jar signatures (subject, issuer, self-signed, expiry) plus byte-marker detection of APK Signing Block v2/v3. **Fixes a false positive**: the old analyzer only checked `META-INF/*.RSA` files and would call any APK built with a current AGP (v2-signed by default, no such files) "unsigned".
- New findings: real `debuggable`/`allowBackup`/`usesCleartextTraffic` (from actual manifest attributes, not word-matching), exported-component-without-permission, expired/self-signed certs, low `minSdkVersion`.

### CI
- `:app:assembleDebug` now runs on every push, not just on release tags — app/ changes get a real compile check immediately instead of only at release time.

### Known scope not yet covered
- v2/v3 signing block: presence/scheme-ID detection only, not certificate extraction (the nested length-prefixed parsing needed for that wasn't validated enough to ship with confidence).
