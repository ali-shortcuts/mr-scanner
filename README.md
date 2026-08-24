# Mr. Scanner Ω

**Powerful mobile-class network scanner** — ConfidenceEngineV3 · 41-plugin DAG · DPI/bypass research tooling.

> Strictly for **authorized** security research, network audits, and code analysis.  
> Unauthorized scanning of networks you do not own or have permission to test may be illegal.

| | |
|---|---|
| Package | `com.mrscanner.omega` |
| Version | **2.3.0-final** |
| Engine | Confidence v3 (symmetric log-odds) |
| Plugins | **41 catalog · 37 active by default** |
| minSdk / targetSdk | 26 / 34 |

---


## What's new in 2.2.0

- **Real DNS-over-TLS (DoT)** answers, not just port 853 open
- **QUIC/H3** via UDP path + Alt-Svc + HTTPS RR
- **Cellular bind** + SIM operator detect (zero-rate path)
- **APK tab** in app (pick & analyze APK)
- **WorkManager** 12h hole re-verify
- Cert SHA-256 meta in ApkStaticAnalyzer

## What's new in 2.1.0 (deep engine)

- **Real TLS ClientHello record fragmentation** (`FragmentingSocket`) — not sleep-fakes
- **True multi-resolver DNS** (UDP + DoH Cloudflare/Google/Quad9 + system)
- **JA3** from crafted ClientHello bytes
- **QUIC UDP path probe** + HTTPS RR h3 hints
- **Zero-rating operator packs** (AF + captive) on cellular profile
- **Active lab injection probes** (safe canary reflection)
- **ApkStaticAnalyzer** (`apk <file.apk>` CLI)
- **SQLite persistence** (Room-compatible schema) for holes/checkpoints
- **FGS auto-promote** on bulk scans · **UpdateChecker** on About
- **AliasPrefixDeduper** wired into `cidr`
- Expanded offline **CVE** signature table

## Download APK (32-bit + 64-bit)

| APK | ABI | Recommended for |
|---|---|---|
| [`MrScannerOmega-2.2.0-universal.apk`](dist/MrScannerOmega-2.2.0-universal.apk) | 32+64 | **Default — all phones** |
| [`MrScannerOmega-2.2.0-arm64-v8a.apk`](dist/MrScannerOmega-2.2.0-arm64-v8a.apk) | 64-bit | Modern phones (2017+) |
| [`MrScannerOmega-2.2.0-armeabi-v7a.apk`](dist/MrScannerOmega-2.2.0-armeabi-v7a.apk) | 32-bit | Older devices |

Also: CLI zip · full source tarball · [`SPECS.md`](dist/SPECS.md) · [`SHA256SUMS.txt`](dist/SHA256SUMS.txt)  
GitHub Release: [v2.3.0-final](https://github.com/ali-shortcuts/mr-scanner/releases/tag/v2.3.0-final)

```bash
adb install -r dist/MrScannerOmega-2.2.0-universal.apk
```

---

## What's inside

| Module | Role |
|---|---|
| `:core` | Pure Kotlin engine — plugins, DAG, ConfidenceEngineV3, CLI, export, hole-age, metrics |
| `:cli` | Desktop `mrscanner` REPL / one-shot commands |
| `:app` | Android UI — Home · Bulk Scan · Terminal · About |

### Architecture (canonical)
Full design doc: [`docs/omega-master.md`](docs/omega-master.md)

Highlights:
- **ConfidenceEngineV3** — SUPPORTS / REFUTES / ABSTAIN + log-odds; symmetric `CONFIRMED_CANDIDATE` ↔ `CONFIRMED_NOT_VULNERABLE`
- **PluginDagExecutor** + **BudgetGuard** (network-profile aware)
- P0: `dnsconsistency`, `recordfragment`, `snisan` (SAN-aware SNI exploitability)
- Bypass family: TLS fragment, SNI fronting/spoof, DoH, zero-rate (cellular), CVE lite, …
- Checkpoint / hole-age persistence · JSON export schema v1 · EventBus · selftest

### Android tabs
1. **Home** — one-host fullscan + verdict card  
2. **Scan** — multi-host bulk scan with live progress  
3. **Term** — full in-app CLI  
4. **About** — engine specs, contacts, disclaimer  

---

## Build

### Requirements
- JDK **17+**
- Android SDK **34** (for APK)
- Gradle wrapper included

```bash
# CLI + tests (no Android SDK required)
./gradlew :core:test :cli:installDist

./mrscanner selftest
./mrscanner fullscan example.com --confidence
./mrscanner help

# Android APK
echo "sdk.dir=$ANDROID_HOME" > local.properties
./gradlew :app:assembleRelease
# → app/build/outputs/apk/release/app-release.apk
```

### Useful CLI commands

| Command | Purpose |
|---|---|
| `fullscan <host\|file>` | Full DAG + confidence |
| `fragment <host>` | tlsfragment + recordfragment |
| `sni --target=` | fronting + SAN |
| `selftest` | Engine fixtures + live soft checks |
| `export <id>` | JSON schema v1 |
| `holes` / `checkpoint` | Persistence |
| `cidr a.b.c.0/24` | Bulk ≤/24 |
| `set key=value` | Live settings |
| `plugins` | Catalog |

---

## Tests

```bash
./gradlew :core:test
```

Unit coverage includes ConfidenceEngineV3 truth table, SAN/wildcard match, DAG topology + dead-host short-circuit.

---

## GitHub Actions

- **CI** (`.github/workflows/ci.yml`) — core tests + CLI on every push  
- **Release** (`.github/workflows/release.yml`) — on tag `v*`, builds APK + CLI zip  

Optional secrets for signed release: `RELEASE_KEYSTORE_BASE64`, `KEYSTORE_PASSWORD`, `KEY_ALIAS`, `KEY_PASSWORD`.

```bash
git tag v2.3.0-final
git push origin v2.3.0-final
```

---

## Limits (honest)

No raw SYN / masscan-class pps on non-root Android. This tool is **I/O-bound** on cellular RTT.  
See [`docs/LIMITS.md`](docs/LIMITS.md).

QUIC/HTTP3 full path needs Cronet on device (`testQuic` flag). ECH is probe-level. Zero-rating needs operator packs on cellular.

---

## Creator / Support

**Powered by Mr Ali**

Created and developed by Mr Ali, an independent developer building practical digital tools, automation solutions, and useful projects. Follow the channels below for updates, new projects, and useful content.

| | |
|---|---|
| **Email** | [Ali.hekmati2026@gmail.com](mailto:Ali.hekmati2026@gmail.com) |
| **Telegram** | [t.me/Mr_Ali_2025](https://t.me/Mr_Ali_2025) |
| **Telegram Channel** | [t.me/Ali_shortcuts](https://t.me/Ali_shortcuts) |
| **Facebook** | [facebook.com/AliShortcuts](https://www.facebook.com/AliShortcuts) |
| **TikTok** | [tiktok.com/@ali_shortcuts](https://www.tiktok.com/@ali_shortcuts) |
| **Instagram** | [instagram.com/ali_shortcuts](https://www.instagram.com/ali_shortcuts) |
| **YouTube** | [youtube.com/@Ali_Shortcuts](https://www.youtube.com/@Ali_Shortcuts) |


## License / ethics

> Strictly for authorized security research, network audits, and code analysis.

Use only on systems you own or are explicitly authorized to test.
