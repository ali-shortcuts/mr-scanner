# Mr Scanner Ω — Release Specs v2.0.0-omega

## Identity
| Field | Value |
|---|---|
| Name | Mr Scanner Omega |
| Package / Application ID | `com.mrscanner.omega` |
| versionName | `2.0.0-omega` |
| versionCode (base) | `200` |
| Engine | ConfidenceEngineV3 (symmetric log-odds) |
| Plugin catalog | **41** (22 base + 9 bypass + 10 advanced) |
| Active plugins (default) | **37** |
| minSdk | 26 (Android 8.0) |
| targetSdk / compileSdk | 34 (Android 14) |
| Author | Mr Ali |
| Telegram | t.me/Mr_Ali_2025 · t.me/Ali_shortcuts |
| Email | ali.hekmati2026@gmail.com |

## APK matrix (32-bit + 64-bit)

| File | ABI | Who should install |
|---|---|---|
| `MrScannerOmega-2.0.0-universal.apk` | armeabi-v7a + arm64-v8a | **Recommended default** — works on all supported phones |
| `MrScannerOmega-2.0.0-arm64-v8a.apk` | arm64-v8a only | Phones ~2017+ (64-bit), smaller download |
| `MrScannerOmega-2.0.0-armeabi-v7a.apk` | armeabi-v7a only | Older 32-bit phones |

Install:
```bash
adb install -r MrScannerOmega-2.0.0-universal.apk
```

## Architecture modules
| Module | Description |
|---|---|
| `:core` | Engine: plugins, DAG, ConfidenceEngineV3, CLI commands, export, hole-age, metrics, security |
| `:cli` | Desktop `mrscanner` REPL (`mrscanner-2.0.0-omega.zip`) |
| `:app` | Android UI — Home · Bulk Scan · Terminal · About + FGS |

## ConfidenceEngineV3
- Polarities: `SUPPORTS_BYPASS` · `REFUTES_BYPASS` · `ABSTAIN`
- Evidence: DEFINITIVE(3.0) · STRONG(1.5) · MODERATE(0.7) · WEAK(0.3)
- Verdicts: `CONFIRMED_CANDIDATE` · `CONFIRMED_NOT_VULNERABLE` · `WEAK_SIGNAL_ONLY`
- Timeouts → ABSTAIN (never false refute)
- Symmetric minimum-evidence rule both directions

## Plugin catalog (41)
**Base (22):** tcpconnect, dns, ipv4, ipv6, http, https, tls, certificate, redirect, header, server, compression, httpversion, securityheader, cookie, robots, sitemap, fingerprint, dnsmulti, banner, cdnwaf, tlsfingerprint  

**Bypass (9):** snifronting, tlsfragment, payloadinjection, dohbypass, headerinjection, zerorated, snispoofing, misconfig, cveaudit  

**Advanced (10):** dnsconsistency, recordfragment, snisan, ech, dnstransport, ja3self, cdnedge, alpnmatrix, quic, timeconsistency  

## Runtime features
- PluginDagExecutor (dependency layers, parallel within layer)
- BudgetGuard per NetworkProfile (CELLULAR / WIFI / VPN / CIDR_BULK / DEEP)
- Shared OkHttp connection pool
- Checkpoint / resume + Hole-age store
- JSON export schema v1 + ExportRedactor (NONE/STANDARD/STRICT)
- LocalMetricsStore · EventBus · UpdateChecker (GitHub Releases API)
- In-app CLI parity with desktop
- Android NetworkProfileDetector (WiFi / Cellular / VPN)

## Permissions
- INTERNET, ACCESS_NETWORK_STATE, ACCESS_WIFI_STATE (normal)
- FOREGROUND_SERVICE + FOREGROUND_SERVICE_DATA_SYNC
- POST_NOTIFICATIONS (API 33+)
- **No READ_PHONE_STATE** (by design)

## CLI commands
`help` · `fullscan` · `hostscan` · `fragment` · `sni` · `selftest` · `set` · `get` · `export` · `holes` · `checkpoint` · `plugins` · `reverify` · `diff` · `metrics` · `cidr`

## Build
```bash
# JDK 17 + Android SDK 34
./gradlew :core:test :cli:installDist :app:assembleRelease
```

## Limits
No raw SYN / masscan pps on non-root Android. I/O-bound on cellular RTT.  
QUIC full path needs Cronet on device. See docs/LIMITS.md.

## Canonical design
`docs/omega-master.md` — full Ω-2.0.0-FINAL architecture.

## Ethics
Strictly for authorized security research, network audits, and code analysis.

## Note on ABI splits
This release is pure Kotlin/JVM (no bundled `.so` native libraries yet).  
ABI-split APKs (`armeabi-v7a` / `arm64-v8a` / `universal`) are produced per architecture §12 so installers and future Cronet/native deps are ready.  
Without native code the bytecode payload is equivalent; **install `universal` unless you need a smaller label-specific package.**  
When Cronet is enabled, arm64 vs v7a sizes will diverge significantly.
