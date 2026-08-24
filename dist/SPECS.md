# Mr. Scanner Ω — Release Specs v2.1.0-omega

## Identity
| Field | Value |
|---|---|
| Name | **Mr. Scanner Ω** |
| Application ID | `com.mrscanner.omega` |
| versionName | `2.1.0-omega` |
| versionCode | `210` |
| Architecture | Ω-2.1.0-DEEP |
| Engine | Confidence v3 (symmetric log-odds) |
| Plugins | **41 catalog · 38 active default** |
| Transport | OkHttp + FragmentingSocket + QUIC UDP probe |
| Creator | **Mr Ali** |

## Deep capabilities (2.1)
- FragmentingSocket: real TLS record-layer ClientHello split
- MultiResolverDns: system + UDP + DoH (CF/Google/Quad9)
- JA3Calculator from crafted ClientHello
- ZeroRatePacks (Afghanistan-generic + captive)
- Safe payload/header injection canaries
- ApkStaticAnalyzer (permissions, ABIs, dangerous API strings)
- SQLite OmegaDatabase (checkpoints, hole_age, host_fingerprints)
- FGS promote on bulk scan; UpdateChecker on About
- AliasPrefixDeduper on cidr path

## Creator / Support
**Powered by Mr Ali**
- mailto:Ali.hekmati2026@gmail.com
- https://t.me/Mr_Ali_2025
- https://t.me/Ali_shortcuts
- https://www.facebook.com/AliShortcuts
- https://www.tiktok.com/@ali_shortcuts
- https://www.instagram.com/ali_shortcuts
- https://www.youtube.com/@Ali_Shortcuts

## APK matrix
| File | ABI |
|---|---|
| MrScannerOmega-2.1.0-universal.apk | 32+64 recommended |
| MrScannerOmega-2.1.0-arm64-v8a.apk | 64-bit |
| MrScannerOmega-2.1.0-armeabi-v7a.apk | 32-bit |

## Ethics
> Strictly for authorized security research, network audits, and code analysis.
