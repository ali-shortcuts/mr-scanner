# Mr. Scanner Ω — Release Specs v2.0.0-omega

## Identity (architecture §9)

| Field | Value |
|---|---|
| Name | **Mr. Scanner Ω** |
| Application ID | `com.mrscanner.omega` |
| versionName | `2.0.0-omega` |
| versionCode (base) | `200` |
| Architecture | **Ω-2.0.0-FINAL** |
| Engine | Confidence v3 (symmetric log-odds) |
| Plugins | **41** (22 base + 9 bypass + 10 advanced) |
| Transport | OkHttp + optional Cronet H3 |
| minSdk / targetSdk | 26 / 34 |
| Creator | **Mr Ali** |
| Telegram | [t.me/Mr_Ali_2025](https://t.me/Mr_Ali_2025) |
| Channel | [t.me/Ali_shortcuts](https://t.me/Ali_shortcuts) |
| Email | [ali.hekmati2026@gmail.com](mailto:ali.hekmati2026@gmail.com) |
| Social | Facebook `AliShortcuts` · TikTok/Instagram/YouTube: `ali_shortcuts` |
| In-app warning | «Strictly for authorized security research, network audits, and code analysis.» |

## App Specs & Engine Info (in-app About card)

- `Engine: Confidence v3 (symmetric log-odds)`
- `Plugins: 41 (22 base + 9 bypass + 10 advanced)`
- `Transport: OkHttp + optional Cronet H3`

## APK matrix (32-bit + 64-bit)

| File | ABI | Who should install |
|---|---|---|
| `MrScannerOmega-2.0.0-universal.apk` | armeabi-v7a + arm64-v8a | **Recommended default** |
| `MrScannerOmega-2.0.0-arm64-v8a.apk` | arm64-v8a only | Modern 64-bit phones |
| `MrScannerOmega-2.0.0-armeabi-v7a.apk` | armeabi-v7a only | Older 32-bit phones |

```bash
adb install -r MrScannerOmega-2.0.0-universal.apk
```

## UI branding (§7.4)

- Dark theme surfaces `#0B1020` / `#121A2F`
- Primary `#5B8CFF` · Secondary `#9AD1FF`
- Verdict chips: green `CANDIDATE` · gray `WEAK` · dark-red `NOT_VULN`
- Terminal: mono font, dark background, WCAG AA contrast
- Logo: Ω radar mark · Creator avatar monogram **MA**

## Modules

| Module | Description |
|---|---|
| `:core` | Engine, 41 plugins, DAG, ConfidenceEngineV3, CLI, export, hole-age |
| `:cli` | Desktop `mrscanner` |
| `:app` | Android — Home · Scan · Term · About |

## Ethics

> Strictly for authorized security research, network audits, and code analysis.

Canonical design: `docs/omega-master.md`
