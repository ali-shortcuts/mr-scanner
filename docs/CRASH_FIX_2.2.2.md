# 2.2.2-stable — launch reliability

## Why 2.2.0 crashed on open (including 32-bit)
`sqlite-jdbc` was bundled into the APK. On startup `OmegaDatabase` loaded JDBC,
which tried desktop native libraries → process killed in `Application.onCreate`.

## Guarantees in 2.2.2-stable
1. Android never opens JDBC (`database = null` in `OmegaApp`).
2. `:app` excludes `org.xerial:sqlite-jdbc`.
3. Packaging strips `org/sqlite/native/**`.
4. File-backed stores only on device.
5. Soft-fail Application + MainActivity.
6. WorkManager deferred after first frame.
7. Automated `tools/verify_launch_safe.py` must pass before release.

## Install (32-bit)
Uninstall old build first:
```bash
adb uninstall com.mrscanner.omega
adb install -r MrScannerOmega-2.2.2-stable-armeabi-v7a.apk
```
