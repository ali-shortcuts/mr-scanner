# v2.3.0-final — production launch reliability

## Install (32-bit phones)
```bash
adb uninstall com.mrscanner.omega
adb install -r MrScannerOmega-2.3.0-final-armeabi-v7a.apk
adb shell am start -n com.mrscanner.omega/.MainActivity
```

## Crash root cause (fixed since 2.2.1/2.3.0)
sqlite-jdbc desktop natives were inside the APK and killed Application.onCreate.

## 2.3.0 guarantees
- sqlite-jdbc is compileOnly on :core; :app excludes it; packaging strips natives
- OmegaApp never opens JDBC (database=null)
- File-backed persistence on Android
- Soft-fail Application + MainActivity
- Deferred WorkManager
- PNG mipmap launcher icons (OEM-safe)
- AppCompat vector compat enabled
- FGS startForeground hardened
- verify_launch_safe.py must pass

## Verified in CI-like environment
- BUILD SUCCESSFUL
- unit tests green
- APK contains zero org/sqlite/native
- APK signature v2 OK
- live CLI selftest + fragment OK
