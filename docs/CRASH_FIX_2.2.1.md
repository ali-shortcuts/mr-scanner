# Crash fix 2.2.1-hotfix

## Symptom
App installs on 32-bit (armeabi-v7a) devices, then immediately force-closes on open.

## Root cause
`org.xerial:sqlite-jdbc` was a transitive dependency of `:core` and was packaged into the Android APK.
That library embeds **desktop** natives (Windows/Mac/Linux). On Android startup,
`OmegaDatabase` called `Class.forName("org.sqlite.JDBC")`, which attempted to load an incompatible native
and killed the process in `Application.onCreate()` before any UI appeared.

## Fix
1. Detect Android via `Class.forName("android.os.Build")` and **never** enable JDBC on Android.
2. On Android always use file-backed `HoleAgeStore` / `CheckpointStore` fallback.
3. `app` dependency excludes `org.xerial:sqlite-jdbc` entirely.
4. Packaging excludes `**/org/sqlite/native/**`.
5. `Application.onCreate` and `MainActivity.onCreate` wrapped to fail soft (log, continue).

## Verification
- APK zip listing contains **zero** `org/sqlite/native/**` paths.
- versionName `2.2.1-hotfix` versionCode `221`.
