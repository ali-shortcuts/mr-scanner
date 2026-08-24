# Mr Scanner Ω — سند معماری نهایی و واحد (نسخه‌ی کامل‌شده‌ی قدرتمند)
### جایگزین کامل تمام نسخه‌های قبلی (`omega-architecture.md` + `advanced-plugins.md` + بازبینی‌های میانی)
### وضعیت: **COMPLETE · CANONICAL · IMPLEMENTATION-READY**
### نسخه‌ی سند: **Ω-2.0.0-FINAL** · تاریخ canonical: **2026-08-23**

---

> ### سه لایه‌ی اصلاح نسبت به اسناد قبلی (نه ادغام متنی)
>
> **لایه A — اصلاحات نسخه‌ی ادغام اولیه**
> 1. **شمارش پلاگین** — عدد «۲۶» غلط بود → **۲۲ پایه + ۹ bypass = ۳۱ موجود**.
> 2. **موتور QUIC** — `netty-incubator-codec-quic` (ناپایدار) → **Cronet** + `cronet-transport-for-okhttp` روی همان `OkHttpClient` مشترک.
> 3. **موتور امتیازدهی** — جمع وزنی ساده → **مدل شواهد سه‌حالته + ترکیب log-odds** (بخش ۴).
>
> **لایه B — بازبینی کامل‌سازی میانی**
> 4. **شمارش ۳۷ خودش غلط بود** — ۲۲+۹=۳۱ موجود + **۱۰ پلاگین جدید** = **۴۱ پلاگین در مجموع** (نه ۶؛ `AdvancedPlugins.kt` نه نام داشت + `SniExploitabilityPlugin` جدا).
> 5. **موتور امتیازدهی نامتقارن بود** — قاعده‌ی «حداقل یک DEFINITIVE یا دو STRONG» فقط برای تأیید بود؛ verdict سوم `CONFIRMED_NOT_VULNERABLE` با قاعده‌ی قرینه اضافه شد.
> 6. **گپ‌های عملیاتی** — پایپ‌لاین انتشار فاقد `KEY_ALIAS`/`KEY_PASSWORD` بود؛ بخش دسترسی‌های اندروید (۱۲.۵) اضافه شد.
>
> **لایه C — این نسخه (Ω-2.0.0-FINAL) — کامل‌سازی تا انتها + قدرت عملیاتی**
> 7. **کدهای «اسکلت» به «پیاده‌سازی‌پذیر» ارتقا یافتند** — تمام تایپ‌ها، امضاها، Room schema، CLI registry، EventBus wiring، و قرارداد `ScanPlugin` کامل‌اند و بدون «TODO مبهم» رها نشده‌اند.
> 8. **لایه‌ی امنیت اپ، تهدیدمدل، و ضدسوءاستفاده** اضافه شد (بخش ۱۴) — برای ابزاری که DPI/zero-rating را لمس می‌کند ضروری است، نه تزئینی.
> 9. **ماتریس وابستگی پلاگین + DAG اجرا + بودجهٔ هزینه** (بخش ۳.۴–۳.۶) — بدون این، ۴۱ پلاگین روی موبایل به thrashing تبدیل می‌شود.
> 10. **Observability، متریک‌ها، و telemetery محلی** (بخش ۱۵) — بدون عدد، «قدرتمند» فقط ادعا است.
> 11. **قرارداد خروجی JSON پایدار + schema versioning** (بخش ۱۶) — پیش‌نیاز differential test با باینری Go و هر مصرف‌کننده‌ی خارجی.
> 12. **Threat model اپراتور/شبکه + حالت‌های عملیاتی** (بخش ۱۷) — WiFi / Cellular / Airplane+WiFi / VPN-on جدا مدل شده‌اند.
> 13. **نقشه‌ی راه با Definition of Done قابل‌اندازه‌گیری** برای هر فاز (بخش ۱۱ بازنویسی‌شده).
> 14. **فهرست کامل فایل‌های جدید/تغییریافته** (پیوست A) — یک مهندس می‌تواند از صفر checkout کند و بداند دقیقاً چه چیزی را باید بسازد.

---

## بخش ۰ — هویت سند و قواعد خواندن

| فیلد | مقدار |
|---|---|
| نام سند | Mr Scanner Ω Master Architecture |
| وضعیت | **Canonical** — تنها مرجع معماری |
| زبان پیاده‌سازی | Kotlin 1.9+ / Android API 26+ (target 34)، Coroutines + Flow |
| بدنه‌ی نگه‌داشته‌شده | پروژه‌ی Android/Kotlin موجود (B) |
| مغز پورت‌شده | منطق تصمیم‌گیری Go CLI (A) |
| موتور verdict | `ConfidenceEngineV3` (log-odds، متقارن) |
| شمارش پلاگین | **۴۱** (۲۲ پایه + ۹ bypass + ۱۰ جدید) |
| توزیع | GitHub Releases · sideload · APK multi-ABI |
| اختیار آینده | بخش ۱۳ — ADR الزامی برای تغییر بزرگ |

**قاعده‌ی خواندن برای دستیار AI / مهندس جدید:**
1. بخش ۱–۲ = «چرا و کجا».
2. بخش ۳–۴ = «چه چیزی و چگونه تصمیم می‌گیرد» — قلب محصول.
3. بخش ۵–۷ = تنظیمات، CLI، عملکرد.
4. بخش ۸ + ۱۱ + ۱۲ = چگونه از سند به APK امضاشده برسیم.
5. بخش ۱۴–۱۷ = لایه‌هایی که بدونشان «قدرتمند» توخالی است.
6. پیوست A–D = چک‌لیست اجرایی روز صفر.

---

## بخش ۱ — فلسفه‌ی ادغام (خلاصه)

دو پروژه بررسی شد: **Go CLI** (منطق تصمیم‌گیری بالغ) و **Android/Kotlin موجود** (معماری plugin-based بالغ، از قبل دارای Console زنده و TLS-fragmentation دستی روی Socket خام). نتیجه:

> **بدنه‌ی Kotlin نگه داشته می‌شود، مغز Go داخلش کاشته می‌شود.**

| قابلیت | Go (A) | Kotlin موجود (B) | تصمیم |
|---|---|---|---|
| TLS Fragmentation | ✅ | ✅ (`FragmentingSocket`) | نگه‌داشتن B |
| SNI Exploitability (چک SAN گواهی) | ✅ دقیق | ⚠️ سطحی‌تر | پورت منطق A داخل پلاگین B |
| Confidence Scoring | ✅ ولی ساده | ⚠️ فقط تفریق امتیاز | **بازطراحی کامل، بخش ۴** |
| Checkpoint/Resume | ✅ | ❌ | پورت به Room |
| Hole-Age Tracking | ✅ | ❌ | Entity جدید |
| DNS چندمنطقه‌ای | ✅ کامل | ⚠️ محدود | تجمیع لیست از A |
| JARM-lite/Favicon Hash | ✅ | ❌ | پکیج جدید |
| CVE Audit | ❌ | ✅ | نگه‌داشتن B |
| APK Static Analyzer | ❌ | ✅ کامل | نگه‌داشتن B — بی‌رقیب |
| Plugin/EventBus/Room/Foreground-Service | ❌ | ✅ | نگه‌داشتن B |
| Live Console | ❌ (ترمینال خام) | ✅ (`LiveConsoleView`) | پایه‌ی CLI درون‌برنامه‌ای (بخش ۶) |
| Differential validation | — | — | **جدید: هر دو موتور در برابر هم** (۱۱.۴) |

**اصل غیرقابل‌مذاکره:** هیچ قابلیت Goای «دوباره از صفر اختراع» نمی‌شود اگر معادل بالغ در B وجود دارد. پورت یعنی **منطق تصمیم**، نه کپی syntax.

---

## بخش ۲ — درخت پکیج نهایی (کاملاً یکپارچه)

```
com.mrscanner.omega          ← rename اجباری قبل از انتشار (فعلاً com.aistudio.mrscanner.app)
│
├── core/
│   ├── plugin/
│   │   ScanPlugin · ScanTarget · ScanContext · PluginResult
│   │   PluginSignal · EvidenceClass · SignalPolarity          [از بخش ۴ — shared types]
│   │   WorkflowStep · PluginCost · PluginDependency
│   │
│   ├── eventbus/
│   │   EventBus · ScanEvent
│   │   (LogEmitted · Progress · HostVerdict · CheckpointSaved · HoleClosed)
│   │
│   ├── scheduler/
│   │   ScanScheduler · DefaultScanScheduler · WorkerPoolScanner
│   │   AdaptiveConcurrencyController
│   │   GlobalConnectionGate          ← معادل pkg/netlimit
│   │   RateLimiter
│   │   RetryEngine
│   │   ★ PluginDagExecutor.kt        ← اجرای وابسته بر اساس بخش ۳.۴          [NEW]
│   │   ★ AliasPrefixDeduper.kt       ← پورت pkg/scanner/aliased.go            [NEW]
│   │   ★ BudgetGuard.kt              ← سقف زمان/بایت/اتصالات per-host         [NEW]
│   │
│   ├── intelligence/
│   │   BypassIntelligenceStore · ScanDiffEngine
│   │   BypassVerdictEngine           ← سازگاری UI؛ verdict نهایی از V3
│   │   ★★ ConfidenceEngineV3.kt      ← بخش ۴                                   [NEW]
│   │   ★ EvidenceExplainer.kt        ← متن انسانی از contributingSignals       [NEW]
│   │
│   ├── db/
│   │   entities/
│   │     ScanEntity · ResultEntity · LogEntity · WorkflowEntity · BypassTechniqueStat
│   │     ★ CheckpointEntity          ← schemaVersion + configHash              [NEW]
│   │     ★ HoleAgeEntity             ← open/closed + تاریخچه                   [NEW]
│   │     ★ HostFingerprintEntity     ← favicon/jarm/ja3 cache                  [NEW]
│   │   dao/ + CheckpointDao · HoleAgeDao · HostFingerprintDao
│   │   repository/ ScanRepository · CheckpointRepository · HoleAgeRepository
│   │   ★ Mappers.kt                  ← Entity ↔ domain                         [NEW]
│   │
│   ├── network/
│   │   AfghanOperatorDns             ← + AfghanDNSServers کامل از Go
│   │   MultiResolverDns              ← + RegionalDNSServers + DoHResolvers
│   │   ★ DnsHttpsRecordQuery.kt      ← rawQuery type=65 (ECH)                  [NEW]
│   │   ★ SharedOkHttpFactory.kt      ← pool مشترک + optional Cronet            [NEW]
│   │   ★ QuicFeature.kt              ← feature-flag HTTP/3                     [NEW]
│   │   CellularNetworkBinder · SimOperatorDetector
│   │   ★ NetworkProfileDetector.kt   ← WiFi/Cell/VPN/Metered → profile         [NEW]
│   │
│   ├── fingerprint/                  ★ پکیج جدید                               [NEW]
│   │   FaviconHasher.kt              ← murmur3 سازگار Shodan
│   │   JarmLite.kt
│   │   TechDetector.kt
│   │   Ja3SelfReporter.kt            ← هش ClientHello خام FragmentingSocket
│   │
│   ├── cache/ · log/ · session/
│   │   settings/ ConsoleSettings (بخش ۵) · SettingsRepository
│   │
│   ├── security/                     ★ پکیج جدید (بخش ۱۴)                      [NEW]
│   │   RootDetector · DebuggerDetector · ApkIntegrityChecker
│   │   SecurePrefs · ExportRedactor
│   │
│   ├── update/                       ★ UpdateChecker (۱۲.۴)                    [NEW]
│   │
│   ├── metrics/                      ★ بخش ۱۵                                  [NEW]
│   │   LocalMetricsStore · ScanTiming · PluginTiming
│   │
│   ├── export/                       ★ بخش ۱۶                                  [NEW]
│   │   ResultJsonCodec · SchemaV1 · SchemaMigrator
│   │
│   └── ★ cli/                                                                  [NEW]
│       CliInterpreter · CliCommand · CliCommandRegistry
│       CliSession · CliArgs · CliOutputLine · CliOutputStream
│       commands/ HostScanCmd · CidrCmd · SniCmd · FragmentCmd
│                 FullScanCmd · ReverifyCmd · SelfTestCmd · SetCmd
│                 ExportCmd · DiffCmd · HelpCmd
│
├── features/
│   ├── hostscan/plugins/
│   │   HostPlugins.kt                (۲۲ پایه — دست‌نخورده)
│   │   BypassPlugins.kt              (۹ bypass — دست‌نخورده)
│   │   ★ AdvancedPlugins.kt          (۹ از ۱۰ جدید)
│   │   ★ SniExploitabilityPlugin.kt  (دهمی — SAN-aware)
│   ├── cidrscan/                     (+ AliasPrefixDeduper در مسیر)
│   ├── bulkscan/ · workflow/ · reports/(+ raw export)
│   ├── plugins/ · logs/ · settings/ · about/ · boot/
│   ├── apkanalyzer/                  کامل دست‌نخورده — مزیت رقابتی
│   └── ★ terminal/                   TerminalScreen · TerminalViewModel        [NEW]
│
├── di/                               ★ Hilt/Koin modules صریح برای NEWها       [NEW]
│
└── ui/navigation/ (+ مسیر Terminal) · ui/theme/ (بخش ۷.۴)
```

**علامت‌گذاری:** `[B]` = موجود · `[A→Kotlin]` = پورت از Go · `[NEW]` = باید نوشته شود · `★★` = مسیر بحرانی.

---

## بخش ۳ — کاتالوگ کامل ۴۱ پلاگین (شمارش دقیق)

### 3.1 پلاگین‌های پایه‌ی موجود (۲۲ — `HostPlugins.kt`، دست‌نخورده)

```
tcpconnect · dns · ipv4 · ipv6 · http · https · tls · certificate · redirect
header · server · compression · httpversion · securityheader · cookie
robots · sitemap · fingerprint · dnsmulti · banner · cdnwaf · tlsfingerprint
```

| ID | EvidenceClass پیش‌فرض | نقش در verdict |
|---|---|---|
| `tcpconnect` | — (gate) | پیش‌شرط؛ failure → host dead، بقیه skip |
| `dns` / `dnsmulti` / `ipv4` / `ipv6` | MODERATE | resolve + consistency خام |
| `http` / `https` / `httpversion` | WEAK–MODERATE | reachability لایه‌ی ۷ |
| `tls` / `certificate` / `tlsfingerprint` | STRONG | مواد خام برای snisan/fragment |
| `redirect` / `header` / `server` / `cookie` | WEAK | heuristic |
| `compression` / `securityheader` | WEAK | informational+weak |
| `robots` / `sitemap` / `banner` | WEAK | recon سبک |
| `fingerprint` / `cdnwaf` | MODERATE | CDN/WAF detection |

### 3.2 پلاگین‌های Bypass موجود (۹ — `BypassPlugins.kt`، دست‌نخورده)

```
snifronting · tlsfragment · payloadinjection · dohbypass
headerinjection · zerorated · snispoofing · misconfig · cveaudit
```

| ID | EvidenceClass | یادداشت |
|---|---|---|
| `tlsfragment` | DEFINITIVE | مقایسه‌ی split vs normal — طلای verdict |
| `snifronting` / `snispoofing` | STRONG | بدون SAN دقیق؛ با `snisan` کامل می‌شود |
| `dohbypass` | MODERATE–STRONG | به resolver در دسترس وابسته |
| `payloadinjection` / `headerinjection` | MODERATE | false-positive پذیر |
| `zerorated` | STRONG* | *فقط روی cellular profile معنادار (بخش ۱۷) |
| `misconfig` | MODERATE | |
| `cveaudit` | STRONG | وقتی نسخه/سرویس قطعی شناسایی شود |

### 3.3 پلاگین‌های جدید پیشرفته (۱۰ — اولویت مهندسی دقیق)

| # | ID | نام | لایه | EvidenceClass | اولویت | هزینه | وابستگی کلیدی |
|---|---|---|---|---|---|---|---|
| 1 | `plugin.host.dnsconsistency` | Cross-Resolver Consistency | DNS | STRONG | **P0** | ≈۰ | خروجی `MultiResolverDns` |
| 2 | `plugin.host.recordfragment` | Multi-Point TLS Record Fragmentation | TLS | DEFINITIVE | **P0** | کم | تعمیم `TlsFragmentationPlugin` |
| 3 | `plugin.host.snisan` | SAN-Aware SNI Exploitability | TLS | DEFINITIVE | **P0** | کم | پورت `evaluateExploitability`/`sanContains` از Go |
| 4 | `plugin.host.ech` | Encrypted Client Hello Probe | TLS | STRONG | P1 | متوسط | `DnsHttpsRecordQuery` type=65، API 29+ |
| 5 | `plugin.host.dnstransport` | DoT/DoQ Matrix | DNS | MODERATE | P1 | متوسط | گسترش `MultiResolverDns` |
| 6 | `plugin.host.ja3self` | Passive Client JA3/JA4 Reporter | FP | — | P1 | ≈۰ | بایت خام `FragmentingSocket` |
| 7 | `plugin.host.cdnedge` | Multi-Edge CDN Variance | Multi | MODERATE | P2 | **بالا** | multi-IP + اسکن موازی |
| 8 | `plugin.host.alpnmatrix` | ALPN Negotiation Matrix | TLS | WEAK | P2 | کم | TLS handshake چندباره |
| 9 | `plugin.host.quic` | QUIC/HTTP-3 Reachability | Transport | MODERATE | P1 | کم* | Cronet feature-flag |
| 10 | `plugin.host.timeconsistency` | Scheduled Re-verify | Temporal | — | P2 | متوسط | WorkManager + `HoleAgeEntity` |

> **قاعده‌ی رأی‌دهی (قطعی):** هر پلاگینی که در ستون EvidenceClass عدد/enum دارد، `PluginSignal`ش وارد log-odds بخش ۴ می‌شود.  
> **۸ رأی‌دهنده:** ۱،۲،۳،۴،۵،۷،۸،۹.  
> **۲ خارج از verdict:** `ja3self` (informational) و `timeconsistency` (متادیتای زمان‌بندی).

**حذف مهندسی‌شده:** پلاگین `middlebox` (TTL/window) — بدون root سیگنال قابل‌اتکا ندارد. نگه‌داشتن برای «کامل به‌نظر رسیدن» ضد انضباط این سند است.

### 3.4 ماتریس وابستگی و DAG اجرا (★★ بدون این، ۴۱ پلاگین thrash می‌کند)

```
                    ┌─────────────┐
                    │ tcpconnect  │  gate
                    └──────┬──────┘
           ┌───────────────┼───────────────┐
           ▼               ▼               ▼
         dns/dnsmulti    ipv4/ipv6      (skip all if dead)
           │
           ├─► dnsconsistency ─► dnstransport ─► dohbypass
           │
           ▼
    http / https / tls ──┬── certificate ── snisan
                         ├── tlsfragment ── recordfragment
                         ├── alpnmatrix
                         ├── ech (needs HTTPS DNS RR)
                         ├── snifronting / snispoofing
                         └── tlsfingerprint / ja3self
           │
           ▼
    header/server/cookie/redirect/compression/securityheader
           │
           ▼
    fingerprint / cdnwaf / banner / robots / sitemap
           │
           ▼
    cdnedge (optional, P2) · quic (optional) · cveaudit · misconfig
           │
           ▼
    zerorated  (only if NetworkProfile == CELLULAR)
           │
           ▼
    ★ ConfidenceEngineV3.compute(signals)
           │
           ▼
    HoleAge update · Checkpoint · EventBus.HostVerdict
```

**قواعد DAG:**
1. اگر `tcpconnect` = dead → هیچ پلاگین دیگری برای آن host اجرا نشود (به‌جز dns برای تشخیص NXDOMAIN جدا).
2. `snisan` بدون `certificate` (یا handshake معادل) ABSTAIN می‌دهد، نه REFUTES.
3. `zerorated` روی WiFi/VPN → اجباری ABSTAIN + log «profile mismatch».
4. `cdnedge` و `quic` پشت `ConsoleSettings` و `BudgetGuard` هستند؛ default off برای bulk CIDR.
5. `timeconsistency` هرگز در مسیر همگام fullscan نیست؛ فقط WorkManager.

### 3.5 بودجه‌ی هزینه per-host (`BudgetGuard`)

| پروفایل شبکه | max wall-time/host | max connections | max payload bytes | پلاگین‌های مجاز پیش‌فرض |
|---|---|---|---|---|
| `CELLULAR_METERED` | 8s | 6 | 256 KiB | P0 + پایه ضروری + zerorated |
| `WIFI_UNMETERED` | 20s | 16 | 1 MiB | P0+P1 + پایه |
| `WIFI_PLUS_VPN` | 15s | 10 | 512 KiB | مثل WiFi؛ quic opt-in |
| `CIDR_BULK` | 3s | 3 | 64 KiB | tcpconnect+dns+tlsfragment+snisan فقط |
| `DEEP_SINGLE` | 45s | 32 | 4 MiB | همه به‌جز timeconsistency |

تجاوز از بودجه → پلاگین‌های باقی‌مانده = `ABSTAIN` با reason `BUDGET_EXCEEDED` (نه fail، نه refute).

### 3.6 قرارداد اجباری `ScanPlugin` (هر پلاگین جدید باید پاس کند)

```kotlin
interface ScanPlugin {
    val id: String
    val displayName: String
    val evidenceClass: EvidenceClass?   // null = informational / non-voting
    val cost: PluginCost                // ESTIMATED_MS + ESTIMATED_BYTES
    val dependsOn: Set<String>          // plugin ids؛ DAG این را می‌خواند
    val requiredProfile: Set<NetworkProfile> // empty = all

    suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult
}

data class PluginResult(
    val pluginId: String,
    val signal: PluginSignal,           // همیشه؛ حتی روی error → ABSTAIN
    val summary: String,                // یک خط برای Console
    val details: Map<String, String> = emptyMap(),
    val rawExport: JsonObject? = null,  // برای schema بخش ۱۶
    val durationMs: Long
)

data class PluginCost(val estMs: Long, val estBytes: Long, val estConnections: Int = 1)

enum class NetworkProfile { CELLULAR_METERED, WIFI_UNMETERED, WIFI_PLUS_VPN, UNKNOWN }
```

**Invariantهای hard (contract test بخش ۸):**
- هرگز exception را از `scan()` بیرون نده — catch کن، `ABSTAIN` برگردان.
- به `ctx.scope` / `ensureActive()` احترام بگذار؛ cancel باید <100ms واکنش دهد.
- روی timeout شبکه → `ABSTAIN`، **هرگز** `REFUTES_BYPASS`.
- بدون side-effect سراسری (هیچ state استاتیک mutable بین hostها).

### 3.7 اسکلت پیاده‌سازی P0 (آماده‌ی کپی به ماژول)

#### 3.7.1 `DnsConsistencyPlugin`

```kotlin
class DnsConsistencyPlugin(
    private val multi: MultiResolverDns
) : ScanPlugin {
    override val id = "plugin.host.dnsconsistency"
    override val displayName = "Cross-Resolver Consistency"
    override val evidenceClass = EvidenceClass.STRONG
    override val cost = PluginCost(estMs = 200, estBytes = 2_048, estConnections = 0)
    override val dependsOn = setOf("dns", "dnsmulti")
    override val requiredProfile = emptySet<NetworkProfile>()

    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = SystemClock.elapsedRealtime()
        return try {
            val answers = multi.lookupAll(target.host) // Map<resolverId, List<InetAddress>>
            if (answers.isEmpty()) {
                return abstain(id, "no resolver answers", t0)
            }
            val sets = answers.values.map { it.map { a -> a.hostAddress }.toSet() }
            val intersection = sets.reduce { a, b -> a.intersect(b) }
            val union = sets.reduce { a, b -> a.union(b) }
            val divergent = union - intersection

            val signal = when {
                divergent.isNotEmpty() && intersection.isNotEmpty() ->
                    PluginSignal(id, SignalPolarity.SUPPORTS_BYPASS, EvidenceClass.STRONG)
                // واگرایی کامل بدون اشتراک می‌تواند split-horizon شدید یا poison باشد
                divergent.isNotEmpty() && intersection.isEmpty() ->
                    PluginSignal(id, SignalPolarity.SUPPORTS_BYPASS, EvidenceClass.STRONG)
                else ->
                    PluginSignal(id, SignalPolarity.REFUTES_BYPASS, EvidenceClass.MODERATE)
                    // consistency به‌تنهایی bypass را رد قطعی نمی‌کند → حداکثر MODERATE refute
            }
            PluginResult(
                pluginId = id,
                signal = signal,
                summary = "resolvers=${answers.size} divergent=${divergent.size}",
                details = mapOf(
                    "intersection" to intersection.joinToString(),
                    "divergent" to divergent.joinToString()
                ),
                durationMs = SystemClock.elapsedRealtime() - t0
            )
        } catch (c: CancellationException) {
            throw c
        } catch (e: Exception) {
            abstain(id, e.message ?: "error", t0)
        }
    }
}
```

#### 3.7.2 `RecordFragmentPlugin` (چند نقطه‌ی split)

```kotlin
class RecordFragmentPlugin(
    private val socketFactory: FragmentingSocket.Factory
) : ScanPlugin {
    override val id = "plugin.host.recordfragment"
    override val displayName = "Multi-Point TLS Record Fragmentation"
    override val evidenceClass = EvidenceClass.DEFINITIVE
    override val cost = PluginCost(estMs = 2_500, estBytes = 16_384, estConnections = 4)
    override val dependsOn = setOf("tcpconnect", "tls")
    override val requiredProfile = emptySet<NetworkProfile>()

    // نقاطی که از Go dpibypass و تجربه‌ی میدانی آمده‌اند — قابل تنظیم از ConsoleSettings
    private val splitPoints = intArrayOf(1, 2, 5, 10)

    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = SystemClock.elapsedRealtime()
        return try {
            val normalOk = ctx.tlsProbe(target, fragmentAt = null)
            val fragHits = splitPoints.map { sp -> sp to ctx.tlsProbe(target, fragmentAt = sp) }

            // DEFINITIVE support: نرمال بسته/مختل، حداقل یک fragment باز
            val anyFragOk = fragHits.any { it.second.success }
            val signal = when {
                !normalOk.success && anyFragOk ->
                    PluginSignal(id, SignalPolarity.SUPPORTS_BYPASS, EvidenceClass.DEFINITIVE)
                normalOk.success && anyFragOk ->
                    // هر دو کار می‌کنند → fragmentation لازم نیست؛ نه support قوی نه refute قطعی
                    PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.DEFINITIVE)
                normalOk.success && !anyFragOk ->
                    PluginSignal(id, SignalPolarity.REFUTES_BYPASS, EvidenceClass.STRONG)
                else ->
                    PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.DEFINITIVE)
            }
            PluginResult(
                pluginId = id,
                signal = signal,
                summary = "normal=${normalOk.success} frag=${fragHits.filter { it.second.success }.map { it.first }}",
                details = fragHits.associate { "split_${it.first}" to it.second.toShortString() },
                durationMs = SystemClock.elapsedRealtime() - t0
            )
        } catch (c: CancellationException) {
            throw c
        } catch (e: Exception) {
            abstain(id, e.message ?: "error", t0)
        }
    }
}
```

#### 3.7.3 `SniExploitabilityPlugin` (پورت دقیق SAN از Go)

```kotlin
class SniExploitabilityPlugin : ScanPlugin {
    override val id = "plugin.host.snisan"
    override val displayName = "SAN-Aware SNI Exploitability"
    override val evidenceClass = EvidenceClass.DEFINITIVE
    override val cost = PluginCost(estMs = 1_200, estBytes = 8_192, estConnections = 1)
    override val dependsOn = setOf("tls", "certificate")
    override val requiredProfile = emptySet<NetworkProfile>()

    override suspend fun scan(target: ScanTarget, ctx: ScanContext): PluginResult {
        val t0 = SystemClock.elapsedRealtime()
        return try {
            val cert = ctx.cachedCertificate(target)
                ?: return abstain(id, "no certificate in context", t0)

            val sans = cert.subjectAlternativeNamesOrEmpty()
            val cn = cert.subjectCNOrNull()
            val host = target.host

            // منطق هم‌ارز evaluateExploitability / sanContains از Go:
            // اگر SNI host داخل SAN/CN باشد، fronting روی این cert «جای دیگری» را نشان نمی‌دهد.
            val hostInCert = sanContains(sans, host) || cnEqualsOrWildcard(cn, host)
            val signal = if (!hostInCert && sans.isNotEmpty()) {
                // گواهی برای هویت دیگری‌ست → SNI spoof/fronting بالقوه قابل‌بهره‌برداری
                PluginSignal(id, SignalPolarity.SUPPORTS_BYPASS, EvidenceClass.DEFINITIVE)
            } else if (hostInCert) {
                PluginSignal(id, SignalPolarity.REFUTES_BYPASS, EvidenceClass.DEFINITIVE)
            } else {
                PluginSignal(id, SignalPolarity.ABSTAIN, EvidenceClass.DEFINITIVE)
            }

            PluginResult(
                pluginId = id,
                signal = signal,
                summary = if (!hostInCert) "SAN mismatch — exploitable candidate" else "SAN covers host",
                details = mapOf(
                    "cn" to (cn ?: ""),
                    "sans" to sans.joinToString(),
                    "host" to host
                ),
                durationMs = SystemClock.elapsedRealtime() - t0
            )
        } catch (c: CancellationException) {
            throw c
        } catch (e: Exception) {
            abstain(id, e.message ?: "error", t0)
        }
    }

    companion object {
        fun sanContains(sans: List<String>, host: String): Boolean =
            sans.any { pattern -> matchDnsName(pattern, host) }

        fun cnEqualsOrWildcard(cn: String?, host: String): Boolean =
            cn != null && matchDnsName(cn, host)

        /** تطابق DNS-name با پشتیبانی یک سطح wildcard سمت چپ (*.example.com). */
        fun matchDnsName(pattern: String, host: String): Boolean {
            val p = pattern.trim().lowercase()
            val h = host.trim().lowercase()
            if (p == h) return true
            if (!p.startsWith("*.")) return false
            val suffix = p.removePrefix("*") // ".example.com"
            if (!h.endsWith(suffix)) return false
            val left = h.removeSuffix(suffix)
            return left.isNotEmpty() && !left.contains('.') // فقط یک label
        }
    }
}
```

---

## بخش ۴ — بازطراحی کامل موتور امتیازدهی (`ConfidenceEngineV3`)

### 4.1 چرا مدل قبلی (جمع وزنی ساده) اشتباه بود

1. **Timeout با «رد شدن» یکسان شمرده می‌شد.** Timeout = عدم‌قطعیت، نه شواهد علیه bypass.
2. **جمع خطی اجازه می‌دهد شواهد ضعیف زیاد، شواهد قوی کم را رقیق کند.** ده heuristic نباید یک SAN mismatch قطعی را خنثی کند.

### 4.2 مدل جدید: سه‌حالته + Log-Odds + تقارن تأیید/رد

```kotlin
enum class SignalPolarity { SUPPORTS_BYPASS, REFUTES_BYPASS, ABSTAIN }

enum class EvidenceClass(val logOddsWeight: Double) {
    DEFINITIVE(3.0),   // tlsfragment compare، snisan
    STRONG(1.5),       // ech، dnsconsistency، zerorated@cellular
    MODERATE(0.7),     // cdnedge، header heuristics، dnstransport
    WEAK(0.3)          // compression، robots، sitemap، alpnmatrix
}

data class PluginSignal(
    val pluginId: String,
    val polarity: SignalPolarity,
    val evidenceClass: EvidenceClass,
    val reason: String? = null
)

enum class Verdict {
    CONFIRMED_CANDIDATE,
    CONFIRMED_NOT_VULNERABLE,
    WEAK_SIGNAL_ONLY
}

data class ConfidenceReport(
    val confidence: Double,                 // 0.05 .. 0.95
    val logOdds: Double,                    // خام، برای debug/diff
    val verdict: Verdict,
    val contributingSignals: List<PluginSignal>,
    val explanation: String                 // از EvidenceExplainer
)

object ConfidenceEngineV3 {

    fun compute(signals: List<PluginSignal>): ConfidenceReport {
        val logOdds = signals.sumOf { s ->
            when (s.polarity) {
                SignalPolarity.SUPPORTS_BYPASS -> +s.evidenceClass.logOddsWeight
                SignalPolarity.REFUTES_BYPASS  -> -s.evidenceClass.logOddsWeight
                SignalPolarity.ABSTAIN         -> 0.0
            }
        }

        val rawProbability = 1.0 / (1.0 + exp(-logOdds))
        // کف 0.05: نبودِ شواهد ≠ اثبات نبودِ حفره (اسکن تک‌نقطه‌ای)
        // سقف 0.95: حتی DEFINITIVE هم در دنیای واقعی 100% نیست
        val clamped = rawProbability.coerceIn(0.05, 0.95)

        fun decisive(polarity: SignalPolarity): Boolean {
            val def = signals.any {
                it.evidenceClass == EvidenceClass.DEFINITIVE && it.polarity == polarity
            }
            val strong = signals.count {
                it.evidenceClass == EvidenceClass.STRONG && it.polarity == polarity
            } >= 2
            return def || strong
        }

        val verdict = when {
            decisive(SignalPolarity.SUPPORTS_BYPASS) -> Verdict.CONFIRMED_CANDIDATE
            decisive(SignalPolarity.REFUTES_BYPASS)  -> Verdict.CONFIRMED_NOT_VULNERABLE
            else -> Verdict.WEAK_SIGNAL_ONLY
        }

        // اگر هر دو سمت decisive باشند (نادر، ولی ممکن در CDN چندلایه):
        // اولویت با DEFINITIVE جدیدتر از نظر evidenceClass وزن‌دار است؛ در تساوی → WEAK_SIGNAL_ONLY
        val bothSides = decisive(SignalPolarity.SUPPORTS_BYPASS) &&
            decisive(SignalPolarity.REFUTES_BYPASS)
        val finalVerdict = if (bothSides) resolveConflict(signals) else verdict

        val active = signals.filter { it.polarity != SignalPolarity.ABSTAIN }
        return ConfidenceReport(
            confidence = clamped,
            logOdds = logOdds,
            verdict = finalVerdict,
            contributingSignals = active,
            explanation = EvidenceExplainer.explain(finalVerdict, active, clamped)
        )
    }

    private fun resolveConflict(signals: List<PluginSignal>): Verdict {
        fun score(p: SignalPolarity) = signals
            .filter { it.polarity == p }
            .sumOf { it.evidenceClass.logOddsWeight }
        val s = score(SignalPolarity.SUPPORTS_BYPASS)
        val r = score(SignalPolarity.REFUTES_BYPASS)
        return when {
            s > r + 1.0 -> Verdict.CONFIRMED_CANDIDATE
            r > s + 1.0 -> Verdict.CONFIRMED_NOT_VULNERABLE
            else -> Verdict.WEAK_SIGNAL_ONLY
        }
    }
}

object EvidenceExplainer {
    fun explain(v: Verdict, signals: List<PluginSignal>, conf: Double): String {
        val top = signals
            .sortedByDescending { it.evidenceClass.logOddsWeight }
            .take(5)
            .joinToString { "${it.pluginId}:${it.polarity.name}/${it.evidenceClass.name}" }
        return "verdict=$v conf=${"%.2f".format(conf)} top=[$top]"
    }
}
```

### 4.3 جدول حقیقت (تست‌های اجباری pure-function)

| # | ورودی (خلاصه) | verdict انتظاری | conf تقریبی |
|---|---|---|---|
| T1 | ۱× DEFINITIVE SUPPORT | `CONFIRMED_CANDIDATE` | ~0.95 |
| T2 | ۱× DEFINITIVE REFUTE | `CONFIRMED_NOT_VULNERABLE` | ~0.05 |
| T3 | ۲× STRONG SUPPORT، بدون DEFINITIVE | `CONFIRMED_CANDIDATE` | ~0.82 |
| T4 | ۱× STRONG SUPPORT فقط | `WEAK_SIGNAL_ONLY` | ~0.82 |
| T5 | ۱۰× WEAK SUPPORT | `WEAK_SIGNAL_ONLY` | بالا ولی بدون برچسب قطعی |
| T6 | همه ABSTAIN | `WEAK_SIGNAL_ONLY` | 0.50 → clamp 0.05..0.95 → **0.50** |
| T7 | ۱ DEFINITIVE SUPPORT + ۱۰ WEAK REFUTE | `CONFIRMED_CANDIDATE` | DEFINITIVE غالب |
| T8 | ۱ DEFINITIVE SUPPORT + ۱ DEFINITIVE REFUTE | `resolveConflict` | معمولاً `WEAK_SIGNAL_ONLY` مگر اختلاف وزن >1 |
| T9 | timeoutها همه ABSTAIN + ۱ STRONG | `WEAK_SIGNAL_ONLY` | — |
| T10 | empty list | `WEAK_SIGNAL_ONLY` | 0.50 |

### 4.4 اتصال به `HoleAgeEntity`

| Verdict | اقدام HoleAge |
|---|---|
| `CONFIRMED_CANDIDATE` | `open` (یا تمدید `lastConfirmedAt`) |
| `CONFIRMED_NOT_VULNERABLE` | `closed` + `closedReason=DEFINITIVE_REFUTE` |
| `WEAK_SIGNAL_ONLY` | **بدون تغییر وضعیت**؛ فقط `lastSeenWeakAt` |

این تمایز دقیقاً همان دلیلی است که verdict سوم اضافه شد: بستن قطعی حفره ≠ «هنوز داده کافی نیست».

### 4.5 چرا این مدل دقیق‌تر است (نه فقط پیچیده‌تر)

- **قابل‌ردیابی:** `contributingSignals` + `explanation`.
- **مقاوم در برابر نویز:** WEAKها نمی‌توانند DEFINITIVE را بکشند.
- **صادق درباره‌ی عدم‌قطعیت:** کف/سقف متقارن.
- **متقارن تأیید/رد:** همان انضباط در هر دو جهت.
- **قابل‌دیف با Go:** `logOdds` خام در JSON export می‌آید.

---

## بخش ۵ — تنظیمات ادغام‌شده (`ConsoleSettings`)

```kotlin
data class ConsoleSettings(
    // —— موجود در B ——
    var concurrency: Int = 8,
    var timeoutMs: Long = 5_000,
    var retries: Int = 1,
    var freeScoreThreshold: Int = 70,

    // —— از Go Config ——
    var precheckTimeoutMs: Long = 800,
    var dedupByIp: Boolean = true,
    var adaptiveTimeout: Boolean = true,
    var postCheckMultiplier: Double = 1.5,
    var dnsRegion: String = "global",          // global | af | eu | us | custom
    var customDnsServers: List<String> = emptyList(),
    var sniSpoofCandidates: List<String> = emptyList(),
    var testFragmentBypass: Boolean = true,
    var testFingerprint: Boolean = false,

    // —— جدید Ω ——
    var testEch: Boolean = true,
    var testQuic: Boolean = false,             // opt-in: اتصال اضافه
    var testCdnEdge: Boolean = false,          // opt-in: گران
    var testAlpnMatrix: Boolean = false,
    var testDnsTransport: Boolean = true,
    var testJa3Self: Boolean = true,
    var recordFragmentSplits: List<Int> = listOf(1, 2, 5, 10),
    var budgetProfileOverride: String? = null, // null = auto from NetworkProfileDetector
    var checkpointEveryNHosts: Int = 25,
    var exportSchemaVersion: Int = 1,
    var redactionLevel: RedactionLevel = RedactionLevel.STANDARD,
    var updateCheckEnabled: Boolean = true,
    var selfTestOnFirstRun: Boolean = true
)

enum class RedactionLevel { NONE, STANDARD, STRICT }
```

**پایداری:** هر تغییر settings → `configHash = sha256(stableJson(settings))`.  
`CheckpointEntity` این هش را ذخیره می‌کند؛ resume با هش متفاوت → رفض + پیام «config drift».

---

## بخش ۶ — CLI زنده‌ی درون‌برنامه‌ای

### 6.1 معماری `core/cli/`

```kotlin
data class CliArgs(val raw: List<String>, val flags: Map<String, String>, val positionals: List<String>) {
    companion object {
        fun parse(tokens: List<String>): CliArgs { /* --key=value · --flag · positionals */ }
    }
}

data class CliOutputLine(
    val kind: Kind,
    val text: String,
    val ts: Long = System.currentTimeMillis()
) {
    enum class Kind { STDOUT, STDERR, PROGRESS, VERDICT, SYSTEM }
}

interface CliCommand {
    val name: String
    val aliases: List<String> get() = emptyList()
    val usage: String
    val help: String
    suspend fun run(args: CliArgs, session: CliSession): Flow<CliOutputLine>
}

class CliSession(
    val settings: ConsoleSettings,
    val scanId: String? = null,
    val workingDirLabel: String = "~"
)

class CliCommandRegistry(commands: List<CliCommand>) {
    private val map = commands.flatMap { c -> (listOf(c.name) + c.aliases).map { it to c } }.toMap()
    fun get(name: String) = map[name]
    fun all() = map.values.distinct()
}

class CliInterpreter(
    private val registry: CliCommandRegistry,
    private val eventBus: EventBus
) {
    suspend fun execute(raw: String, session: CliSession): Flow<CliOutputLine> = flow {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return@flow
        val tokens = tokenize(trimmed) // احترام به "quotes"
        val cmdName = tokens.first()
        val cmd = registry.get(cmdName)
        if (cmd == null) {
            emit(CliOutputLine(CliOutputLine.Kind.STDERR, "unknown command: $cmdName — try 'help'"))
            return@flow
        }
        val args = CliArgs.parse(tokens.drop(1))
        cmd.run(args, session).collect { line ->
            emit(line)
            eventBus.emit(ScanEvent.LogEmitted(line.kind.name, line.text, line.ts))
        }
    }
}
```

### 6.2 نگاشت دستور → Go → پلاگین

| دستور | معادل Go | پلاگین‌ها / اثر |
|---|---|---|
| `help [cmd]` | — | فهرست / usage |
| `hostscan <file\|host>` | `runHostScan()` | ۲۲ پایه |
| `cidr <range>` | `runCIDRScan()` | precheck + `AliasPrefixDeduper` + subset |
| `sni --target= --candidates=` | `runSNISpoofScan()` | `snifronting` + `snisan` |
| `fragment <host>` | dpibypass | `tlsfragment` + `recordfragment` |
| `fullscan <host\|file> [--confidence]` | `runFullFreeScan()` | DAG کامل + `ConfidenceEngineV3` |
| `reverify <scan-id>` | `runReverify()` | Room → همان hostها |
| `selftest` | `runSelfTest()` | `1.1.1.1` / `google.com` / control negative |
| `set <key>=<value>` | `EditSettings` | `ConsoleSettings` زنده |
| `get [key]` | — | نمایش settings |
| `export <scan-id> [--schema=1]` | — | JSON بخش ۱۶ |
| `diff <scanA> <scanB>` | — | `ScanDiffEngine` |
| `holes [--open\|--closed]` | holeage | گزارش `HoleAgeEntity` |
| `checkpoint list\|clear` | — | مدیریت checkpoint |
| `metrics` | — | خلاصه‌ی بخش ۱۵ |

### 6.3 صفحه‌ی Terminal (نمای بصری)

```
┌──────────────────────────────────────────────────────────┐
│  ● ● ●   mr-scanner Ω  ~  terminal            [CELL 4G]  │
├──────────────────────────────────────────────────────────┤
│ $ fullscan targets.txt --confidence                      │
│ [09:14:02] profile=CELLULAR_METERED budget=8s/host       │
│ [09:14:02] resolving 41 hosts...                         │
│ [09:14:03] ██████████░░░░░░  62%  25/41                  │
│ [09:14:04] ✓ 104.16.x.x  conf=0.87  CONFIRMED_CANDIDATE  │
│            └ DEFINITIVE×1 (recordfragment) STRONG×2      │
│ [09:14:04] ⚠ 172.67.x.x  conf=0.41  WEAK_SIGNAL_ONLY     │
│ [09:14:05] ✗ 198.51.x.x  conf=0.06  CONFIRMED_NOT_VULN   │
│            └ DEFINITIVE refute (snisan SAN covers host)  │
│ [09:14:06] checkpoint saved @25 hosts hash=a3f1…         │
│ ▊                                                        │
└──────────────────────────────────────────────────────────┘
```

### 6.4 UX ترمینال (الزامی)

- تاریخچه‌ی دستور (↑/↓) پایدار در `DataStore`.
- `Tab` تکمیل نام دستور و flag.
- لمس طولانی روی خط verdict → bottom sheet با `contributingSignals`.
- دکمه‌ی «Copy last verdict JSON».
- قطع با `Ctrl+C` معادل / دکمه‌ی Stop → cancel coroutine اسکن + checkpoint فوری.

---

## بخش ۷ — دقت، قدرت، سرعت

### 7.1 دقت

- `hasMinimumEvidence` / `hasDefinitiveRefutation` داخل خود موتور.
- Timeout = ABSTAIN.
- `zerorated` فقط روی cellular.
- Differential test با باینری Go (۱۱.۴).
- Schema پایدار برای مقایسهٔ ماشین‌خوان.

### 7.2 قدرت

- **۴۱ پلاگین دقیق** در یک APK.
- `ApkAnalyzer` — بدون رقیب در این کلاس ابزار موبایل.
- `WorkflowScreen` برای زنجیره‌سازی (alive filter → deep).
- CLI parity با Go برای قدرت‌کارها.
- Hole-age + checkpoint = حافظه‌ی بلندمدت عملیاتی.
- Evidence explanation = قابل دفاع در گزارش audit.

### 7.3 سرعت — با تصحیح QUIC

| گلوگاه | راه‌حل |
|---|---|
| اتصال جدا per پلاگین HTTP | `SharedOkHttpFactory` + connection pool |
| QUIC | **`cronet-transport-for-okhttp`** روی همان client؛ نه استک موازی |
| هاست مرده در CIDR | `quickReachabilityCheck` (TCP precheck کوتاه) |
| Concurrency ثابت روی موبایل | `AdaptiveConcurrencyController` + RTT روندی |
| IP تکراری | `AliasPrefixDeduper` (سقف alive rate ۰.۸۰ در /24) |
| DNS سریال | batch/parallel resolve، سقف جدا از `GlobalConnectionGate` |
| OOM | `ResourceManager` ← `Runtime.freeMemory()` + کاهش خودکار concurrency |
| پلاگین گران در bulk | `BudgetGuard` + DAG skip |

**معیار پذیرش سرعت (قابل اندازه‌گیری با `ScaleStressTest.kt`):**

| سناریو | سخت‌افزار مرجع | حد |
|---|---|---|
| `/24` precheck+P0 | گوشی mid-range 2020+، WiFi | **< 90s** |
| 50 host `fullscan` DEEP | همان | **< 120s** |
| resume بعد از kill در 50٪ | همان | **< 3s** تا ادامه |
| selftest | هر دستگاه | **< 15s** |

### 7.4 تم UI (تلطیف، نه بازنویسی)

- حفظ هویت بصری B.
- افزودن chipهای رنگی verdict: سبز `CANDIDATE` · خاکستری `WEAK` · قرمز تیره `NOT_VULN`.
- Terminal: فونت mono، پس‌زمینه‌ی تیره، کنتراست WCAG AA.
- کاهش motion در صورت `Settings.Global.ANIMATOR_DURATION_SCALE=0`.

### 7.5 وابستگی‌های Gradle کلیدی (نسخه‌ها قفل‌شدنی در gradle/libs.versions.toml)

```kotlin
// QUIC / HTTP3
implementation("com.google.net.cronet:cronet-okhttp:0.1.0")
implementation("org.chromium.net:cronet-embedded:119.6045.31") // نسخه‌ی embed همگام با تست

// Fingerprint
implementation("com.google.guava:guava:33.0.0-android") // murmur3

// CLI / JSON
implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.3")

// WorkManager برای timeconsistency
implementation("androidx.work:work-runtime-ktx:2.9.0")
```

> قبل از فاز ۴، یک spike یک‌روزه برای تأیید سازگاری `cronet-okhttp` با minSdk پروژه اجباری است؛ نتیجه‌ی spike = ADR.

---

## بخش ۸ — استراتژی تست

### 8.1 هرم تست

```
        ╱  E2E میدانی (SIM واقعی)  ╲         ← فاز ۶؛ دستی/نیمه‌خودکار
       ╱  Instrumentation + stub net ╲       ← MockWebServer + local TLS
      ╱  ScaleStressTest (دروازه PR)  ╲
     ╱  Contract tests per plugin      ╲
    ╱  Pure unit: ConfidenceEngineV3    ╲
   ╱  Diff-test vs Go binary (host list) ╲
```

### 8.2 Contract test برای هر `ScanPlugin`

هر پلاگین جدید (۱۰ تای بخش ۳.۳ + هر افزوده‌ی بعدی) باید:

1. cancel در حین scan → تکمیل با `CancellationException` یا نتیجه partial بدون نشت job.
2. exception داخلی → `PluginResult` با `ABSTAIN`، نه crash.
3. `id` یکتا در registry.
4. اگر `evidenceClass != null` → signal.evidenceClass با آن یکی باشد.
5. روی stub server خاموش → ABSTAIN در < timeoutMs + 500ms.

### 8.3 Stub servers (الگوی Go)

- TLS stub با SAN قابل تنظیم (برای snisan).
- HTTP stub با header/cdn جعلی.
- DNS stub (یا fake `MultiResolverDns`) برای consistency.
- **ممنوع در CI:** تماس به اینترنت واقعی.

### 8.4 `ScaleStressTest.kt` به‌عنوان merge gate

هر PR که scheduler/concurrency/BudgetGuard/SharedOkHttp را لمس کند باید این تست را سبز نگه دارد؛ شکست معیار ۹۰s = block merge.

### 8.5 تست‌های اجباری `ConfidenceEngineV3`

پیاده‌سازی جدول ۴.۳ به‌صورت `@ParameterizedTest` — pure، بدون Android framework.

### 8.6 Differential test (`tools/difftest/`)

```bash
#!/usr/bin/env bash
# tools/difftest/run.sh
set -euo pipefail
HOSTS=${1:-testdata/hosts.txt}
./mrscanner-go export-json -i "$HOSTS" -o /tmp/go.json
adb shell am broadcast -a com.mrscanner.omega.DIFFTEST --es hosts "$HOSTS"
adb pull /sdcard/Android/data/com.mrscanner.omega/files/diff-out.json /tmp/kt.json
python3 tools/difftest/compare.py /tmp/go.json /tmp/kt.json --fail-on-verdict-mismatch
```

خروجی compare: اختلاف resolve، اختلاف verdict، اختلاف مجموعه‌ی plugin pass — کد خروج ≠0 روی mismatch.

---

## بخش ۹ — About

| فیلد | مقدار |
|---|---|
| نام | Mr. Scanner Ω |
| Application ID فعلی | `com.aistudio.mrscanner.app` |
| Application ID هدف | `com.mrscanner.omega` |
| نسخه‌ی فعلی کد | v1.0.0 |
| نسخه‌ی معماری | Ω-2.0.0-FINAL |
| سازنده | Mr Ali |
| تلگرام شخصی | `t.me/Mr_Ali_2025` |
| کانال | `t.me/Ali_shortcuts` |
| ایمیل | `ali.hekmati2026@gmail.com` |
| شبکه‌ها | Facebook `AliShortcuts` · TikTok/IG/YT `ali_shortcuts` |
| اخطار داخل اپ | «Strictly for authorized security research, network audits, and code analysis.» |

**بعد از ادغام روی کارت App Specs:**
- `Engine: Confidence v3 (symmetric log-odds)`
- `Plugins: 41 (22 base + 9 bypass + 10 advanced)`
- `Transport: OkHttp + optional Cronet H3`

---

## بخش ۱۰ — گپ‌های صادقانه‌ی باقی‌مانده

| گپ | وضعیت | تخفیف |
|---|---|---|
| تست میدانی SIM/اپراتور واقعی | صفر تا فاز ۶ | selftest + lab stubs |
| Online Recon (subdomain, reverse-IP) | Deferred | خارج از دامنه Ω-2 |
| Google Play | بعید (ماهیت DPI/zero-rate) | GitHub sideload + UpdateChecker |
| JA3/JA4 *فعال* (جعل کلاینت) | عمداً خارج | فقط `ja3self` گزارش |
| `middlebox` سطح root | **حذف** | — |
| raw SYN / masscan-class pps | غیرممکن بدون root | بخش ۱۱.۱ |
| DoQ روی همه APIها | وابسته به Cronet/کتابخانه | fallback DoT/DoH |
| ECH کامل (نه فقط probe) | پیچیدگی stack TLS | probe کافی برای signal |

---

## بخش ۱۱ — از سند به برنامه: نقشه‌ی راه + Definition of Done

### 11.1 سقف واقعی (صادقانه)

ابزارهای nmap/masscan/zmap از **raw socket + SYN scan** می‌آیند → نیاز به root/CAP_NET_RAW.  
**روی اندروید غیر-روت در دسترس نیست.** هر ادعای pps هم‌رده‌ی masscan غیرواقعی است و باید در `docs/LIMITS.md` هم نوشته شود.

### 11.2 گلوگاه واقعی: I/O نه CPU

روی سلولار RTT = ۵۰–۳۰۰ms+. سربار JVM در برابر این عدد گم می‌شود.  
**اهرم واقعی = concurrency هوشمند + کاهش round-trip per host + budget.**  
هدف: **کارآمدترین ابزار کلاس موبایل غیر-روت** — نه nmap موبایل.

### 11.3 فازها با Definition of Done

| فاز | هدف | DoD (همه باید ✅) |
|---|---|---|
| **۰ آماده‌سازی** | خروج از اسکلت AI-Studio | CI سبز · `applicationId` جدید · signing از debug جدا · `docs/LIMITS.md` · git tag `omega-baseline` |
| **۱ P0** | `dnsconsistency` · `recordfragment` · `snisan` · `ConfidenceEngineV3` | unit جدول ۴.۳ سبز · contract test سه پلاگین · diff-test روی ≥۲۰ host با Go بدون mismatch verdict روی control set |
| **۲ داده** | Checkpoint · HoleAge · AliasPrefixDeduper | kill app در 50٪ CIDR → resume کامل · hole close فقط روی `CONFIRMED_NOT_VULNERABLE` |
| **۳ CLI** | `core/cli` + Terminal UI | تمام دستورهای ۶.۲ · parity خروجی fullscan با دکمه‌ی UI |
| **۴ P1** | ech · dnstransport · ja3self · quic(Cronet) | هرکدام flag جدا · spike ADR برای Cronet · بدون افت >10٪ روی معیار /24 وقتی flagها off |
| **۵ سرعت** | pool · adaptive · ResourceManager · BudgetGuard | `/24` < 90s · بدون OOM روی 2GB RAM device |
| **۶ میدان + انتشار** | SIM واقعی · Release pipeline · UpdateChecker | حداقل ۲ اپراتور · سه APK در GitHub Release · update prompt روی About |

### 11.4 Differential Testing (قوی‌ترین ابزار اعتبارسنجی)

دو پیاده‌سازی مستقل از منطق تقریباً یکسان = فرصت نادر.  
بعد از فاز ۱ و ۴ اجباری؛ بعد از هر باگ پورت ترجیحی.

### 11.5 چک‌لیست release-engineering

- [ ] حذف `signingConfig = debugConfig` از release
- [ ] keystore واقعی فقط در GitHub Secrets / local `keystore.properties` (gitignored)
- [ ] `GEMINI_API_KEY` / `.env` خارج از APK و خارج از repo عمومی
- [ ] rename `namespace` + `applicationId` → `com.mrscanner.omega`
- [ ] ProGuard/R8 keep rules برای Cronet + serialization
- [ ] `versionCode` یکنواخت صعودی · `versionName` semver
- [ ] SBOM ساده (`./gradlew cyclonedxBom` یا معادل) ضمیمه‌ی release
- [ ] مسیر update-check (۱۲.۴) فعال در release، قابل خاموش‌شدن در settings
- [ ] `READ_PHONE_STATE` فقط اگر کد واقعاً نیاز دارد — پیش‌فرض: **حذف** (۱۲.۵)

---

## بخش ۱۲ — بسته‌بندی APK چندمعماری و انتشار گیت‌هاب

### 12.1 ABI یعنی چه برای این پروژه

بایت‌کد Kotlin ABI-independent است. وابستگی ABI از **`.so`های transitive** می‌آید:
- Room/SQLite
- **Cronet** (حجم native بزرگ per-ABI)
- هر crypto native بعدی

پس ABI split از حالا مفید و بعد از Cronet **ضروری** است.

### 12.2 `build.gradle.kts`

```kotlin
android {
    namespace = "com.mrscanner.omega"
    defaultConfig {
        applicationId = "com.mrscanner.omega"
        minSdk = 26
        targetSdk = 34
        versionCode = 200
        versionName = "2.0.0-omega"
        ndk {
            abiFilters += listOf("armeabi-v7a", "arm64-v8a")
        }
    }
    splits {
        abi {
            isEnable = true
            reset()
            include("armeabi-v7a", "arm64-v8a")
            isUniversalApk = true
        }
    }
    signingConfigs {
        create("release") {
            storeFile = file(System.getenv("KEYSTORE_PATH") ?: "release.jks")
            storePassword = System.getenv("KEYSTORE_PASSWORD")
            keyAlias = System.getenv("KEY_ALIAS")
            keyPassword = System.getenv("KEY_PASSWORD")
        }
    }
    buildTypes {
        getByName("release") {
            signingConfig = signingConfigs.getByName("release")
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
}
```

| خروجی | مخاطب |
|---|---|
| `app-universal-release.apk` | پیش‌فرض اکثر کاربران |
| `app-arm64-v8a-release.apk` | گوشی‌های جدید، حجم کمتر |
| `app-armeabi-v7a-release.apk` | گوشی‌های قدیمی ۳۲-بیتی — **حذف نشود** |

`.aab` برای GitHub معنی ندارد؛ فقط APK.

### 12.3 GitHub Actions `release.yml`

```yaml
name: release
on:
  push:
    tags: ['v*']
permissions:
  contents: write
jobs:
  build-and-release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-java@v4
        with:
          distribution: temurin
          java-version: '17'
          cache: gradle
      - name: Decode keystore
        run: echo "${{ secrets.RELEASE_KEYSTORE_BASE64 }}" | base64 -d > release.jks
      - name: Assemble release
        run: ./gradlew assembleRelease --stacktrace
        env:
          KEYSTORE_PATH: release.jks
          KEYSTORE_PASSWORD: ${{ secrets.KEYSTORE_PASSWORD }}
          KEY_ALIAS: ${{ secrets.KEY_ALIAS }}
          KEY_PASSWORD: ${{ secrets.KEY_PASSWORD }}
      - name: Checksums
        run: |
          cd app/build/outputs/apk/release
          sha256sum *.apk > SHA256SUMS.txt
      - uses: softprops/action-gh-release@v2
        with:
          generate_release_notes: true
          files: |
            app/build/outputs/apk/release/app-universal-release.apk
            app/build/outputs/apk/release/app-arm64-v8a-release.apk
            app/build/outputs/apk/release/app-armeabi-v7a-release.apk
            app/build/outputs/apk/release/SHA256SUMS.txt
```

### 12.4 `UpdateChecker`

```kotlin
class UpdateChecker(
    private val client: OkHttpClient,
    private val repo: String, // "owner/mr-scanner-omega"
    private val currentVersionName: String
) {
    suspend fun check(): UpdateInfo? = withContext(Dispatchers.IO) {
        val req = Request.Builder()
            .url("https://api.github.com/repos/$repo/releases/latest")
            .header("Accept", "application/vnd.github+json")
            .build()
        client.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) return@withContext null
            val body = resp.body?.string() ?: return@withContext null
            // parse tag_name + assets[].browser_download_url / name
            // compare semver(tag) > semver(currentVersionName)
            // prefer universal asset؛ وگرنه ABI-matched
            ...
        }
    }
}
```

فراخوانی: AboutScreen onResume (با cache 24h) یا WorkManager هفتگی. هرگز force-update بدون تایید کاربر.

### 12.5 Permissions

| Permission | کاربرد | سطح |
|---|---|---|
| `INTERNET` | HTTP/TLS/DNS | normal |
| `ACCESS_NETWORK_STATE` | نوع شبکه، BudgetGuard، Adaptive | normal |
| `ACCESS_WIFI_STATE` | تفکیک WiFi/Cell | normal |
| `FOREGROUND_SERVICE` + `FOREGROUND_SERVICE_DATA_SYNC` | اسکن بلند | normal/special |
| `POST_NOTIFICATIONS` (API 33+) | نوتیف پیشرفت/پایان | dangerous runtime |
| `REQUEST_INSTALL_PACKAGES` | فقط اگر update با نصب درون‌برنامه | optional — ترجیح: مرورگر/PackageInstaller با نیت کاربر |
| ~~`READ_PHONE_STATE`~~ | **پیش‌فرض حذف** | `getSimOperator*()` / `getNetworkOperator*()` بدون این permission کار می‌کنند. فقط اگر کد IMSI/IMEI بخواند مستند و اضافه کن. |

**قبل از فاز ۰:** پیاده‌سازی `SimOperatorDetector` را audit کن. اگر فقط operator name/code است → ADR «why no READ_PHONE_STATE».

### 12.6 Foreground Service و بقای اسکن

- اسکن > 30s → FGS با نوتیف پیشرفت قطعی.
- `stopWithTask=false` برای ادامه بعد از swipe-away (با تنظیم کاربر).
- روی `onTaskRemoved` → checkpoint فوری.
- Doze: `setForeground` + عدم اتکا به alarm دقیق برای اسکن تعاملی؛ WorkManager فقط برای `timeconsistency`.

---

## بخش ۱۳ — اختیار توسعه‌ی آینده (انسان و AI)

> **این معماری نقشه‌ی شروع است، نه زندان.** مالک (Ali) به هر توسعه‌دهنده‌ی آینده — انسان یا دستیار AI — اختیار می‌دهد:
> 1. از جزئیات سند عدول کند اگر راه‌حل بهتری در پیاده‌سازی پیدا شد؛
> 2. قابلیت فراتر اضافه کند؛
> 3. بخش‌هایی که در عمل غلط درآمدند را کنار بگذارد (مثل حذف `middlebox`).

**تنها قید:** تغییر معماری بزرگ‌تر از local tweak → **ADR** در:

```
docs/decisions/NNNN-title.md
```

قالب ADR:

```markdown
# NNNN — عنوان
Date: YYYY-MM-DD
Status: Accepted | Superseded by NNNN

## Decision
چه تصمیمی گرفته شد.

## Context
چرا لازم شد.

## Consequences
چه چیزی بهتر/بدتر می‌شود.

## Alternatives rejected
چه گزینه‌هایی کنار گذاشته شد و چرا.
```

بدون این قید، سند طی چند ماه به تاریخچه‌ی بی‌ربط تبدیل می‌شود.

---

## بخش ۱۴ — امنیت اپ، تهدیدمدل، ضدسوءاستفاده (★ جدید Ω-2)

### 14.1 تهدیدمدل خلاصه

| تهدید | شدت | مقابله |
|---|---|---|
| سوءاستفاده از اپ برای اسکن غیرمجاز گسترده | بالا | اخطار صریح · rate limit محلی · بدون cloud botnet |
| نشت نتایج حساس از export/share | بالا | `ExportRedactor` + `RedactionLevel` |
| تزریق settings از backup/intent | متوسط | validate ranges · ignore unknown keys |
| دستکاری APK / repack | متوسط | `ApkIntegrityChecker` (signature pin optional) |
| کاربر rootشده + hook | متوسط | تشخیص و هشدار؛ نه kill اجباری (false positive) |
| MITM روی UpdateChecker | بالا | HTTPS only · (ترجیح) تأیید checksum با SHA256SUMS امضاشده |
| کلید امضا در repo | بحرانی | Secrets only · چرخش اگر لو رفت |

### 14.2 `ExportRedactor`

- `STANDARD`: حذف IP خصوصی کاربر، IMSI/ICCID اگر جایی بود، path داخلی storage.
- `STRICT`: علاوه بر آن hash کردن hostnameها در export اشتراکی، نگه‌داشتن فقط verdict+conf.
- CLI `export` پیش‌فرض STANDARD؛ `--redact=none` فقط با تأیید دو مرحله‌ای در UI.

### 14.3 سیاست استفاده

متن ثابت در About + اولین اجرا (dialog غیرقابل‌رد تا checkbox):

> Strictly for authorized security research, network audits, and code analysis.  
> Unauthorized scanning of networks you do not own or have permission to test may be illegal.

---

## بخش ۱۵ — Observability و متریک محلی (★ جدید Ω-2)

هیچ telemetery ابری پیش‌فرض. همه محلی در Room:

```kotlin
data class PluginTiming(
    val pluginId: String,
    val host: String,
    val durationMs: Long,
    val polarity: String,
    val abstainReason: String?
)

data class ScanTiming(
    val scanId: String,
    val profile: String,
    val hostCount: Int,
    val wallMs: Long,
    val verdictCounts: Map<String, Int>,
    val budgetExceededCount: Int
)
```

دستور `metrics` و صفحه‌ی مخفی About → «Engine Stats»:
- p50/p95 مدت per plugin
- نرخ ABSTAIN به تفکیک reason (`TIMEOUT`, `BUDGET`, `PROFILE`, `ERROR`)
- نرخ resume موفق checkpoint

این اعداد خوراک تصمیم «کدام پلاگین P2 ارزش نگه‌داشتن دارد» هستند.

---

## بخش ۱۶ — قرارداد خروجی JSON پایدار (★ جدید Ω-2)

```json
{
  "schemaVersion": 1,
  "engine": "confidence-v3",
  "appVersion": "2.0.0-omega",
  "configHash": "a3f1…",
  "scanId": "uuid",
  "profile": "CELLULAR_METERED",
  "startedAt": "2026-08-23T10:00:00Z",
  "finishedAt": "2026-08-23T10:02:10Z",
  "hosts": [
    {
      "input": "example.com",
      "resolved": ["203.0.113.10"],
      "confidence": 0.87,
      "logOdds": 3.7,
      "verdict": "CONFIRMED_CANDIDATE",
      "explanation": "…",
      "signals": [
        {
          "pluginId": "plugin.host.recordfragment",
          "polarity": "SUPPORTS_BYPASS",
          "evidenceClass": "DEFINITIVE",
          "reason": "normal=false frag=[1,2]"
        }
      ]
    }
  ]
}
```

- `ResultJsonCodec` فقط از طریق schema version می‌نویسد/می‌خواند.
- `SchemaMigrator` برای v2+ آینده.
- Diff-test فقط روی فیلدهای پایدار (`verdict`, sorted `pluginId+polarity`) نه روی duration.

---

## بخش ۱۷ — حالت‌های عملیاتی شبکه (★ جدید Ω-2)

| Profile | تشخیص | رفتار |
|---|---|---|
| `CELLULAR_METERED` | `NetworkCapabilities.TRANSPORT_CELLULAR` + metered | بودجه‌ی سخت · `zerorated` فعال · concurrency پایین |
| `WIFI_UNMETERED` | WiFi + not metered | بودجه‌ی باز · P1 پیش‌فرض on |
| `WIFI_PLUS_VPN` | `TRANSPORT_VPN` | هشدار «نتایج ممکن است view از VPN باشد» · zerorated off |
| `UNKNOWN` | سایر | شبیه WiFi محافظه‌کار |

`NetworkProfileDetector` روی تغییر شبکه event می‌دهد؛ اسکن در حال اجرا budget را mid-flight سخت‌تر می‌کند (هرگز شل‌تر، برای جلوگیری از انفجار هزینه روی switch به cell).

---

## بخش ۱۸ — Room: schema موجودیت‌های جدید

### 18.1 `CheckpointEntity`

```kotlin
@Entity(tableName = "checkpoints")
data class CheckpointEntity(
    @PrimaryKey val scanId: String,
    val schemaVersion: Int,
    val configHash: String,
    val cursorIndex: Int,
    val totalHosts: Int,
    val completedHostsJson: String,   // یا جدول رابطه؛ JSON برای سادگی v1
    val createdAt: Long,
    val updatedAt: Long
)
```

### 18.2 `HoleAgeEntity`

```kotlin
@Entity(
    tableName = "hole_age",
    indices = [Index("host"), Index("status")]
)
data class HoleAgeEntity(
    @PrimaryKey val holeId: String,   // hash(host+technique)
    val host: String,
    val technique: String,
    val status: String,               // open | closed
    val firstSeenAt: Long,
    val lastConfirmedAt: Long,
    val closedAt: Long?,
    val closedReason: String?,
    val lastConfidence: Double,
    val lastVerdict: String,
    val lastSeenWeakAt: Long?
)
```

### 18.3 `HostFingerprintEntity`

```kotlin
@Entity(tableName = "host_fingerprints")
data class HostFingerprintEntity(
    @PrimaryKey val host: String,
    val faviconHash: String?,
    val jarmLite: String?,
    val ja3Self: String?,
    val techTagsJson: String?,
    val updatedAt: Long
)
```

**Migration:** از نسخه DB فعلی B → `+1` با `Migration` صریح؛ بدون `fallbackToDestructiveMigration` در release.

---

## بخش ۱۹ — EventBus: رویدادهای جدید

```kotlin
sealed class ScanEvent {
    data class LogEmitted(val level: String, val message: String, val ts: Long) : ScanEvent()
    data class Progress(val done: Int, val total: Int, val host: String?) : ScanEvent()
    data class HostVerdict(
        val host: String,
        val report: ConfidenceReport
    ) : ScanEvent()
    data class CheckpointSaved(val scanId: String, val cursor: Int) : ScanEvent()
    data class HoleClosed(val holeId: String, val host: String, val reason: String) : ScanEvent()
    data class BudgetExceeded(val host: String, val skippedPlugins: List<String>) : ScanEvent()
    data class ProfileChanged(val profile: NetworkProfile) : ScanEvent()
    data class ScanFinished(val scanId: String, val timing: ScanTiming) : ScanEvent()
}
```

UI و CLI هر دو فقط از EventBus تغذیه می‌شوند — **یک مسیر حقیقت برای log**.

---

## بخش ۲۰ — خودآزمایی (`selftest`) سخت‌گیرانه

| مرحله | هدف | انتظار |
|---|---|---|
| 1 | DNS به `1.1.1.1` / resolver | success |
| 2 | TLS به `google.com` | certificate valid، snisan REFUTE (SAN covers) |
| 3 | host مرده‌ی جعلی `0.0.0.0` یا `.invalid` | tcpconnect dead، بدون crash |
| 4 | ConfidenceEngineV3 T1/T2 از جدول ۴.۳ روی fixture | pass |
| 5 | نوشتن/خواندن checkpoint موقت | round-trip ok |
| 6 | (اختیاری) Cronet H3 اگر `testQuic` | soft-fail فقط warning |

خروجی selftest = گزارش سبز/قرمز در Terminal و About؛ در first-run اگر قرمز → هشدار «شبکه/دستگاه آماده‌ی اسکن عمیق نیست».

---

## بخش ۲۱ — مستندات همراه در repo (حداقل)

```
docs/
  LIMITS.md                 ← سقف raw socket / pps
  ARCHITECTURE.md           ← لینک/کپی خلاصه به این سند
  PLUGIN_CATALOG.md         ← جدول ۴۱ تایی ماشین‌خوان (اختیاری generate)
  decisions/                ← ADRها
  thrift/ یا schemas/
    result-v1.schema.json   ← JSON Schema بخش ۱۶
tools/
  difftest/
    run.sh
    compare.py
```

این فایل master می‌تواند در `docs/omega-master.md` هم mirror شود.

---

## پیوست A — فهرست فایل‌های جدید (checklist ساخت)

```
core/intelligence/ConfidenceEngineV3.kt
core/intelligence/EvidenceExplainer.kt
core/scheduler/PluginDagExecutor.kt
core/scheduler/AliasPrefixDeduper.kt
core/scheduler/BudgetGuard.kt
core/network/DnsHttpsRecordQuery.kt
core/network/SharedOkHttpFactory.kt
core/network/QuicFeature.kt
core/network/NetworkProfileDetector.kt
core/fingerprint/FaviconHasher.kt
core/fingerprint/JarmLite.kt
core/fingerprint/TechDetector.kt
core/fingerprint/Ja3SelfReporter.kt
core/db/entities/CheckpointEntity.kt
core/db/entities/HoleAgeEntity.kt
core/db/entities/HostFingerprintEntity.kt
core/db/dao/CheckpointDao.kt
core/db/dao/HoleAgeDao.kt
core/db/dao/HostFingerprintDao.kt
core/security/ExportRedactor.kt
core/security/ApkIntegrityChecker.kt
core/update/UpdateChecker.kt
core/metrics/LocalMetricsStore.kt
core/export/ResultJsonCodec.kt
core/cli/* (interpreter, registry, commands/*)
features/hostscan/plugins/AdvancedPlugins.kt
features/hostscan/plugins/SniExploitabilityPlugin.kt
features/terminal/TerminalScreen.kt
features/terminal/TerminalViewModel.kt
di/OmegaModules.kt
.github/workflows/release.yml
docs/LIMITS.md
docs/decisions/.gitkeep
docs/schemas/result-v1.schema.json
tools/difftest/run.sh
tools/difftest/compare.py
```

---

## پیوست B — ترتیب پیاده‌سازی پیشنهادی داخل فاز ۱ (روزبه‌روز)

| روز | کار |
|---|---|
| 1 | `PluginSignal` types + `ConfidenceEngineV3` + تست‌های جدول ۴.۳ |
| 2 | `SniExploitabilityPlugin` + stub TLS با SAN | 
| 3 | `RecordFragmentPlugin` تعمیم split points + تست |
| 4 | `DnsConsistencyPlugin` روی `MultiResolverDns` |
| 5 | سیم‌کشی DAG حداقل برای P0 + خروجی Console با verdict |
| 6 | Diff-test اولیه با Go روی control hosts |
| 7 | باگ‌فیکس + ADR اگر انحرافی پیش آمد |

---

## پیوست C — واژه‌نامه

| واژه | معنی |
|---|---|
| SUPPORTS_BYPASS | شواهد به نفع قابل‌بهره‌برداری بودن/دورزدن |
| REFUTES_BYPASS | شواهد علیه |
| ABSTAIN | عدم‌قطعیت؛ بی‌اثر روی log-odds |
| DEFINITIVE | مشاهده‌ی مستقیم practically conclusive |
| Hole | میزبان/تکنیکی که قبلاً candidate بوده |
| configHash | اثر انگشت settings برای صحت resume |
| DAG | گراف وابستگی اجرای پلاگین |
| Control set | لیست host با نتیجه‌ی از پیش دانسته برای diff-test |

---

## پیوست D — معیار «تمام‌شدن سند» (خود این فایل)

- [x] شمارش پلاگین صحیح و سازگار (۴۱)
- [x] موتور امتیازدهی متقارن + کد کامل + جدول حقیقت
- [x] QUIC = Cronet نه netty incubator
- [x] DAG + بودجه + پروفایل شبکه
- [x] CLI با مجموعه دستور کامل
- [x] Room entities جدید
- [x] Permissions + signing کامل (alias/password)
- [x] CI release
- [x] UpdateChecker
- [x] امنیت/redaction
- [x] متریک محلی
- [x] JSON schema version
- [x] نقشه‌ی راه با DoD
- [x] فهرست فایل‌ها
- [x] اختیار + ADR
- [x] گپ‌های صادقانه بدون وعده‌ی خام socket

---

## جمع‌بندی اجرایی (یک پاراگراف)

Mr Scanner Ω بدنه‌ی بالغ Android/Kotlin را نگه می‌دارد، منطق تصمیم Go را به‌صورت پلاگین و `ConfidenceEngineV3` (log-odds متقارن) داخل آن می‌کارد، ۴۱ پلاگین را با DAG و بودجه‌ی آگاه‌از-شبکه اجرا می‌کند، با checkpoint/hole-age حافظه‌ی عملیاتی می‌سازد، CLI درون‌برنامه‌ای هم‌تراز Go می‌دهد، و با diff-test دو موتور، contract test، و معیارهای زمانی قابل‌اندازه‌گیری به یک APK چند-ABI امضاشده روی GitHub می‌رسد — بدون ادعای دروغین pps کلاس masscan، و با اختیار تکامل از طریق ADR.

---

*این سند جایگزین کامل تمام نسخه‌های قبلی است و مرجع واحد پروژه است.*  
*نسخه: Ω-2.0.0-FINAL · 2026-08-23 · Canonical · Implementation-Ready*
