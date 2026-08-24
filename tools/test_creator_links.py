#!/usr/bin/env python3
"""Validate Creator/Support URLs are exact and consistent across app + README."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    "email": "mailto:Ali.hekmati2026@gmail.com",
    "telegram": "https://t.me/Mr_Ali_2025",
    "channel": "https://t.me/Ali_shortcuts",
    "facebook": "https://www.facebook.com/AliShortcuts",
    "tiktok": "https://www.tiktok.com/@ali_shortcuts",
    "instagram": "https://www.instagram.com/ali_shortcuts",
    "youtube": "https://www.youtube.com/@Ali_Shortcuts",
}

def parse_strings(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    out = {}
    for key in EXPECTED:
        m = re.search(rf'name="url_{key}">([^<]+)</string>', text)
        if not m:
            raise AssertionError(f"missing url_{key} in strings.xml")
        out[key] = m.group(1).strip()
    return out

def main() -> int:
    strings = ROOT / "app/src/main/res/values/strings.xml"
    readme = ROOT / "README.md"
    about = ROOT / "app/src/main/res/layout/fragment_about.xml"
    main_kt = ROOT / "app/src/main/java/com/mrscanner/omega/MainActivity.kt"
    icons = [
        "ic_brand_email", "ic_brand_telegram", "ic_brand_channel",
        "ic_brand_facebook", "ic_brand_tiktok", "ic_brand_instagram", "ic_brand_youtube",
    ]

    fails = []
    app_urls = parse_strings(strings)
    for k, exp in EXPECTED.items():
        got = app_urls[k]
        if got != exp:
            fails.append(f"strings.xml url_{k}: got {got!r} != {exp!r}")
        else:
            print(f"OK strings {k}: {got}")

    rd = readme.read_text(encoding="utf-8")
    if "## Creator / Support" not in rd:
        fails.append("README missing ## Creator / Support")
    if "Powered by Mr Ali" not in rd:
        fails.append("README missing Powered by Mr Ali")
    bio = "Created and developed by Mr Ali, an independent developer building practical digital tools"
    if bio not in rd:
        fails.append("README missing creator bio")
    # README must contain each exact URL (email as mailto link target)
    checks = [
        ("mailto:Ali.hekmati2026@gmail.com", "email"),
        ("https://t.me/Mr_Ali_2025", "telegram"),
        ("https://t.me/Ali_shortcuts", "channel"),
        ("https://www.facebook.com/AliShortcuts", "facebook"),
        ("https://www.tiktok.com/@ali_shortcuts", "tiktok"),
        ("https://www.instagram.com/ali_shortcuts", "instagram"),
        ("https://www.youtube.com/@Ali_Shortcuts", "youtube"),
    ]
    for url, name in checks:
        if url not in rd:
            fails.append(f"README missing exact URL for {name}: {url}")
        else:
            print(f"OK readme {name}")

    ab = about.read_text(encoding="utf-8")
    for lid in ["linkEmail", "linkTelegram", "linkChannel", "linkFacebook", "linkTiktok", "linkInstagram", "linkYoutube"]:
        if f'@+id/{lid}' not in ab:
            fails.append(f"about layout missing {lid}")
        else:
            print(f"OK layout {lid}")
    if "powered_by" not in ab or "creator_bio" not in ab:
        fails.append("about layout missing powered_by/creator_bio")

    kt = main_kt.read_text(encoding="utf-8")
    for key in ["url_email", "url_telegram", "url_channel", "url_facebook", "url_tiktok", "url_instagram", "url_youtube"]:
        if key not in kt:
            fails.append(f"MainActivity missing bind for {key}")
        else:
            print(f"OK bind {key}")
    if "cell.setOnClickListener" not in kt:
        fails.append("MainActivity cell not clickable")
    if "ACTION_SENDTO" not in kt and "mailto" not in kt:
        print("WARN: mailto handling soft")

    for ic in icons:
        path = ROOT / f"app/src/main/res/drawable/{ic}.xml"
        if not path.exists():
            fails.append(f"missing icon {ic}")
        else:
            print(f"OK icon {ic}")

    # No invented shortened host-only without scheme in strings
    bad = re.findall(r'name="url_[^"]+">(?!https?://|mailto:)([^<]+)', strings.read_text())
    if bad:
        fails.append(f"non-absolute urls in strings: {bad}")

    if fails:
        print("\nFAILED:")
        for f in fails:
            print(" -", f)
        return 1
    print("\nALL CREATOR/SUPPORT CHECKS PASSED")
    return 0

if __name__ == "__main__":
    sys.exit(main())
