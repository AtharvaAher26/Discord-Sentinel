"""Detection corpus tests - the false-positive / false-negative budget.

A moderation bot lives or dies on its false-positive rate. This suite
scores realistic BENIGN messages (must stay below the SUSPICIOUS band,
score < 30 at medium sensitivity) and realistic MALICIOUS messages
(must reach the band stated per case) through Layers 1-3 exactly as
the scanner composes them.

Run:  pip install -r requirements-dev.txt && pytest tests/ -q
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentinel import detection  # noqa: E402


class FakeIntel:
    """Feed stub: domains in `bad` are confirmed malicious; `resolved`
    maps shortener URLs to final destinations."""

    def __init__(self, bad=(), resolved=None):
        self.bad = set(bad)
        self.resolved = resolved or {}

    async def check(self, domain):
        if domain in self.bad:
            return True, "test_feed"
        return False, None

    async def resolve(self, url):
        return self.resolved.get(url)


class FakeAttachment:
    def __init__(self, filename):
        self.filename = filename


def score_message(text, attachments=(), age_days=400.0, intel=None,
                  mult=1.0):
    """Compose Layers 1-3 the way ScannerCog does."""
    intel = intel or FakeIntel()
    urls = detection.extract_urls(text)

    async def run():
        signals, flagged = await detection.analyze_domains(
            urls, intel, mult, set())
        signals += detection.analyze_markdown_links(text, mult)
        all_trusted = bool(urls) and not flagged
        signals += detection.analyze_content(
            text, list(attachments), age_days, mult,
            suppress_lures=all_trusted)
        return signals, flagged

    signals, flagged = asyncio.run(run())
    return min(100, sum(s.weight for s in signals)), signals, flagged


def names(signals):
    return {s.name for s in signals}


# =====================================================================
# BENIGN - every case must score < 30 (SAFE band)
# =====================================================================
BENIGN = [
    "hello everyone, game night at 8?",
    "watch this https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "my portfolio is at https://example.dev - feedback welcome",
    "trade link: https://steamcommunity.com/market/listings/730/AK-47",
    "join the event server https://discord.gg/abcd1234",
    "official site https://discord.com/download",
    "I love discord nitro, the animated emojis are great",
    "check my repo https://github.com/AtharvaAher26/Job-finder",
    "good writeup https://en.wikipedia.org/wiki/Phishing",
    "my landing page https://coolproject.xyz is live",          # .xyz alone = 12
    "docs for the sprint are in the pinned message",
    "steam summer sale is wild this year, grabbed two games",
    "we're giving a talk on phishing detection tomorrow, slides soon",
]


def test_benign_corpus_stays_safe():
    failures = []
    for text in BENIGN:
        score, signals, _ = score_message(text)
        if score >= 30:
            failures.append((text, score, names(signals)))
    assert not failures, f"false positives: {failures}"


def test_official_steam_link_not_a_lookalike():
    """v1.0 bug: steamcommunity.com scored +35 as its own lookalike."""
    _score, signals, flagged = score_message(
        "https://steamcommunity.com/id/someplayer")
    assert "lookalike_domain" not in names(signals)
    assert flagged == []


def test_nitro_talk_with_official_link_is_safe():
    """Lure suppression: promo talk pointing AT discord.com is fine."""
    score, _s, _f = score_message(
        "discord is giving free nitro trials, details https://discord.com")
    assert score < 30


# =====================================================================
# MALICIOUS - every case must reach its band
# =====================================================================
def test_leetspeak_lookalike_caught():
    """v1.0 CRITICAL bug: d1scord.com folded exactly to discord.com and
    was exempted as official. Must now reach MALICIOUS with lure text."""
    score, signals, _ = score_message(
        "FREE NITRO giveaway!! grab yours https://d1scord.com/claim")
    assert "lookalike_domain" in names(signals)
    assert score >= 70


def test_cyrillic_homograph_caught():
    cyrillic = "https://disc\u043erd.com/login"  # Cyrillic о
    score, signals, _ = score_message(
        f"free nitro here {cyrillic} - log in with your discord")
    assert "mixed_script_host" in names(signals)
    assert score >= 70


def test_feed_hit_alone_is_malicious():
    intel = FakeIntel(bad={"evil-phish-123.com"})
    score, signals, _ = score_message(
        "check this out https://evil-phish-123.com/landing", intel=intel)
    assert "feed_hit" in names(signals)
    assert score >= 70


def test_shortener_destination_is_scored():
    """v1.0 never resolved shorteners; the destination must be scored."""
    intel = FakeIntel(resolved={
        "https://bit.ly/3xYzAb": "https://d1scord.gift/claim"})
    score, signals, flagged = score_message(
        "free nitro https://bit.ly/3xYzAb", intel=intel)
    assert "shortener_resolved" in names(signals)
    assert "d1scord.gift" in flagged
    assert score >= 70


def test_hxxp_obfuscation_extracted():
    urls = detection.extract_urls("hxxp://d1scord.gift free nitro")
    assert any("d1scord.gift" in u for u in urls)
    score, _s, _f = score_message("hxxp://d1scord.gift free nitro")
    assert score >= 70


def test_bare_domain_extracted():
    """v1.0 defined BARE_DOMAIN_RE but never used it."""
    urls = detection.extract_urls("go to dlscord.gift now")
    assert any("dlscord.gift" in u for u in urls)


def test_bracket_dot_obfuscation():
    urls = detection.extract_urls("visit d1scord[.]gift for free nitro")
    assert any("d1scord.gift" in u for u in urls)


def test_ip_literal_with_lure():
    score, signals, _ = score_message(
        "free nitro at http://185.199.108.153/login")
    assert "ip_literal_host" in names(signals)
    assert score >= 50


def test_masked_markdown_link():
    score, signals, _ = score_message(
        "[https://discord.com](https://d1scord.gift/claim) free nitro")
    assert "masked_link_mismatch" in names(signals)
    assert score >= 70


def test_double_extension_attachment():
    score, signals, _ = score_message(
        "photo for you", attachments=[FakeAttachment("photo.png.exe")],
        age_days=2.0)
    assert "double_extension" in names(signals)
    assert score >= 30


def test_young_account_archive_flagged_old_account_not():
    young, signals_y, _ = score_message(
        "my modpack", attachments=[FakeAttachment("modpack.zip")],
        age_days=3.0)
    assert "young_account_archive" in names(signals_y)
    old, signals_o, _ = score_message(
        "my modpack", attachments=[FakeAttachment("modpack.zip")],
        age_days=900.0)
    assert "young_account_archive" not in names(signals_o)
    assert old < young


def test_subdomain_brand_bait():
    """discord.com.evil-host.net is NOT discord.com."""
    score, signals, flagged = score_message(
        "free nitro https://discord.com.evil-host.net/login")
    assert "evil-host.net" in flagged
    assert score >= 30


# =====================================================================
# Unit-level: fold / punycode / scripts
# =====================================================================
def test_fold_maps_confusables_not_deletes():
    assert detection.fold("disc\u043erd") == "discord"


def test_fold_leetspeak():
    assert detection.fold("d1sc0rd") == "discord"


def test_punycode_decode():
    # xn--discrd-t9a.com is a punycode label; decode must not crash and
    # must change the label
    out = detection.decode_punycode("xn--bcher-kva.example")
    assert "bücher" in out


def test_mixed_script_detection():
    assert detection.is_mixed_script("disc\u043erd.com")
    assert not detection.is_mixed_script("discord.com")
    assert not detection.is_mixed_script("example-domain.net")


def test_verdict_bands():
    from sentinel.enforcement import verdict_for
    assert verdict_for(0) == "SAFE"
    assert verdict_for(29) == "SAFE"
    assert verdict_for(30) == "SUSPICIOUS"
    assert verdict_for(69) == "SUSPICIOUS"
    assert verdict_for(70) == "MALICIOUS"
