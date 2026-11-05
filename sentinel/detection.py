"""Layers 2 and 3 - heuristic URL analysis and content pattern matching.

Layer 2: normalize URLs, extract the registrable domain, score lookalike
similarity against protected brands, weigh suspicious TLDs, RESOLVE link
shorteners and score the real destination.

Layer 3: lure-phrase regex families, risky/archive attachments, masked
markdown links.

CRITICAL INVARIANT (v1.1 fix): official-domain exemptions are ALWAYS
checked against the RAW registrable domain, never the folded one. The
v1.0 code folded first and exempted second, so 'd1scord.com' folded
exactly to 'discord.com' and skipped every check - total evasion by the
canonical lookalike. Folding is for similarity comparison only.

Every function returns Signal objects with a weight; nothing here can
alone declare MALICIOUS except a confirmed feed hit handled in the
scanner.
"""
import ipaddress
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import urlparse

# ---------------------------------------------------------------- brands
PROTECTED_BRANDS = [
    "discord", "discordapp", "discordgift", "discordnitro", "nitro",
    "steam", "steamcommunity", "steamchat",
]

# Raw registrable domains that are always exempt. Checked against the
# UNFOLDED domain (see module docstring).
OFFICIAL_DOMAINS = {
    "discord.com", "discord.gg", "discordapp.com", "discordstatus.com",
    "steamcommunity.com", "steampowered.com",
}

SUSPICIOUS_TLDS = {
    "gift", "xyz", "icu", "top", "tk", "cf", "ml", "ga", "gq", "buzz", "cfd",
}

DOMAIN_LURE_WORDS = {
    "nitro", "free", "gift", "giveaway", "claim", "airdrop", "premium",
}

LINK_SHORTENERS = {
    "bit.ly", "tinyurl.com", "shorturl.at", "rb.gy", "cutt.ly", "is.gd",
    "goo.gl", "t.co", "ow.ly", "buff.ly", "rebrand.ly", "tiny.cc",
    "short.gy", "clck.ru", "v.gd", "x.co", "s.id",
}

# Levenshtein similarity at or above this value against a protected brand,
# on a domain that is NOT the official one, is a strong lookalike signal.
SIMILARITY_THRESHOLD = 0.82

# leetspeak folding applied before similarity scoring
# ("1" -> "i" because d1scord is the canonical Discord lookalike)
FOLD_MAP = {
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
    "|": "l", "!": "i", "$": "s",
}

# Unicode confusables: Cyrillic/Greek letters that render identically to
# Latin ones. v1.0 DELETED these via ascii-ignore, corrupting the domain
# ('disc\u043erd.com' -> 'discrd.com'); v1.1 MAPS them to their Latin twins.
CONFUSABLES = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0445": "x", "\u0456": "i", "\u0455": "s",
    "\u0458": "j", "\u04bb": "h", "\u043a": "k", "\u043c": "m",
    "\u0442": "t", "\u0432": "b", "\u043d": "h", "\u0443": "y",
    "\u03b1": "a", "\u03bf": "o", "\u03c1": "p", "\u03c7": "x",
    "\u03b5": "e", "\u03b9": "i", "\u03ba": "k", "\u03bd": "v",
    "\u03c4": "t", "\u03bc": "u",
}

# public suffix approximations: registrable domain = last two labels,
# except these two-level suffixes -> last three labels.
TWO_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.nz",
    "com.br", "com.mx", "co.jp", "co.kr", "com.tr", "com.cn", "com.hk",
}

URL_RE = re.compile(
    r"(?:https?://|www\.)[^\s<>\[\]()\"']+", re.IGNORECASE
)
BARE_DOMAIN_RE = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+"
    r"(?:gift|xyz|icu|top|tk|cf|ml|ga|gq|com|net|org|info|io|me|cc|buzz|cfd|"
    r"link|site|online|shop|store))\b",
    re.IGNORECASE,
)
MD_LINK_RE = re.compile(r"\[([^\]]{1,120})\]\((https?://[^\s)]+)\)")

# ---------------------------------------------------------------- Layer 3
LURE_PATTERNS = [
    (re.compile(r"free\s+(discord\s+)?nitro", re.I), 30, "nitro_lure"),
    (re.compile(r"nitro\s+(giveaway|gift|for\s+free)", re.I), 30, "nitro_lure"),
    (re.compile(r"discord\s+(nitro\s+)?gift", re.I), 25, "nitro_lure"),
    (re.compile(r"(first|next)\s+\d{2,4}\s+(users|people|members)", re.I), 15,
     "urgency"),
    (re.compile(r"limited\s+(time|offer|spots|claim)", re.I), 12, "urgency"),
    (re.compile(r"claim\s+your\s+(nitro|reward|prize|gift)", re.I), 25,
     "nitro_lure"),
    (re.compile(r"steam\s+(gift|game)\s+for\s+free", re.I), 25, "steam_bait"),
    (re.compile(r"log\s?in\s+with\s+your\s+discord", re.I), 35,
     "fake_login"),
    (re.compile(r"verify\s+your\s+(discord|steam)\s+account", re.I), 30,
     "fake_login"),
    (re.compile(r"airdrop|double\s+your\s+(crypto|btc|eth)", re.I), 20,
     "crypto_bait"),
]

ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u2060\ufeff\u2061-\u2064]")

RISKY_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".msi", ".jar",
    ".vbs", ".ps1", ".py", ".sh", ".apk", ".ahk",
}
ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".iso",
}
DOUBLE_EXT_RE = re.compile(
    r"\.(jpg|jpeg|png|gif|pdf|txt|doc|mp4)\.(exe|scr|bat|cmd|com|pif|jar|vbs)$",
    re.IGNORECASE,
)


@dataclass
class Signal:
    """One weighted detection signal."""
    layer: int          # 1-4
    name: str           # machine name, e.g. "lookalike_domain"
    weight: int         # points contributed (already sensitivity-scaled)
    detail: str         # human-readable evidence for the mod-log


@dataclass
class ScanResult:
    signals: list[Signal] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)

    @property
    def score(self) -> int:
        return min(100, sum(s.weight for s in self.signals))


# ---------------------------------------------------------------- helpers
def levenshtein(a: str, b: str) -> int:
    """Classic DP edit distance (no third-party dependency)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1,
                           prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def similarity(a: str, b: str) -> float:
    m = max(len(a), len(b))
    if m == 0:
        return 1.0
    return 1.0 - levenshtein(a, b) / m


def fold(text: str) -> str:
    """Map confusables, NFKD-fold, strip zero-width chars, leetspeak-fold.

    Order matters: confusables are mapped BEFORE the ASCII strip, or
    Cyrillic/Greek lookalikes would be silently deleted (v1.0 bug).
    """
    text = "".join(CONFUSABLES.get(ch, ch) for ch in text)
    text = unicodedata.normalize("NFKD", text)
    text = text.encode("ascii", "ignore").decode("ascii")
    text = ZERO_WIDTH_RE.sub("", text).lower()
    return "".join(FOLD_MAP.get(ch, ch) for ch in text)


def _script_of(ch: str) -> str | None:
    if not ch.isalpha():
        return None
    name = unicodedata.name(ch, "")
    for script in ("LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "GEORGIAN"):
        if script in name:
            return script
    return "OTHER"


def is_mixed_script(host: str) -> bool:
    """True when a hostname mixes letters from 2+ scripts - the classic
    IDN homograph attack shape (e.g. Latin 'disc' + Cyrillic 'о')."""
    scripts = {s for s in (_script_of(c) for c in host) if s}
    return len(scripts) > 1


def decode_punycode(host: str) -> str:
    """Decode xn-- labels so IDN domains fold/compare correctly."""
    out = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                out.append(label.encode("ascii").decode("idna"))
                continue
            except (UnicodeError, ValueError):
                pass
        out.append(label)
    return ".".join(out)


def deobfuscate(text: str) -> str:
    """Undo the cheap obfuscations scammers type: hxxp, [.] , spaced dots."""
    t = re.sub(r"hxxps(?=://)", "https", text, flags=re.IGNORECASE)
    t = re.sub(r"hxxp(?=://)", "http", t, flags=re.IGNORECASE)
    t = t.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    t = re.sub(r"\[\s*dot\s*\]", ".", t, flags=re.IGNORECASE)
    t = re.sub(r"\s+\.\s+", ".", t)
    return t


def extract_urls(text: str) -> list[str]:
    """All URLs in a message: scheme URLs, www. URLs, and bare domains
    on scammable TLDs (v1.0 defined the bare-domain regex but never
    used it - 'dlscord.gift' typed plain was invisible)."""
    text = deobfuscate(text or "")
    urls = URL_RE.findall(text)
    out: list[str] = []
    seen: set[str] = set()
    for u in urls:
        u = u.rstrip(".,;:!?")
        full = u if u.lower().startswith("http") else "https://" + u
        if full.lower() not in seen:
            seen.add(full.lower())
            out.append(full)
    for m in BARE_DOMAIN_RE.findall(text):
        full = "https://" + m
        # skip bare domains already covered by a scheme URL
        if not any(m.lower() in u.lower() for u in out):
            if full.lower() not in seen:
                seen.add(full.lower())
                out.append(full)
    return out


def registrable_domain(host: str) -> str:
    """eTLD+1 with a small public-suffix approximation.

    discord.gift.evil-site.example -> evil-site.example (brand in a
    subdomain is NOT the official domain - the distinction Layer 2 exists
    to enforce).
    """
    host = host.lower().strip(".")
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in TWO_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return host


def host_of(raw: str) -> str:
    """Actual hostname (not folded) of a URL - used for logging/feed hits."""
    parsed = urlparse(raw if "://" in raw else "https://" + raw)
    host = parsed.netloc or parsed.path.split("/")[0]
    return host.split("@")[-1].split(":")[0].lower()


def raw_domain_of(raw_url: str) -> str:
    """Registrable domain as actually written (punycode-decoded, NOT
    leet/confusable folded). Exemptions and feed checks use this."""
    return registrable_domain(decode_punycode(host_of(raw_url)))


def folded_domain_of(raw_url: str) -> str:
    """Folded registrable domain - for similarity/lure comparison only."""
    return fold(raw_domain_of(raw_url))


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------- Layer 2
async def analyze_domains(urls: list[str], intel, mult: float,
                          allowlist: set[str],
                          network=None) -> tuple[list[Signal], list[str]]:
    """Score every URL's registrable domain.

    network: optional async callable domain -> (hits, guilds) | None
    backing the cross-server threat network (v1.2). A domain reported
    MALICIOUS across 2+ servers earns +40 before any public feed lists
    it; repeat reports in one server earn +25.

    Returns (signals, flagged_domains). flagged_domains contains only
    domains that were actually scored (official/allowlisted domains are
    exempt and absent) - the scanner uses an empty flagged list plus a
    non-empty URL list to mean 'all links trusted'.

    Shorteners are RESOLVED via intel.resolve() and the final
    destination is pushed back onto the worklist and scored like any
    other URL (v1.0 only added +5 and never saw the destination).
    """
    signals: list[Signal] = []
    flagged: list[str] = []
    seen_hosts: set[str] = set()
    worklist: list[str] = list(urls)
    resolutions = 0

    while worklist:
        url = worklist.pop(0)
        host = host_of(url)
        if not host or host in seen_hosts:
            continue
        seen_hosts.add(host)
        raw_dom = raw_domain_of(url)
        dom = fold(raw_dom)

        # -- exemptions: RAW domain only (module docstring) -------------
        if raw_dom in OFFICIAL_DOMAINS or raw_dom in allowlist \
                or dom in allowlist:
            continue
        if raw_dom not in flagged:
            flagged.append(raw_dom)

        # -- Layer 1 (absolute, not sensitivity-scaled) -----------------
        malicious, source = await intel.check(raw_dom)
        if malicious:
            signals.append(Signal(
                1, "feed_hit", 85, f"{raw_dom} confirmed by {source}"))
            continue

        # -- Sentinel network: peers saw it first (v1.2) ----------------
        if network is not None:
            hit = await network(raw_dom)
            if hit:
                hits, guilds = hit
                weight = 40 if guilds >= 2 else (25 if hits >= 3 else 0)
                if weight:
                    signals.append(Signal(
                        1, "network_flag", weight,
                        f"{raw_dom} reported malicious {hits}x across "
                        f"{guilds} server(s) in the Sentinel network"))

        # -- IP-literal hosts: no domain to reputation-check ------------
        if is_ip_literal(host):
            signals.append(Signal(
                2, "ip_literal_host", int(25 * mult),
                f"link points at bare IP {host} - no domain accountability"))
            continue

        # -- shorteners: resolve, then score the destination -----------
        if raw_dom in LINK_SHORTENERS:
            signals.append(Signal(
                2, "link_shortener", int(5 * mult),
                f"{raw_dom} hides the real destination"))
            if resolutions < 3 and hasattr(intel, "resolve"):
                resolutions += 1
                final = await intel.resolve(url)
                if final and host_of(final) != host:
                    signals.append(Signal(
                        2, "shortener_resolved", 0,
                        f"{raw_dom} resolves to {host_of(final)}"))
                    worklist.append(final)
            continue

        # -- Layer 2 heuristics (on the FOLDED domain) ------------------
        if is_mixed_script(host):
            signals.append(Signal(
                2, "mixed_script_host", int(20 * mult),
                f"{host} mixes letter scripts - IDN homograph shape"))

        match = _brand_similarity(dom)
        if match is not None:
            sim, brand = match
            signals.append(Signal(
                2, "lookalike_domain", int(35 * mult),
                f"{raw_dom} is {sim:.0%} similar to {brand} but is not "
                f"the official {brand} domain"))

        tld = raw_dom.rsplit(".", 1)[-1]
        if tld in SUSPICIOUS_TLDS:
            signals.append(Signal(
                2, "suspicious_tld", int(12 * mult),
                f".{tld} is heavily abused in lure campaigns"))

        for word in DOMAIN_LURE_WORDS:
            if word in dom:
                signals.append(Signal(
                    2, "lure_keyword_domain", int(15 * mult),
                    f"lure keyword '{word}' inside domain {raw_dom}"))
                break

    return signals, flagged


def _brand_similarity(dom: str):
    """Return (similarity, brand) for the best lookalike match, or None.

    Compares the FOLDED registrable domain against brand names. Exact
    official domains never reach here (raw-exempted by the caller).
    """
    best = None
    for brand in PROTECTED_BRANDS:
        sim = similarity(dom, brand)
        # 'discordgifts.xyz' vs 'discord' - prefix containment counts too
        if dom.startswith(brand) and len(dom) > len(brand) + 2:
            sim = max(sim, 0.9)
        if sim >= SIMILARITY_THRESHOLD and (best is None or sim > best[0]):
            best = (sim, brand)
    if best and dom != best[1]:
        return best
    return None


def analyze_markdown_links(text: str, mult: float) -> list[Signal]:
    """Masked-link check: [label](target) where the label LOOKS like an
    official/brand destination but the target goes somewhere else -
    Discord renders only the label, so this is pure deception."""
    signals: list[Signal] = []
    for label, target in MD_LINK_RE.findall(text or ""):
        label_clean = label.strip()
        label_folded = fold(label_clean)
        target_raw = raw_domain_of(target)
        if target_raw in OFFICIAL_DOMAINS:
            continue
        looks_official = any(
            od in label_folded for od in OFFICIAL_DOMAINS)
        label_is_url = bool(URL_RE.search(label_clean)) or \
            ("." in label_clean and " " not in label_clean)
        if looks_official or (label_is_url and
                              fold(raw_domain_of(label_clean)) != fold(target_raw)):
            signals.append(Signal(
                3, "masked_link_mismatch", int(35 * mult),
                f"link label shows '{label_clean[:60]}' but leads to "
                f"{target_raw}"))
    return signals


# ---------------------------------------------------------------- Layer 3
def analyze_content(text: str, attachments: list,
                    account_age_days: float | None,
                    mult: float, suppress_lures: bool = False) -> list[Signal]:
    """Lure phrases and attachment risk.

    suppress_lures: True when every link in the message is official or
    allowlisted - talking about a Nitro promo ON discord.com is not
    phishing, and v1.0 deleted exactly those messages.
    """
    signals: list[Signal] = []

    has_link = bool(extract_urls(text or "")) or bool(attachments)
    for pattern, weight, name in LURE_PATTERNS:
        m = pattern.search(text or "")
        if not m:
            continue
        if name == "nitro_lure" and not has_link:
            continue  # talking about nitro is fine; linking one is not
        if suppress_lures and name in ("nitro_lure", "steam_bait",
                                       "crypto_bait", "urgency"):
            continue
        signals.append(Signal(
            3, name, int(weight * mult), f"pattern matched: {m.group(0)!r}"))

    for att in attachments or []:
        fname = getattr(att, "filename", "") or ""
        low = fname.lower()
        risky = any(low.endswith(ext) for ext in RISKY_EXTENSIONS)
        double = bool(DOUBLE_EXT_RE.search(low))
        archive = any(low.endswith(ext) for ext in ARCHIVE_EXTENSIONS)
        age = account_age_days if account_age_days is not None else 999
        if double:
            signals.append(Signal(
                3, "double_extension", int(40 * mult),
                f"attachment '{fname}' fakes an image/document extension"))
        elif risky:
            weight = 20 if age > 7 else 35
            signals.append(Signal(
                3, "risky_attachment", int(weight * mult),
                f"executable/script attachment '{fname}'"))
        elif archive and age < 30:
            signals.append(Signal(
                3, "young_account_archive", int(15 * mult),
                f"archive '{fname}' from a {age:.0f}-day-old account - "
                f"contents cannot be inspected"))
    return signals
