> **STATUS: All items implemented in v1.1 (Oct 20, 2026).** Two additional crash bugs were found and fixed during implementation: (1) `_brand_similarity` returning None was unpacked unconditionally - v1.0 would throw on most ordinary links; (2) `bot.session` does not exist in discord.py - v1.0 would crash in setup_hook on first boot. Both are covered by the new test suite / smoke tests.

# Discord Sentinel — Improvement Guide

Prioritized fixes based on a full code review (Oct 20, 2026).
P0 = fix before any public launch. P1 = detection quality. P2 = product & ops.

---

## P0 — Correctness & security flaws

### 1. Staff are exempt from *scanning* — scan them, exempt only from punishment
**Where:** `cogs/scanner.py`, `_scan_guild_message`
**Problem:** Anyone with Manage Server / Administrator skips scanning entirely.
Your own threat model lists hijacked accounts — a hijacked *mod* account is
the most damaging one, and right now it can post phishing links untouched.

**Fix:** Run the full pipeline for everyone. If the author is staff, cap the
action at delete + staff alert (never auto-quarantine), and say so in the log.

```python
# scanner.py — replace the early return with a flag
is_staff = perms.manage_guild or perms.administrator
# ... run layers 1-4 as normal ...
if is_staff and verdict != "SAFE":
    action = await self.bot.enforcement.execute_staff_alert(
        message, verdict, score, signals, domains)  # delete + alert only
```

### 2. Shorteners are flagged (+5) but never resolved
**Where:** `sentinel/detection.py`, `analyze_domains` / `LINK_SHORTENERS`
**Problem:** The README promises "resolve shorteners"; the code only adds
5 points. The real destination domain — the thing your best layers score —
is never seen.

**Fix:** Resolve the redirect chain (max 3 hops, 2s total timeout, cache the
result per short URL for 1h), then score the *final* domain through the same
pipeline. Fail-open: a resolution timeout scores the shortener as today.

```python
async def resolve_shortener(session, url: str) -> str | None:
    try:
        async with session.head(url, allow_redirects=True,
                                timeout=aiohttp.ClientTimeout(total=2)) as r:
            return str(r.url)
    except Exception:
        return None
```

### 3. Homoglyph folding deletes non-ASCII instead of mapping it
**Where:** `sentinel/detection.py`, `fold()`
**Problem:** `encode("ascii", "ignore")` *deletes* Cyrillic/Greek lookalikes,
so `discоrd.com` (Cyrillic о) folds to `discrd.com` — similarity drops and a
classic IDN attack weakens your best signal.

**Fix:** Map confusables *before* the ASCII fold, using a small table
(or the Unicode `confusables.txt` subset for Latin lookalikes):

```python
CONFUSABLES = {"о": "o", "а": "a", "е": "e", "р": "p", "с": "c",
               "х": "x", "і": "i", "ѕ": "s", "ο": "o", "α": "a"}
# in fold(): text = "".join(CONFUSABLES.get(ch, ch) for ch in text)
# also: flag any host containing mixed scripts as its own signal (+20)
```

Also decode punycode (`xn--…`) labels before folding — `idna` codec is stdlib.

### 4. Behavioral state is memory-only — restarts wipe repeat offenders
**Where:** `sentinel/behavior.py` (README admits "in-memory only")
**Problem:** A bot restart erases velocity windows and the 7-day
repeat-offender memory. Attackers who notice a restart window get a
clean slate; legit tuning data is lost too.

**Fix:** Persist only the durable parts to the existing SQLite store:
repeat-offender verdicts (already partially in `config_store`) and
per-user first-seen-domain history. Keep the hot sliding windows in memory.

---

## P1 — Detection quality

### 5. IP-literal hosts get no signal
`http://185.220.x.x/login` has no registrable domain to score. Add a signal:
IP-literal host + any lure pattern = +30. Cheap, high precision.

### 6. Obfuscated link formats slip past extraction
`URL_RE` misses spaced/obfuscated forms scammers actually use:
`discord . com`, `hxxp://`, `[click here](url)` where display text mimics a
brand but the target differs. Add:
- a de-obfuscation pre-pass (`hxxp` → `http`, ` . ` → `.`) before extraction
- a markdown-link check: if link *text* looks like an official domain but the
  target domain differs → strong signal (+35)

### 7. No test corpus — you can't measure false positives
This is the single highest-leverage engineering task after P0:
- Benign corpus: ~500 real messages from public servers (giveaways, legit
  .xyz links, bot commands) — target **<1% false-positive rate**.
- Malicious corpus: samples from Sinking Yachts / PhishTank archives.
- Run both in CI on every threshold change. A moderation bot lives or dies
  on its FP rate; right now the thresholds (30/70) are unmeasured guesses.

### 8. Attachment checks are filename-only
A renamed `grabber.exe` → `photo.png.exe` is caught, but `tool.zip` /
`setup.rar` archives sail through. Add: flag archive attachments from
accounts <30 days old (+15), and optionally check file hashes against
URLhaus payload data (free) when an archive/executable is posted.

### 9. Feed resilience
- Websocket consumer: add exponential-backoff reconnect + a "feed stale"
  health flag — if the SY socket is down >10 min, log it and lean on the
  REST check (you already have it as fallback in `check()`).
- Cache *negative* results with a shorter TTL (e.g. 10 min) than positives:
  a domain clean at 10:00 can be weaponized by 10:30.

---

## P2 — Product & operations

### 10. Default new servers to observe mode for 7 days
Auto-quarantine on day one is how bots get uninstalled. Ship `/setup` with
`mode=observe` + a daily summary DM to the owner; let them flip to `full`
when they trust the logs. (Your mode system already supports this — it's
a default + a reminder, not new machinery.)

### 11. Ship a Dockerfile + one-command deploy
Your audience is Discord admins, not sysadmins. A `docker compose up`
path (bot + volume for `sentinel.db`) removes the biggest adoption
friction after the invite link. Add a `/health`-style owner command
reporting feed status, cache size, and per-guild FP stats from `/stats`.

### 12. QR-code / screenshot scams (from your own roadmap)
A growing Nitro-scam variant is a QR image ("scan to verify"). `pyzbar`
or `opencv` QR decoding on image attachments, then run the decoded URL
through the existing pipeline — reuses everything you've built.

### 13. Privileged-intent readiness
Past 100 servers, Discord requires verification + intent justification.
Prepare the application text early (it's also good marketing copy), and
design the bot to degrade gracefully if Message Content intent is denied
(feed-only mode on domains in embeds/mentions).

---

## Suggested order

| Week | Work |
|------|------|
| 1 | #1 staff scanning, #2 shortener resolution, #3 confusables |
| 2 | #7 test corpus + threshold tuning, #4 persistence |
| 3 | #5 IP hosts, #6 de-obfuscation, #9 feed resilience |
| 4 | #10 observe-by-default, #11 Docker deploy, listing-site launch |
| Later | #8 archive/hash checks, #12 QR scanning, #13 verification |

**The one-sentence version:** the detection engine is solid — spend your
next effort on (a) not exempting the most dangerous accounts, (b) seeing
the real destination of every link, and (c) measuring your false-positive
rate before you scale. Those three decide whether servers keep the bot
installed.
