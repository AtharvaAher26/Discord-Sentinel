# Discord Sentinel

A defensive anti-phishing security bot for Discord, written in Python
(discord.py 2.x). It protects servers from the four account-theft families:

1. **Phishing links** - fake Discord login pages on lookalike domains
2. **Nitro scams** - free-gift lure campaigns
3. **Token grabbers** - malware attachments disguised as tools
4. **Hijacked accounts** - behavioral detection of compromised members

The full design rationale lives in the companion document
*Sentinel - Design and Architecture* (chapters referenced below).

> **v1.2 (network + user app).** Adds the two features that turn a
> good mod bot into a defensible product: a **cross-server threat
> network** (domains reported MALICIOUS in 2+ servers score +40 in
> all of them, before public feeds list them; domain names only, never
> content or member data; `/config network` opts a server out) and a
> **user-installed right-click scan** - install Sentinel to your
> account and check ANY message, including DMs, via
> *Apps -> Scan with Sentinel*.
>
> **v1.1 (production hardening).** Fixed four real bugs
> found in review: leetspeak domains (d1scord.com) folded exactly to
> official domains and evaded all checks; official Steam links scored
> as lookalikes; `delete_only` mode quarantined anyway; and the
> circuit breaker could never trip. It also adds shortener resolution,
> staff scanning, durable offender/link history, QR-code scanning,
> observe-by-default onboarding, a test corpus, and Docker deploys.
> See IMPROVEMENT-GUIDE.md for the full list.

---

## How detection works (Chapter 3 of the design doc)

| Layer | What it does | Source |
|-------|--------------|--------|
| 1. Domain reputation | Confirmed phishing/malware domains, cached in memory with a websocket feed for live updates | Sinking Yachts, Google Safe Browsing (optional key), URLhaus |
| 2. URL heuristics | Leetspeak/homoglyph folding (confusables mapped, not deleted), lookalike similarity vs. protected brands, suspicious TLDs, IP-literal hosts, **shorteners resolved and their destinations scored** | built in |
| 3. Content patterns | Nitro lure phrasing, urgency markers, fake-login framing, risky/double-extension/archive attachments, masked markdown links, QR-code URLs (optional) | built in |
| 4. Behavioral | Message velocity, mass mentions, DM bursts, first-ever-link novelty, new-account bursts, repeat offenders (persisted across restarts) | built in |

Signals are weighted and fused into a 0-100 score:

- **SAFE (0-29)** - no action
- **SUSPICIOUS (30-69)** - message deleted; staff notified; warning DM in the upper band
- **MALICIOUS (70-100)** - message deleted + member quarantined (full mode only)

**Staff accounts are scanned like everyone else** - a hijacked mod
account is the worst case in the threat model. Enforcement is capped
for staff at delete + alert; a human always decides on quarantining
staff. New servers start in **observe mode** (log-only) and opt into
enforcement when the logs earn trust.

Every action is reversible and every action posts evidence to the mod-log.

## Setup

1. Create an application at <https://discord.com/developers/applications>,
   add a bot, and copy the token.
2. On the Bot tab enable **Server Members Intent** and **Message Content
   Intent** (both are required; see Chapter 7 of the design doc for why).
3. OAuth2 > URL Generator: scopes `bot` + `applications.commands`, and
   permissions: View Channels, Send Messages, Embed Links, Read Message
   History, Manage Messages, Manage Roles, Moderate Members.
4. Invite the bot to your server.

```bash
pip install -r requirements.txt
cp .env.example .env    # paste your token
python bot.py
```

Or with Docker (recommended for production - the SQLite database
lives on a named volume and survives rebuilds):

```bash
cp .env.example .env    # paste your token
docker compose up -d --build
```

Optional QR-code scanning: `pip install -r requirements-optional.txt`.

Then run `/setup` in the server to pick a mod-log channel and create
the quarantine role. The server starts in **observe mode**; switch
with `/config mode` when the logs look right.

## Commands (Table 6.1)

| Command | Permission | Purpose |
|---------|-----------|---------|
| `/setup` | Manage Server | Pick mod-log channel, create quarantine role |
| `/config view` | Manage Server | Show all settings |
| `/config sensitivity` | Manage Server | low / medium / high / strict thresholds |
| `/config mode` | Manage Server | observe / delete_only / full |
| `/allowlist add/remove` | Manage Server | Trust or untrust a domain per server |
| `/release` | Moderate Members | Restore a quarantined member |
| `/quarantine` | Moderate Members | Manual quarantine |
| `/stats` | Manage Server | Scan and action counters |
| `/report` | everyone | Flag a suspicious message for staff |
| *Scan with Sentinel* (right-click a message → Apps) | everyone, incl. DMs | On-demand scan of one message; works anywhere if Sentinel is installed to your account (see below) |

### User install (DM protection)

Server bots cannot read your DMs - but you can ask Sentinel to check
one message at a time. In the Developer Portal open your app →
**Installation** and enable both **Guild Install** and **User
Install** (default scopes: `applications.commands` for user installs).
Users then add Sentinel from its profile ("Add App" → "Add to My
Apps") and get **right-click any message → Apps → Scan with
Sentinel**, in servers, DMs, and group chats. The verdict is private
(ephemeral) and nothing is stored.

### Cross-server threat network

Every MALICIOUS verdict contributes its domain (only the domain) to a
shared signal table. A domain flagged in 2+ servers earns +40 in all
of them - typically hours before public feeds catch up. A single
server's lone report never flags anything network-wide, which keeps
the network poison-resistant. Servers opt out with
`/config network off` (stops both sharing and receiving).

## Safety properties

- **Reversible ladder** - quarantine snapshots prior roles; `/release`
  restores them exactly, even after a bot restart.
- **Fail-open** - a feed timeout can never produce a MALICIOUS verdict.
- **Circuit breaker** - 3 releases of automated quarantines within 7 days
  drops the server to observe-only until an admin re-enables enforcement.
- **Durable security state** - repeat-offender verdicts and link
  history persist in SQLite; a bot restart no longer resets them.
- **Privacy** - message content is scanned in memory and never persisted;
  the SQLite store holds settings, allowlists, verdict metadata, and role
  snapshots only (30/90-day retentions).

## Tests

The corpus suite is the false-positive budget: realistic benign
messages must stay SAFE, realistic attacks must reach their band.
Run it before changing any threshold or weight:

```bash
pip install -r requirements-dev.txt
pytest tests/ -q
```

## Production notes

- **Privileged intents.** Message Content + Server Members are
  privileged. Under 100 servers they are simple toggles; beyond that,
  Discord requires app verification and a written justification for
  each intent. Draft it early - Sentinel's is one sentence: *"Message
  Content is scanned in memory to detect phishing URLs; Server Members
  is required to snapshot and restore roles for reversible
  quarantine."* Nothing about message content is ever stored.
- **Feed health.** `/stats` shows the Sinking Yachts feed state. If it
  reads STALE, the websocket is down (auto-reconnect with backoff) and
  per-domain REST checks are carrying Layer 1.
- **Hosting.** Any always-on host works: a small VPS, a Raspberry Pi,
  or the Docker setup above. The bot is a single process; no external
  database or queue.

## Known limitations (honest scope)

- Member-to-member DMs are invisible to bots by platform design; the
  DM-burst signal only observes DMs sent to the bot. `/report` covers
  member-to-member scams.
- A message scanner cannot replace client-side protection against token
  malware - pair the bot with user education.
- Google Safe Browsing v4 is free only for non-commercial use; a commercial
  deployment should migrate to Web Risk (Chapter 7.3).

## Layout

```
bot.py                  entry point, wiring, setup_hook
sentinel/
  config_store.py       SQLite per-guild settings, allowlists, audit,
                        offenders, release log, link history
  reputation.py         Layer 1: feed clients + TTL cache + websocket
                        (backoff/staleness) + shortener resolver
  detection.py          Layers 2-3: URL heuristics + content patterns
  behavior.py           Layer 4: sliding-window behavioral counters
  enforcement.py        verdict -> action ladder, quarantine, mod-log
  qrscan.py             optional QR-code URL extraction (opencv)
cogs/
  scanner.py            on_message pipeline (Section 5.3)
  admin.py              slash commands + observe-mode nudge
  userapp.py            'Scan with Sentinel' context menu (user install)
tests/                  detection corpus + behavior/store/network tests
Dockerfile              production image (docker compose up -d)
```

v1.2 - see IMPROVEMENT-GUIDE.md for what changed and why. The roadmap
chapter covers what ships next (ML scoring, cross-server signal
sharing, web dashboard).
