# Contributing to Discord-Sentinel

Sentinel is a Discord anti-phishing bot (v1.2): it scores messages for
phishing, enforces a reversible action ladder, and shares threat signals
across servers through a cross-server threat network. It never bans and
never stores message content — those rules are permanent, not v1 limits.

## Setup

Requires Python 3.11+.

```bash
git clone https://github.com/AtharvaAher26/Discord-Sentinel.git
cd Discord-Sentinel
pip install -r requirements.txt        # runtime: discord.py, aiohttp, aiosqlite
pip install -r requirements-dev.txt    # + pytest
cp .env.example .env                   # paste your bot token
```

To run the bot you also need a Discord application: create one at
<https://discord.com/developers/applications>, add a bot, and enable
**Server Members Intent** and **Message Content Intent**. Invite it with
scopes `bot` + `applications.commands`. See the README's Setup section for
the full permission list.

```bash
python bot.py
```

## Tests

Tests are offline and fixture-driven (no network calls, no live Discord):

```bash
pytest tests/ -q
```

The suite has 36 tests covering detection, the behaviour store, and the
cross-server network. Run the full suite before opening a pull request.
New behaviour needs a test; a fix needs a regression test that fails
without it.

## Ground rules

- **Reversible enforcement, always.** Every action is reversible and
  posts evidence to the mod-log. Quarantine snapshots a member's prior
  roles so `/release` restores them exactly. Never add an irreversible
  action (no bans, no permanent role strips).
- **Cross-server rule is poison-resistant by design.** Only the domain
  is shared across servers, never message content or user data. A domain
  reported in 2+ servers scores +40 everywhere; a lone report flags
  nothing network-wide. Don't weaken that threshold.
- **Fail-open.** A feed timeout or an unavailable dependency can never
  produce a MALICIOUS verdict. When in doubt, the bot does less, not more.
- **No message content is stored.** Detections are computed from the
  message in memory; nothing about its content is ever persisted. Keep it
  that way.
- **Server starts in observe mode.** Enforcement is opt-in per server
  (`/setup` switches modes). Don't change the default to full enforcement.

## Pull requests

- One focused change per PR, with a clear title and a short description of
  what changed and why.
- Keep the README's status section honest: if a feature lands, say so; if
  something is deferred, say so.
- Don't commit secrets, API keys, bot tokens, or real server/message data
  — fixtures only.
