"""Per-guild configuration store (SQLite, WAL mode).

Data minimization (design doc, Chapter 7):
- guild settings + allowlists: kept until changed or bot removed
- audit rows: member id, channel id, domain(s), verdict, score, action, ts
  -> 30 day retention (purged on startup)
- quarantine snapshots: previous role ids -> 90 day retention
- message content is NEVER written to disk
"""
import aiosqlite
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS guild_settings (
    guild_id      INTEGER PRIMARY KEY,
    log_channel   INTEGER,
    quarantine_role INTEGER,
    appeal_channel INTEGER,
    sensitivity   TEXT DEFAULT 'medium',
    mode          TEXT DEFAULT 'observe',
    warn_dms      INTEGER DEFAULT 1,
    mode_changed_at REAL,
    auto_lower    INTEGER DEFAULT 1,
    setup_at      REAL,
    observe_nudge_at REAL,
    network       INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS allowlist (
    guild_id INTEGER NOT NULL,
    domain   TEXT NOT NULL,
    PRIMARY KEY (guild_id, domain)
);

CREATE TABLE IF NOT EXISTS audit (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    guild_id  INTEGER,
    member_id INTEGER,
    channel_id INTEGER,
    domains   TEXT,
    verdict   TEXT,
    score     INTEGER,
    action    TEXT,
    reason    TEXT,
    ts        REAL
);
CREATE INDEX IF NOT EXISTS audit_guild_ts ON audit(guild_id, ts);

CREATE TABLE IF NOT EXISTS quarantine_snapshots (
    guild_id  INTEGER,
    member_id INTEGER,
    role_ids  TEXT,
    automated INTEGER,
    ts        REAL,
    PRIMARY KEY (guild_id, member_id)
);

-- v1.1: durable security state (survives restarts, unlike Layer 4 RAM)
CREATE TABLE IF NOT EXISTS offenders (
    user_id INTEGER PRIMARY KEY,
    ts      REAL
);

CREATE TABLE IF NOT EXISTS release_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    guild_id  INTEGER,
    member_id INTEGER,
    automated INTEGER,
    ts        REAL
);
CREATE INDEX IF NOT EXISTS release_guild_ts ON release_log(guild_id, ts);

CREATE TABLE IF NOT EXISTS link_history (
    guild_id INTEGER,
    user_id  INTEGER,
    ts       REAL,
    PRIMARY KEY (guild_id, user_id)
);

-- v1.2: cross-server threat network. Anonymized DOMAIN-LEVEL signals
-- only - never message content, never member data. A domain reported
-- MALICIOUS in several servers scores higher in all of them, hours
-- before public feeds list it.
CREATE TABLE IF NOT EXISTS network_signals (
    domain     TEXT PRIMARY KEY,
    hits       INTEGER DEFAULT 0,
    first_seen REAL,
    last_seen  REAL
);

CREATE TABLE IF NOT EXISTS network_sources (
    domain   TEXT,
    guild_id INTEGER,
    PRIMARY KEY (domain, guild_id)
);
"""

RETENTION_AUDIT = 30 * 86400
RETENTION_SNAPSHOT = 90 * 86400

SENSITIVITY_PROFILES = {
    # multiplier applied to Layer 2/3 signal weights (Layer 1 feed hits are absolute)
    "low": 0.7,
    "medium": 1.0,
    "high": 1.25,
    "strict": 1.5,
}

DEFAULTS = {
    "log_channel": None,
    "quarantine_role": None,
    "appeal_channel": None,
    "sensitivity": "medium",
    # v1.1: new guilds start in observe - a bot that deletes/quarantines
    # on day one gets uninstalled before it earns trust. /setup explains,
    # a nudge fires after 7 days, admins opt into enforcement.
    "mode": "observe",
    "warn_dms": 1,
    "mode_changed_at": None,
    "auto_lower": 1,
    "setup_at": None,
    "observe_nudge_at": None,
    "network": 1,
}


class ConfigStore:
    def __init__(self, path: str):
        self.path = path
        self._db: aiosqlite.Connection | None = None

    async def close(self):
        if self._db:
            await self._db.close()

    # ------------------------------------------------------------ lifecycle
    def migrate(self) -> None:
        """Synchronous first-time schema creation (called in setup_hook)."""
        import sqlite3
        conn = sqlite3.connect(self.path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(SCHEMA)
        # v1.1/v1.2 column migration for databases created earlier
        cols = {r[1] for r in conn.execute(
            "PRAGMA table_info(guild_settings)")}
        for col, decl in (("setup_at", "REAL"),
                          ("observe_nudge_at", "REAL"),
                          ("network", "INTEGER DEFAULT 1")):
            if col not in cols:
                conn.execute(
                    f"ALTER TABLE guild_settings ADD COLUMN {col} {decl}")
        cutoff = time.time() - RETENTION_AUDIT
        conn.execute("DELETE FROM audit WHERE ts < ?", (cutoff,))
        conn.execute("DELETE FROM release_log WHERE ts < ?", (cutoff,))
        net_cut = time.time() - RETENTION_SNAPSHOT
        conn.execute("DELETE FROM network_signals WHERE last_seen < ?",
                     (net_cut,))
        snap_cut = time.time() - RETENTION_SNAPSHOT
        conn.execute("DELETE FROM quarantine_snapshots WHERE ts < ?", (snap_cut,))
        conn.commit()
        conn.close()

    async def _conn(self) -> aiosqlite.Connection:
        if self._db is None:
            self._db = await aiosqlite.connect(self.path)
            await self._db.execute("PRAGMA journal_mode=WAL")
        return self._db

    # ------------------------------------------------------------ settings
    async def get_settings(self, guild_id: int) -> dict:
        db = await self._conn()
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM guild_settings WHERE guild_id = ?", (guild_id,)
        ) as cur:
            row = await cur.fetchone()
        out = dict(DEFAULTS)
        if row:
            out.update({k: row[k] for k in out.keys()})
        return out

    async def set_setting(self, guild_id: int, key: str, value) -> None:
        db = await self._conn()
        await db.execute(
            "INSERT INTO guild_settings (guild_id) VALUES (?) "
            "ON CONFLICT(guild_id) DO NOTHING",
            (guild_id,),
        )
        await db.execute(
            f"UPDATE guild_settings SET {key} = ? WHERE guild_id = ?",
            (value, guild_id),
        )
        await db.commit()

    async def sensitivity_multiplier(self, guild_id: int) -> float:
        s = await self.get_settings(guild_id)
        return SENSITIVITY_PROFILES.get(s["sensitivity"], 1.0)

    # ------------------------------------------------------------ allowlist
    async def allowlist_add(self, guild_id: int, domain: str) -> None:
        db = await self._conn()
        await db.execute(
            "INSERT OR IGNORE INTO allowlist (guild_id, domain) VALUES (?, ?)",
            (guild_id, domain.lower()),
        )
        await db.commit()

    async def allowlist_remove(self, guild_id: int, domain: str) -> None:
        db = await self._conn()
        await db.execute(
            "DELETE FROM allowlist WHERE guild_id = ? AND domain = ?",
            (guild_id, domain.lower()),
        )
        await db.commit()

    async def allowlist_get(self, guild_id: int) -> set[str]:
        db = await self._conn()
        async with db.execute(
            "SELECT domain FROM allowlist WHERE guild_id = ?", (guild_id,)
        ) as cur:
            rows = await cur.fetchall()
        return {r[0] for r in rows}

    # ------------------------------------------------------------ audit
    async def audit_add(self, guild_id: int, member_id: int, channel_id: int,
                        domains: str, verdict: str, score: int, action: str,
                        reason: str = "") -> None:
        db = await self._conn()
        await db.execute(
            "INSERT INTO audit (guild_id, member_id, channel_id, domains, "
            "verdict, score, action, reason, ts) VALUES (?,?,?,?,?,?,?,?,?)",
            (guild_id, member_id, channel_id, domains, verdict, score,
             action, reason, time.time()),
        )
        await db.commit()

    async def record_release(self, guild_id: int, member_id: int,
                             automated: bool) -> None:
        """Log a release - the circuit breaker's real input (v1.1).

        v1.0 counted rows in quarantine_snapshots, but snapshots are
        DELETED when a member is released, so the counter measured
        current quarantines, not releases, and the breaker could never
        trip correctly."""
        db = await self._conn()
        await db.execute(
            "INSERT INTO release_log (guild_id, member_id, automated, ts) "
            "VALUES (?,?,?,?)",
            (guild_id, member_id, int(automated), time.time()),
        )
        await db.commit()

    async def releases_recent(self, guild_id: int, days: int = 7) -> int:
        """Count releases of AUTOMATED quarantines - circuit breaker input."""
        db = await self._conn()
        since = time.time() - days * 86400
        async with db.execute(
            "SELECT COUNT(*) FROM release_log "
            "WHERE guild_id = ? AND automated = 1 AND ts > ?",
            (guild_id, since),
        ) as cur:
            row = await cur.fetchone()
        return int(row[0]) if row else 0

    # ------------------------------------------------------------ offenders
    async def offender_note(self, user_id: int) -> None:
        """Persist a MALICIOUS verdict so the repeat-offender signal
        survives bot restarts (v1.0 kept it in RAM only)."""
        db = await self._conn()
        await db.execute(
            "INSERT OR REPLACE INTO offenders (user_id, ts) VALUES (?,?)",
            (user_id, time.time()),
        )
        await db.commit()

    async def offenders_recent(self, days: int = 7) -> dict[int, float]:
        db = await self._conn()
        since = time.time() - days * 86400
        async with db.execute(
            "SELECT user_id, ts FROM offenders WHERE ts > ?", (since,)
        ) as cur:
            rows = await cur.fetchall()
        return {int(r[0]): float(r[1]) for r in rows}

    # ------------------------------------------------------------ link history
    async def link_history_seen(self, guild_id: int, user_id: int) -> bool:
        """Has this member EVER posted an external link here (durable)?
        Backs the link-novelty signal across restarts."""
        db = await self._conn()
        async with db.execute(
            "SELECT 1 FROM link_history WHERE guild_id = ? AND user_id = ?",
            (guild_id, user_id),
        ) as cur:
            return await cur.fetchone() is not None

    async def link_history_add(self, guild_id: int, user_id: int) -> None:
        db = await self._conn()
        await db.execute(
            "INSERT OR IGNORE INTO link_history (guild_id, user_id, ts) "
            "VALUES (?,?,?)",
            (guild_id, user_id, time.time()),
        )
        await db.commit()

    # ------------------------------------------------------------ network
    async def network_report(self, domain: str, guild_id: int) -> None:
        """Contribute one MALICIOUS observation of a domain to the
        cross-server network (domain only - no content, no member)."""
        db = await self._conn()
        now = time.time()
        await db.execute(
            "INSERT INTO network_signals (domain, hits, first_seen, "
            "last_seen) VALUES (?, 1, ?, ?) "
            "ON CONFLICT(domain) DO UPDATE SET hits = hits + 1, "
            "last_seen = excluded.last_seen",
            (domain.lower(), now, now),
        )
        await db.execute(
            "INSERT OR IGNORE INTO network_sources (domain, guild_id) "
            "VALUES (?, ?)",
            (domain.lower(), guild_id),
        )
        await db.commit()

    async def network_lookup(self, domain: str):
        """(hits, distinct_guilds) for a domain, or None if unreported."""
        db = await self._conn()
        async with db.execute(
            "SELECT hits FROM network_signals WHERE domain = ?",
            (domain.lower(),),
        ) as cur:
            row = await cur.fetchone()
        if not row:
            return None
        async with db.execute(
            "SELECT COUNT(*) FROM network_sources WHERE domain = ?",
            (domain.lower(),),
        ) as cur:
            grow = await cur.fetchone()
        return int(row[0]), int(grow[0]) if grow else 0

    async def network_size(self) -> int:
        db = await self._conn()
        async with db.execute("SELECT COUNT(*) FROM network_signals") as cur:
            row = await cur.fetchone()
        return int(row[0]) if row else 0

    # ------------------------------------------------------------ snapshots
    async def snapshot_add(self, guild_id: int, member_id: int,
                           role_ids: list[int], automated: bool) -> None:
        db = await self._conn()
        await db.execute(
            "INSERT OR REPLACE INTO quarantine_snapshots "
            "(guild_id, member_id, role_ids, automated, ts) VALUES (?,?,?,?,?)",
            (guild_id, member_id, ",".join(map(str, role_ids)), int(automated),
             time.time()),
        )
        await db.commit()

    async def snapshot_take(self, guild_id: int, member_id: int):
        db = await self._conn()
        async with db.execute(
            "SELECT role_ids, automated FROM quarantine_snapshots "
            "WHERE guild_id = ? AND member_id = ?",
            (guild_id, member_id),
        ) as cur:
            row = await cur.fetchone()
        if not row:
            return None, None
        await db.execute(
            "DELETE FROM quarantine_snapshots WHERE guild_id = ? AND member_id = ?",
            (guild_id, member_id),
        )
        await db.commit()
        return [int(x) for x in row[0].split(",") if x], bool(row[1])

    async def guilds(self) -> list[int]:
        db = await self._conn()
        async with db.execute("SELECT guild_id FROM guild_settings") as cur:
            return [r[0] for r in await cur.fetchall()]

    async def guild_remove(self, guild_id: int) -> None:
        """Leave-means-forget: wipe all rows for a guild."""
        db = await self._conn()
        for table in ("guild_settings", "allowlist", "audit",
                      "quarantine_snapshots", "release_log", "link_history"):
            await db.execute(f"DELETE FROM {table} WHERE guild_id = ?",
                             (guild_id,))
        await db.commit()
