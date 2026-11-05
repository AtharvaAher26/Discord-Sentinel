"""Layer 4 - behavioral analysis for hijacked accounts.

Sliding-window counters per (guild, user), in memory with a 10-minute
horizon (design doc, Table 3.2). The windows themselves are never
persisted, but v1.1 persists the DURABLE facts through ConfigStore:
repeat-offender verdicts (seeded back at boot via seed_offenders) and
link-history (a member having posted links before), so a bot restart
no longer hands attackers a clean slate.

Threading model: single asyncio loop - no locks needed.
"""
import time
from collections import defaultdict, deque

RETENTION = 600.0  # 10 minutes - anything older is irrelevant


class _Counter:
    """Timestamp deque + anti-retrip guard (one trip per window)."""

    def __init__(self) -> None:
        self.times: deque[float] = deque()
        self.tripped_at: float = 0.0
        self.recipients: dict[int, float] = {}  # dm_distinct: rid -> last ts

    def add(self, now: float) -> None:
        self.times.append(now)

    def count(self, now: float, window: float) -> int:
        while self.times and now - self.times[0] > RETENTION:
            self.times.popleft()
        return sum(1 for t in self.times if now - t <= window)

    def trip(self, now: float, window: float) -> bool:
        """True exactly once per window when the guard allows."""
        if now - self.tripped_at < window:
            return False
        self.tripped_at = now
        return True


class BehaviorTracker:
    """Per-(guild, user) sliding windows for the Table 3.2 signals."""

    THRESHOLDS = {
        # name: (threshold, window_s, weight, description)
        "messages":  (10, 10.0, 25, "10+ messages in 10 s"),
        "mentions":  (7, 30.0, 35, "7+ unique mentions in 30 s"),
        "links":     (3, 60.0, 10, "3+ external links in 60 s"),
        "dm_distinct": (8, 60.0, 40, "8+ distinct DM recipients in 60 s"),
    }

    def __init__(self) -> None:
        # (guild_id, user_id) -> {signal: _Counter}
        self._counters: dict[tuple[int, int], dict[str, _Counter]] = defaultdict(
            lambda: defaultdict(_Counter))
        # (guild_id, user_id) -> set of external domains ever posted
        self._known_domains: dict[tuple[int, int], set[str]] = defaultdict(set)
        # user id -> last MALICIOUS verdict ts (repeat offender, 7 d)
        self._offenders: dict[int, float] = {}

    # ------------------------------------------------------------ repeat
    def note_malicious(self, user_id: int) -> None:
        self._offenders[user_id] = time.time()

    def seed_offenders(self, offenders: dict[int, float]) -> None:
        """Restore repeat-offender state persisted by ConfigStore."""
        self._offenders.update(offenders)

    def is_repeat_offender(self, user_id: int, days: int = 7) -> bool:
        ts = self._offenders.get(user_id)
        return bool(ts and time.time() - ts < days * 86400)

    def mark_has_posted(self, guild_id: int, user_id: int) -> None:
        """Record (from the durable store) that this member has posted
        an external link before, so novelty doesn't re-trip after a
        restart."""
        self._known_domains[(guild_id, user_id)].add("__prior__")

    # ------------------------------------------------------------ events
    def observe_message(self, guild_id: int, user_id: int, *,
                        mention_count: int, has_external_link: bool,
                        domain: str | None) -> list[tuple[str, int, str]]:
        """Feed one channel message; return tripped signals."""
        now = time.time()
        key = (guild_id, user_id)
        cs = self._counters[key]
        tripped: list[tuple[str, int, str]] = []

        def bump(name: str, n: int = 1):
            thresh, window, weight, desc = self.THRESHOLDS[name]
            c = cs[name]
            for _ in range(n):
                c.add(now)
            if c.count(now, window) >= thresh and c.trip(now, window):
                tripped.append((name, weight, desc))

        bump("messages")
        if mention_count:
            bump("mentions", mention_count)
        if has_external_link:
            bump("links")
        return tripped

    def observe_dm(self, guild_id: int, sender_id: int,
                   recipient_id: int) -> list[tuple[str, int, str]]:
        """Feed one outbound DM; track DISTINCT recipients in the window."""
        now = time.time()
        key = (guild_id, sender_id)
        c = self._counters[key]["dm_distinct"]
        c.recipients[recipient_id] = now
        # expire old entries
        stale = [rid for rid, ts in c.recipients.items()
                 if now - ts > RETENTION]
        for rid in stale:
            del c.recipients[rid]
        thresh, window, weight, desc = self.THRESHOLDS["dm_distinct"]
        if len(c.recipients) >= thresh and c.trip(now, window):
            return [("dm_distinct", weight, desc)]
        return []

    def check_link_novelty(self, guild_id: int, user_id: int,
                           domain: str) -> tuple[bool, str]:
        """True (with description) the FIRST time this member posts any
        external domain - Table 3.2 'link novelty'."""
        key = (guild_id, user_id)
        first_ever = len(self._known_domains[key]) == 0
        self._known_domains[key].add(domain)
        if first_ever:
            return True, "first external link ever posted by this member"
        return False, ""

    def check_new_account(self, account_age_days: float | None,
                          has_link: bool) -> tuple[bool, str]:
        """New-account burst: < 7 days old and already posting links."""
        if account_age_days is not None and account_age_days < 7 and has_link:
            return True, (f"account is {account_age_days:.1f} days old and "
                          f"already posting links")
        return False, ""
