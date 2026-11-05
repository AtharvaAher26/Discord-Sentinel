"""Layer 1 - domain reputation feeds.

Feeds (design doc, Table 3.1):
- Sinking Yachts: Discord/Steam phishing domains. Full list at startup,
  per-domain REST checks on cache misses, websocket push for live updates.
- Google Safe Browsing v4 (optional key): SOCIAL_ENGINEERING + MALWARE.
- URLhaus (abuse.ch): malware distribution hosts.

Everything lands in one in-memory set with TTL; lookups on a warm cache are
sub-millisecond. Infrastructure failures NEVER mark a domain malicious
(fail-open rule) - a timeout contributes no verdict at all.
"""
import asyncio
import contextlib
import logging
import time
from dataclasses import dataclass, field

import aiohttp

log = logging.getLogger("sentinel.intel")

SY_BASE = "https://phish.sinking.yachts"
GSB_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/host/"

CACHE_TTL_POS = 3600      # 1 h for confirmed-malicious verdicts
CACHE_TTL_NEG = 600       # 10 min for clean verdicts - a domain clean at
                          # 10:00 can be weaponized by 10:30 (v1.1 change)
RESOLVE_TTL = 3600        # shortener resolution cache
FEED_STALE_AFTER = 600    # no SY sync/ws event for 10 min -> feed stale
GSB_TIMEOUT = aiohttp.ClientTimeout(total=2.0)
SY_TIMEOUT = aiohttp.ClientTimeout(total=5.0)
RESOLVE_TIMEOUT = aiohttp.ClientTimeout(total=2.5)


@dataclass
class ThreatIntel:
    """Merged, cached view over the three feeds."""
    gsb_api_key: str | None = None
    phish: set[str] = field(default_factory=set)          # SY full list
    _cache: dict[str, tuple[bool, str | None, float]] = field(default_factory=dict)
    # domain -> (malicious?, source, ts);  source None = checked, not found
    _ws_task: asyncio.Task | None = None
    _session: aiohttp.ClientSession | None = None
    _last_feed_ts: float = 0.0     # last successful SY sync or ws event
    _resolve_cache: dict = field(default_factory=dict)
    # url -> (final_url | None, ts)

    # ------------------------------------------------------------ lifecycle
    async def start(self, session: aiohttp.ClientSession) -> None:
        self._session = session
        try:
            async with session.get(f"{SY_BASE}/v2/all", timeout=SY_TIMEOUT) as r:
                if r.status == 200:
                    domains = await r.json()
                    self.phish = {d.lower() for d in domains}
                    self._last_feed_ts = time.time()
                    log.info("Sinking Yachts sync: %d domains", len(self.phish))
        except Exception as exc:  # fail-open: log and continue
            log.warning("Sinking Yachts initial sync failed (%s) - "
                        "continuing without full list", exc)

    def start_ws_task(self, bot) -> None:
        self._ws_task = bot.loop.create_task(self._ws_consumer(bot))

    async def stop(self) -> None:
        if self._ws_task:
            self._ws_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._ws_task

    # ------------------------------------------------------------ websocket
    async def _ws_consumer(self, bot) -> None:
        """Keep the feed current: SY pushes 'added'/'deleted' domain events.

        v1.1: exponential backoff on reconnect (5 s -> 300 s cap, reset
        on a healthy connection) instead of a fixed 15 s retry storm,
        and every event stamps _last_feed_ts for staleness reporting.
        """
        import json
        backoff = 5.0
        while not bot.is_closed():
            try:
                async with self._session.ws_connect(
                    f"{SY_BASE}/v2/ws", heartbeat=30.0, timeout=30.0
                ) as ws:
                    log.info("Sinking Yachts websocket connected")
                    backoff = 5.0
                    self._last_feed_ts = time.time()
                    async for msg in ws:
                        if msg.type != aiohttp.WSMsgType.TEXT:
                            continue
                        self._last_feed_ts = time.time()
                        try:
                            data = json.loads(msg.data)
                        except ValueError:
                            continue
                        kind = data.get("type")
                        domains = [d.lower() for d in data.get("data", [])]
                        if kind in ("added", "phish-added"):
                            self.phish.update(domains)
                            log.info("feed +%d domains", len(domains))
                        elif kind in ("deleted", "phish-removed"):
                            self.phish.difference_update(domains)
                        elif kind == "heartbeat":
                            pass
            except asyncio.CancelledError:
                return
            except Exception as exc:
                log.warning("SY websocket dropped (%s) - reconnect in "
                            "%.0f s", exc, backoff)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 300.0)

    # ------------------------------------------------------------ health
    @property
    def feed_stale(self) -> bool:
        """True when no SY sync/websocket event landed recently. The
        per-domain REST checks still run; staleness only means the
        full-list + push freshness is degraded."""
        return time.time() - self._last_feed_ts > FEED_STALE_AFTER

    def stats(self) -> dict:
        return {
            "feed_domains": len(self.phish),
            "feed_stale": self.feed_stale,
            "feed_age_s": int(time.time() - self._last_feed_ts)
            if self._last_feed_ts else None,
            "verdict_cache": len(self._cache),
            "resolve_cache": len(self._resolve_cache),
        }

    # ------------------------------------------------------------ resolver
    async def resolve(self, url: str) -> str | None:
        """Follow a (shortener) URL to its final destination.

        HEAD first, GET fallback for hosts that refuse HEAD. Result is
        cached for RESOLVE_TTL. Fail-open: any error returns None and
        the caller scores the shortener alone, as v1.0 did.
        """
        hit = self._resolve_cache.get(url)
        if hit and time.time() - hit[1] < RESOLVE_TTL:
            return hit[0]
        if self._session is None:
            return None
        final: str | None = None
        for method in ("HEAD", "GET"):
            try:
                async with self._session.request(
                    method, url, allow_redirects=True, max_redirects=5,
                    timeout=RESOLVE_TIMEOUT,
                ) as r:
                    final = str(r.url)
                    # drain a GET body minimally so the socket frees up
                    if method == "GET":
                        await r.content.read(1024)
                break
            except Exception:
                if method == "GET":
                    final = None
                continue
        self._resolve_cache[url] = (final, time.time())
        return final

    # ------------------------------------------------------------ lookups
    def _cache_get(self, domain: str):
        hit = self._cache.get(domain)
        if not hit:
            return None
        ok, source, ts = hit
        ttl = CACHE_TTL_POS if ok else CACHE_TTL_NEG
        if time.time() - ts > ttl:
            del self._cache[domain]
            return None
        return ok, source

    def _cache_put(self, domain: str, malicious: bool, source: str | None):
        self._cache[domain] = (malicious, source, time.time())

    async def check(self, domain: str) -> tuple[bool, str | None]:
        """Return (malicious, source). Source names the feed that flagged it.

        (False, None) means 'no evidence' - which is NOT a clean bill of
        health, just nothing known. Layer 2/3 continue from there.
        """
        domain = domain.lower()
        if domain in self.phish:
            return True, "sinking_yachts"
        cached = self._cache_get(domain)
        if cached is not None:
            return cached

        # Sinking Yachts per-domain check (covers lists fetched before boot)
        sy = await self._check_sy(domain)
        if sy:
            self._cache_put(domain, True, "sinking_yachts")
            return True, "sinking_yachts"

        # Google Safe Browsing (only if a key is configured)
        gsb = await self._check_gsb(domain)
        if gsb:
            self._cache_put(domain, True, "google_safe_browsing")
            return True, "google_safe_browsing"

        # URLhaus - malware distribution hosts
        uh = await self._check_urlhaus(domain)
        if uh:
            self._cache_put(domain, True, "urlhaus")
            return True, "urlhaus"

        self._cache_put(domain, False, None)
        return False, None

    async def _check_sy(self, domain: str) -> bool:
        if self._session is None:
            return False
        try:
            async with self._session.get(
                f"{SY_BASE}/v2/check/{domain}", timeout=SY_TIMEOUT
            ) as r:
                if r.status == 200:
                    return bool(await r.json())
        except Exception:
            pass
        return False

    async def _check_gsb(self, domain: str) -> bool:
        if not self.gsb_api_key or self._session is None:
            return False
        body = {
            "client": {"clientId": "discord-sentinel", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["SOCIAL_ENGINEERING", "MALWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": f"http://{domain}/"}],
            },
        }
        try:
            async with self._session.post(
                f"{GSB_URL}?key={self.gsb_api_key}",
                json=body, timeout=GSB_TIMEOUT,
            ) as r:
                if r.status == 200:
                    data = await r.json()
                    return bool(data.get("matches"))
        except Exception:
            pass
        return False

    async def _check_urlhaus(self, domain: str) -> bool:
        if self._session is None:
            return False
        try:
            async with self._session.post(
                URLHAUS_URL, data={"host": domain}, timeout=GSB_TIMEOUT
            ) as r:
                if r.status == 200:
                    data = await r.json()
                    return data.get("query_status") == "ok"
        except Exception:
            pass
        return False
