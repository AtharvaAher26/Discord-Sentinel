"""v1.2 cross-server threat network tests."""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentinel import detection  # noqa: E402
from sentinel.config_store import ConfigStore  # noqa: E402


class FakeIntel:
    async def check(self, domain):
        return False, None

    async def resolve(self, url):
        return None


def _store(tmp_path):
    store = ConfigStore(str(tmp_path / "net.db"))
    store.migrate()
    return store


def test_network_report_and_lookup(tmp_path):
    store = _store(tmp_path)

    async def run():
        assert await store.network_lookup("bad-domain.net") is None
        await store.network_report("bad-domain.net", guild_id=1)
        assert await store.network_lookup("bad-domain.net") == (1, 1)
        await store.network_report("bad-domain.net", guild_id=1)
        await store.network_report("bad-domain.net", guild_id=2)
        hits, guilds = await store.network_lookup("bad-domain.net")
        assert hits == 3 and guilds == 2  # distinct guilds counted once
        assert await store.network_size() == 1

    asyncio.run(run())


def test_network_defaults_on_and_toggles(tmp_path):
    store = _store(tmp_path)

    async def run():
        s = await store.get_settings(55)
        assert s["network"] == 1
        await store.set_setting(55, "network", 0)
        s = await store.get_settings(55)
        assert s["network"] == 0

    asyncio.run(run())


def _score_with_network(text, network):
    async def run():
        urls = detection.extract_urls(text)
        signals, _flagged = await detection.analyze_domains(
            urls, FakeIntel(), 1.0, set(), network=network)
        return signals

    return asyncio.run(run())


async def _two_guilds(domain):
    return (3, 2)


async def _one_guild_many_hits(domain):
    return (5, 1)


async def _one_hit(domain):
    return (1, 1)


def test_network_flag_two_guilds_is_strong():
    signals = _score_with_network(
        "see https://unknown-shop.net/x", _two_guilds)
    net = [s for s in signals if s.name == "network_flag"]
    assert net and net[0].weight == 40


def test_network_flag_repeat_single_guild():
    signals = _score_with_network(
        "see https://unknown-shop.net/x", _one_guild_many_hits)
    net = [s for s in signals if s.name == "network_flag"]
    assert net and net[0].weight == 25


def test_network_single_hit_is_silent():
    """One report in one server must not flag a domain network-wide -
    that would let a single troll poison the network."""
    signals = _score_with_network(
        "see https://unknown-shop.net/x", _one_hit)
    assert not [s for s in signals if s.name == "network_flag"]


def test_network_off_means_no_signal():
    signals = _score_with_network(
        "see https://unknown-shop.net/x", None)
    assert not [s for s in signals if s.name == "network_flag"]
