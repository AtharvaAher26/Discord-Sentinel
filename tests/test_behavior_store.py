"""Layer 4 behavior + v1.1 persistence tests.

The persistence tests encode the v1.0 failure mode: repeat offenders
and link novelty lived only in RAM, so a bot restart wiped them.
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentinel.behavior import BehaviorTracker  # noqa: E402
from sentinel.config_store import ConfigStore  # noqa: E402


# ---------------------------------------------------------------- behavior
def test_velocity_trip():
    t = BehaviorTracker()
    tripped = []
    for _ in range(10):
        tripped += t.observe_message(
            1, 42, mention_count=0, has_external_link=False, domain=None)
    assert any(name == "messages" for name, _w, _d in tripped)


def test_link_novelty_first_time_only():
    t = BehaviorTracker()
    first, _ = t.check_link_novelty(1, 42, "example.com")
    second, _ = t.check_link_novelty(1, 42, "other.net")
    assert first and not second


def test_mark_has_posted_suppresses_novelty():
    t = BehaviorTracker()
    t.mark_has_posted(1, 42)
    first, _ = t.check_link_novelty(1, 42, "example.com")
    assert not first


def test_repeat_offender_window():
    t = BehaviorTracker()
    assert not t.is_repeat_offender(42)
    t.note_malicious(42)
    assert t.is_repeat_offender(42)
    t.seed_offenders({99: 1_700_000_000.0})  # old ts from store
    assert not t.is_repeat_offender(99)


def test_new_account_burst():
    t = BehaviorTracker()
    hit, _ = t.check_new_account(2.0, True)
    assert hit
    hit, _ = t.check_new_account(200.0, True)
    assert not hit
    hit, _ = t.check_new_account(2.0, False)
    assert not hit


# ---------------------------------------------------------------- store
def _store(tmp_path):
    store = ConfigStore(str(tmp_path / "test.db"))
    store.migrate()
    return store


def test_new_guild_defaults_to_observe(tmp_path):
    store = _store(tmp_path)
    s = asyncio.run(store.get_settings(123))
    assert s["mode"] == "observe"
    assert s["sensitivity"] == "medium"


def test_offenders_survive_reopen(tmp_path):
    path = str(tmp_path / "test.db")
    s1 = ConfigStore(path)
    s1.migrate()
    asyncio.run(s1.offender_note(4242))
    asyncio.run(s1.close())

    s2 = ConfigStore(path)  # simulated restart
    offenders = asyncio.run(s2.offenders_recent(days=7))
    assert 4242 in offenders
    asyncio.run(s2.close())


def test_release_log_counts_automated_only(tmp_path):
    store = _store(tmp_path)

    async def run():
        await store.record_release(1, 10, automated=True)
        await store.record_release(1, 11, automated=True)
        await store.record_release(1, 12, automated=False)
        await store.record_release(2, 13, automated=True)
        return await store.releases_recent(1, days=7)

    assert asyncio.run(run()) == 2


def test_link_history_roundtrip(tmp_path):
    store = _store(tmp_path)

    async def run():
        assert not await store.link_history_seen(1, 42)
        await store.link_history_add(1, 42)
        assert await store.link_history_seen(1, 42)
        assert not await store.link_history_seen(1, 43)
        assert not await store.link_history_seen(2, 42)

    asyncio.run(run())


def test_settings_roundtrip_with_v11_columns(tmp_path):
    store = _store(tmp_path)

    async def run():
        await store.set_setting(7, "setup_at", 123.0)
        await store.set_setting(7, "mode", "full")
        s = await store.get_settings(7)
        assert s["setup_at"] == 123.0
        assert s["mode"] == "full"
        assert s["observe_nudge_at"] is None

    asyncio.run(run())
