#!/usr/bin/env python3
"""Discord Sentinel - anti-phishing security bot (prototype v1.0).

Entry point. Boots the gateway, loads cogs, and wires the shared
subsystems (config store, threat-intel cache) into the bot instance.

Run:
    pip install -r requirements.txt
    python bot.py

Required environment (see .env.example):
    DISCORD_TOKEN   - bot token from the Discord Developer Portal
    GSB_API_KEY     - optional Google Safe Browsing v4 key
    DB_PATH         - optional SQLite path (default ./sentinel.db)
"""
import asyncio
import logging
import os
import sys

import aiohttp
import discord
from discord.ext import commands

from sentinel.reputation import ThreatIntel
from sentinel.config_store import ConfigStore
from sentinel.behavior import BehaviorTracker
from sentinel.enforcement import Enforcement

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
)
log = logging.getLogger("sentinel")


class SentinelBot(commands.Bot):
    """Bot subclass carrying the shared subsystems on itself."""

    def __init__(self) -> None:
        intents = discord.Intents.default()
        intents.message_content = True   # privileged: URL/attachment scanning
        intents.members = True           # privileged: join events, role restore

        super().__init__(
            command_prefix=commands.when_mentioned,  # no prefix commands by design
            intents=intents,
            help_command=None,
        )

        db_path = os.getenv("DB_PATH", "sentinel.db")
        self.store = ConfigStore(db_path)
        self.intel = ThreatIntel(
            gsb_api_key=os.getenv("GSB_API_KEY") or None,
        )
        self.behavior_tracker = BehaviorTracker()
        self.enforcement = Enforcement(self, self.store,
                                       self.behavior_tracker)
        # v1.1: the bot owns its HTTP session explicitly - v1.0 passed
        # `self.session`, which is not a discord.py attribute, and would
        # have crashed setup_hook on first boot.
        self.session: aiohttp.ClientSession | None = None

    async def setup_hook(self) -> None:
        self.store.migrate()
        self.session = aiohttp.ClientSession()
        await self.intel.start(self.session)
        # restore durable repeat-offender state (v1.1 persistence)
        offenders = await self.store.offenders_recent(days=7)
        if offenders:
            self.behavior_tracker.seed_offenders(offenders)
            log.info("restored %d repeat-offender records", len(offenders))
        # keep the phishing feed fresh via websocket
        self.intel.start_ws_task(self)
        for ext in ("cogs.scanner", "cogs.admin", "cogs.userapp"):
            await self.load_extension(ext)
        await self.tree.sync()
        log.info("cogs loaded and slash commands synced")

    async def close(self) -> None:
        await self.intel.stop()
        if self.session is not None:
            await self.session.close()
        await self.store.close()
        await super().close()


async def main() -> None:
    token = os.getenv("DISCORD_TOKEN")
    if not token:
        # try .env file next to the script for local runs
        try:
            from dotenv import load_dotenv
            load_dotenv()
            token = os.getenv("DISCORD_TOKEN")
        except ImportError:
            pass
    if not token:
        log.error("DISCORD_TOKEN is not set. Copy .env.example to .env and fill it in.")
        sys.exit(1)

    bot = SentinelBot()
    async with bot:
        await bot.start(token)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
