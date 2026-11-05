"""Scanner cog - the message pipeline (design doc, Section 5.3).

Cheap-first order: exemptions -> URL extraction (+ QR decode) ->
Layer 1 cache -> Layer 2/3 -> Layer 4 -> score -> enforce.

v1.1 changes:
- Staff are SCANNED like everyone else. v1.0 exempted Manage
  Server/Administrator accounts entirely - but a hijacked mod account
  is the worst case in the threat model. Enforcement caps staff
  actions at delete + alert; only detection is universal.
- QR-code URLs from image attachments join the same pipeline.
- Link novelty is backed by the durable link_history table, so a
  restart doesn't make every member 'first link ever' again.
- /stats counters are actually bumped (v1.0 never called bump()).

A cog may define only ONE on_message listener, so guild and DM
handling share the single entry point below.
"""
import logging

import discord
from discord.ext import commands

from sentinel import detection, qrscan
from sentinel.enforcement import verdict_for

log = logging.getLogger("sentinel.scanner")


class ScannerCog(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot

    # ------------------------------------------------------------ helpers
    @staticmethod
    def _account_age_days(user: discord.abc.User) -> float | None:
        try:
            delta = discord.utils.utcnow() - user.created_at
            return delta.total_seconds() / 86400
        except Exception:
            return None

    async def _skip_channels(self, guild_id: int) -> set[int]:
        """Appeal + mod-log channels are exempt from scanning."""
        settings = await self.bot.store.get_settings(guild_id)
        skip = set()
        for key in ("appeal_channel", "log_channel"):
            if settings[key]:
                skip.add(settings[key])
        return skip

    def _bump(self, guild_id: int, key: str) -> None:
        admin = self.bot.get_cog("AdminCog")
        if admin is not None:
            admin.bump(guild_id, key)

    # ------------------------------------------------------------ listener
    @commands.Cog.listener()
    async def on_message(self, message: discord.Message) -> None:
        if message.author.bot:
            return
        if message.guild is None:
            self._track_dm(message)
            return
        await self._scan_guild_message(message)

    # ------------------------------------------------------------ guild path
    async def _scan_guild_message(self, message: discord.Message) -> None:
        guild = message.guild
        self._bump(guild.id, "scanned")

        # exempt channels skip; staff do NOT skip (v1.1, see docstring)
        if message.channel.id in await self._skip_channels(guild.id):
            return
        perms = message.author.guild_permissions
        is_staff = bool(perms.manage_guild or perms.administrator)

        allow = await self.bot.store.allowlist_get(guild.id)
        mult = await self.bot.store.sensitivity_multiplier(guild.id)
        settings = await self.bot.store.get_settings(guild.id)
        network_on = bool(settings.get("network", 1))
        age_days = self._account_age_days(message.author)

        urls = detection.extract_urls(message.content or "")
        attachments = list(message.attachments)

        # QR codes in images carry URLs too - same pipeline
        qr_urls = await qrscan.extract_qr_urls(attachments)
        if qr_urls:
            for u in qr_urls:
                if u not in urls:
                    urls.append(u)

        # ---- Layers 1-3 (cheap-first) ---------------------------------
        signals: list[detection.Signal] = []
        l2, domains = await detection.analyze_domains(
            urls, self.bot.intel, mult, allow,
            network=self.bot.store.network_lookup if network_on else None)
        signals += l2
        if qr_urls:
            signals.append(detection.Signal(
                2, "qr_code_link", 0,
                "URL arrived via QR code image: "
                + ", ".join(sorted({detection.host_of(u)
                                    for u in qr_urls}))[:120]))
        signals += detection.analyze_markdown_links(
            message.content or "", mult)
        # every link trusted/official -> lure talk is not phishing
        all_trusted = bool(urls) and not domains
        signals += detection.analyze_content(
            message.content, attachments, age_days, mult,
            suppress_lures=all_trusted)

        # combo: bare-IP host + any Layer 3 lure is the classic
        # token-grabber landing page shape
        if any(s.name == "ip_literal_host" for s in signals) and \
                any(s.layer == 3 for s in signals):
            signals.append(detection.Signal(
                2, "ip_lure_combo", 10,
                "bare-IP destination combined with lure content"))

        # ---- Layer 4 behavioral ---------------------------------------
        has_link = bool(urls) or bool(attachments)
        domain = domains[0] if domains else None
        tracker = self.bot.behavior_tracker

        l4 = tracker.observe_message(
            guild.id, message.author.id,
            mention_count=len(set(message.mentions)),
            has_external_link=has_link,
            domain=domain,
        )
        if domain:
            # durable novelty: consult the store before believing
            # 'first link ever' - restarts must not re-trip everyone
            key_seen = await self.bot.store.link_history_seen(
                guild.id, message.author.id)
            if key_seen:
                tracker.mark_has_posted(guild.id, message.author.id)
            novelty, desc = tracker.check_link_novelty(
                guild.id, message.author.id, domain)
            if novelty:
                await self.bot.store.link_history_add(
                    guild.id, message.author.id)
            # link novelty counts only for established accounts (30 d+)
            if novelty and (age_days or 0) >= 30:
                l4.append(("link_novelty", 30, desc))
        new_trip, new_desc = tracker.check_new_account(age_days, has_link)
        if new_trip:
            l4.append(("new_account_burst", 35, new_desc))
        if tracker.is_repeat_offender(message.author.id):
            l4.append(("repeat_offender", 20,
                       "prior MALICIOUS verdict within 7 days"))
        for name, weight, desc in l4:
            signals.append(detection.Signal(4, name, int(weight * mult), desc))

        # ---- verdict ---------------------------------------------------
        score = min(100, sum(s.weight for s in signals))
        verdict = verdict_for(score)

        if verdict != "SAFE" or domains:
            action = await self.bot.enforcement.execute(
                message, verdict, score, signals, domains, staff=is_staff)
            if "deleted" in action:
                self._bump(guild.id, "deleted")
            if "quarantined" in action:
                self._bump(guild.id, "quarantined")
            # contribute to the cross-server network: domains only,
            # only on MALICIOUS verdicts, only if this guild shares
            if verdict == "MALICIOUS" and network_on:
                for d in domains:
                    await self.bot.store.network_report(d, guild.id)
            log.info("g=%s m=%s verdict=%s score=%s action=%s domains=%s",
                     guild.id, message.author.id, verdict, score, action,
                     domains[:3])

    # ------------------------------------------------------------ DM path
    def _track_dm(self, message: discord.Message) -> None:
        """DM burst tracking.

        Platform reality: the gateway only shows the bot the DMs it
        receives - member-to-member DMs are invisible to any bot. The
        dm_distinct counter still flags a hijacked account blasting the
        bot itself (common during raid waves); /report covers the rest.
        """
        recipient = getattr(getattr(message.channel, "recipient", None),
                            "id", 0)
        for guild in getattr(message.author, "mutual_guilds", []):
            tripped = self.bot.behavior_tracker.observe_dm(
                guild.id, message.author.id, recipient)
            if tripped:
                log.info("dm_distinct tripped for %s in guild %s",
                         message.author.id, guild.id)

    # ------------------------------------------------------------ edits
    @commands.Cog.listener()
    async def on_message_edit(self, before: discord.Message,
                              after: discord.Message) -> None:
        """Edited messages are re-scanned - a classic evasion vector."""
        if after.guild and after.edited_at and not after.author.bot:
            await self._scan_guild_message(after)


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(ScannerCog(bot))
