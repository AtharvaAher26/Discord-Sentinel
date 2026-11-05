"""Enforcement - the escalation ladder from the design doc (Table 4.1).

Verdict bands (Table 3.3):
    SAFE        0-29    no action, quiet audit row
    SUSPICIOUS  30-69   delete (+ warn DM in the upper band)
    MALICIOUS   70-100  delete + quarantine (+ staff ping)

Every rung is reversible: quarantine snapshots roles and /release restores
them. No automatic bans in v1.
"""
import contextlib
import logging
import time

import discord

log = logging.getLogger("sentinel.enforce")

QUARANTINE_ROLE_NAME = "Sentinel Quarantine"

VERDICT_COLORS = {
    "SAFE": discord.Color.from_str("#2d7ab3"),
    "SUSPICIOUS": discord.Color.from_str("#c9a227"),
    "MALICIOUS": discord.Color.from_str("#b3452d"),
}


def verdict_for(score: int) -> str:
    if score >= 70:
        return "MALICIOUS"
    if score >= 30:
        return "SUSPICIOUS"
    return "SAFE"


class Enforcement:
    def __init__(self, bot, store, behavior):
        self.bot = bot
        self.store = store
        self.behavior = behavior

    # ------------------------------------------------------------ quarantine
    async def ensure_quarantine_role(self, guild: discord.Guild,
                                     appeal_channel_id: int | None
                                     ) -> discord.Role:
        """Create (once) the quarantine role and its channel overwrites."""
        role = discord.utils.get(guild.roles, name=QUARANTINE_ROLE_NAME)
        if role is None:
            role = await guild.create_role(
                name=QUARANTINE_ROLE_NAME,
                reason="Sentinel /setup: quarantine role",
            )
        deny = discord.Permissions(
            send_messages=False, add_reactions=False, speak=False,
            create_public_threads=False, create_private_threads=False,
            send_messages_in_threads=False,
        )
        for channel in guild.channels:
            try:
                await channel.set_permissions(role, permissions=deny,
                                              reason="Sentinel quarantine")
            except discord.HTTPException:
                continue
        if appeal_channel_id:
            channel = guild.get_channel(appeal_channel_id)
            if channel:
                allow = discord.Permissions(
                    view_channel=True, send_messages=True,
                    read_message_history=True,
                )
                try:
                    await channel.set_permissions(
                        role, permissions=allow,
                        reason="Sentinel appeal channel")
                except discord.HTTPException:
                    pass
        return role

    async def quarantine(self, member: discord.Member, role: discord.Role,
                         automated: bool) -> None:
        """Assign the role, snapshot prior roles for guaranteed restore."""
        prior = [r.id for r in member.roles
                 if r != role and r != guild_everyone(member.guild)]
        await self.store.snapshot_add(
            member.guild.id, member.id, prior, automated)
        try:
            await member.add_roles(role, reason="Sentinel quarantine")
        except discord.HTTPException as exc:
            log.warning("quarantine add_roles failed: %s", exc)

    async def release(self, guild: discord.Guild, member_id: int,
                      reason: str) -> bool:
        """Restore snapshot roles and remove the quarantine role. True if
        a snapshot existed."""
        role = discord.utils.get(guild.roles, name=QUARANTINE_ROLE_NAME)
        role_ids, automated = await self.store.snapshot_take(
            guild.id, member_id)
        if role_ids is not None:
            # circuit-breaker input (v1.1): releases are logged durably
            await self.store.record_release(guild.id, member_id,
                                            bool(automated))
        member = guild.get_member(member_id)
        if member is None:
            return role_ids is not None
        restore: list[discord.Role] = []
        if role_ids:
            for rid in role_ids:
                r = guild.get_role(rid)
                if r:
                    restore.append(r)
        try:
            if role and role in member.roles:
                await member.remove_roles(role, reason=f"release: {reason}")
            if restore:
                await member.add_roles(
                    *restore, reason=f"release snapshot: {reason}")
        except discord.HTTPException as exc:
            log.warning("release failed: %s", exc)
        return role_ids is not None

    # ------------------------------------------------------------ actions
    async def execute(self, message: discord.Message, verdict: str,
                      score: int, signals, domains: list[str],
                      staff: bool = False) -> str:
        """Apply the ladder for a verdict. Returns the action label.

        staff=True caps the ladder at delete + alert: staff accounts are
        SCANNED like everyone else (a hijacked mod account is the worst
        case in the threat model, and v1.0 exempted it from scanning
        entirely), but never auto-quarantined - a human decides that.
        """
        guild = message.guild
        settings = await self.store.get_settings(guild.id)
        mode = settings["mode"]
        action = "logged"

        if mode == "observe":
            await self._audit(message, verdict, score, domains, "observe_only")
            return "observe_only"

        if verdict == "SAFE":
            await self._audit(message, verdict, score, domains, action)
            return action

        # delete first - stop the spread before anything else
        try:
            await message.delete()
            action = "deleted"
        except discord.HTTPException:
            action = "delete_failed"

        if verdict == "SUSPICIOUS" and score >= 50:
            await self._warn_member(message)
        elif verdict == "MALICIOUS" and staff:
            # staff cap: delete + warn + mod-log alert, no quarantine
            action += "+staff_alert"
            if settings["warn_dms"]:
                await self._warn_member(message)
        elif verdict == "MALICIOUS" and mode == "full":
            role_id = settings["quarantine_role"]
            role = guild.get_role(role_id) if role_id else None
            if role is None:
                role = await self.ensure_quarantine_role(
                    guild, settings["appeal_channel"])
            member = message.author if isinstance(message.author,
                                                  discord.Member) else None
            if member and role:
                try:
                    await self.quarantine(member, role, automated=True)
                    action += "+quarantined"
                    self.behavior.note_malicious(member.id)
                    await self.store.offender_note(member.id)
                except discord.HTTPException as exc:
                    log.warning("quarantine failed: %s", exc)
            if settings["warn_dms"]:
                await self._warn_member(message, quarantined=True)
        elif verdict == "MALICIOUS":
            # delete_only mode: exactly what it says - delete + warn,
            # never quarantine (v1.0 quarantined in delete_only too)
            if settings["warn_dms"]:
                await self._warn_member(message)

        await self._audit(message, verdict, score, domains, action)
        await self.mod_log(message, verdict, score, signals, domains, action)
        return action

    async def _warn_member(self, message: discord.Message,
                           quarantined: bool = False) -> None:
        kind = ("quarantined" if quarantined else "removed")
        embed = discord.Embed(
            title=f"Your message was {kind}",
            description=(
                "A link or attachment you posted was flagged by Sentinel "
                "as likely phishing or malware. If you believe this was a "
                "mistake, ask the server staff - they can restore you with "
                "/release and allowlist the domain."),
            color=VERDICT_COLORS["SUSPICIOUS"],
        )
        try:
            await message.author.send(embed=embed)
        except discord.HTTPException:
            pass  # DMs closed - fine

    async def _audit(self, message, verdict, score, domains, action):
        await self.store.audit_add(
            message.guild.id, message.author.id, message.channel.id,
            ",".join(domains)[:400], verdict, score, action)

    # ------------------------------------------------------------ mod log
    async def mod_log(self, message, verdict: str, score: int,
                      signals, domains: list[str], action: str) -> None:
        settings = await self.store.get_settings(message.guild.id)
        channel_id = settings["log_channel"]
        channel = self.bot.get_channel(channel_id) if channel_id else None
        if channel is None:
            return
        author = message.author
        embed = discord.Embed(
            title=f"{verdict} ({score}/100) - {action}",
            color=VERDICT_COLORS.get(verdict, discord.Color.dark_grey()),
            timestamp=discord.utils.utcnow(),
        )
        embed.add_field(name="Member",
                        value=f"{author.mention} (`{author.id}`)",
                        inline=True)
        embed.add_field(name="Account created",
                        value=f"<t:{int(author.created_at.timestamp())}:R>",
                        inline=True)
        embed.add_field(name="Trigger",
                        value=", ".join(domains[:5]) or "content pattern",
                        inline=False)
        if signals:
            detail = "\n".join(f"L{s.layer} {s.name} +{s.weight}: {s.detail}"
                               for s in signals[:8])
            embed.add_field(name="Signals", value=detail[:1000],
                            inline=False)
        embed.add_field(name="Channel", value=message.channel.mention,
                        inline=True)
        if action.startswith("delete"):
            embed.set_footer(text="/release restores - /allowlist trusts a "
                                  "domain in this server")
        else:
            embed.set_footer(text="Audit row recorded")
        try:
            await channel.send(embed=embed)
        except discord.HTTPException:
            pass

    async def notify_circuit_breaker(self, guild: discord.Guild) -> None:
        """3 releases of automated quarantines in 7 days -> observe-only.

        Called after every release; acts only when the threshold is
        actually met (v1.0 defined this but nothing ever called it)."""
        settings = await self.store.get_settings(guild.id)
        if not settings["auto_lower"] or settings["mode"] == "observe":
            return
        if await self.store.releases_recent(guild.id, days=7) < 3:
            return
        await self.store.set_setting(guild.id, "mode", "observe")
        await self.store.set_setting(guild.id, "mode_changed_at", time.time())
        channel = self.bot.get_channel(settings["log_channel"]) \
            if settings["log_channel"] else None
        if channel:
            embed = discord.Embed(
                title="Sentinel dropped to observe-only",
                description=(
                    "Three automated quarantines were released in the last "
                    "7 days, so detection here needs tuning. No messages "
                    "will be deleted until a server admin re-enables "
                    "enforcement with /config mode."),
                color=VERDICT_COLORS["SUSPICIOUS"],
            )
            with contextlib.suppress(discord.HTTPException):
                await channel.send(embed=embed)


def guild_everyone(guild: discord.Guild) -> discord.Role:
    return guild.default_role
