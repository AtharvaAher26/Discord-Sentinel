"""Admin cog - slash command surface (design doc, Table 6.1).

Permission gates are Discord-native: configuration commands require
Manage Server, moderation commands require Moderate Members. Every
action lands in the audit trail.
"""
import logging
import time
from collections import defaultdict

import discord
from discord import app_commands
from discord.ext import commands, tasks

from sentinel.config_store import SENSITIVITY_PROFILES

log = logging.getLogger("sentinel.admin")

MODE_CHOICES = [
    app_commands.Choice(name="observe (detect + log only)", value="observe"),
    app_commands.Choice(name="delete_only (grace period)", value="delete_only"),
    app_commands.Choice(name="full (delete + quarantine)", value="full"),
]
SENSITIVITY_CHOICES = [
    app_commands.Choice(name=n, value=n) for n in SENSITIVITY_PROFILES
]


class AdminCog(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot
        # in-memory /stats counters: guild_id -> {key: count}
        self.stats: dict[int, defaultdict] = defaultdict(
            lambda: defaultdict(int))
        self.observe_nudge.start()

    def cog_unload(self) -> None:
        self.observe_nudge.cancel()

    def bump(self, guild_id: int, key: str) -> None:
        self.stats[guild_id][key] += 1

    # ------------------------------------------------------------ nudge
    @tasks.loop(hours=24)
    async def observe_nudge(self) -> None:
        """Guilds still in observe mode 7+ days after setup get ONE
        mod-log nudge suggesting they enable enforcement (v1.1)."""
        for guild_id in await self.bot.store.guilds():
            s = await self.bot.store.get_settings(guild_id)
            if s["mode"] != "observe" or s["observe_nudge_at"]:
                continue
            since = s["setup_at"] or s["mode_changed_at"]
            if not since or time.time() - since < 7 * 86400:
                continue
            channel = self.bot.get_channel(s["log_channel"]) \
                if s["log_channel"] else None
            if channel is not None:
                embed = discord.Embed(
                    title="Sentinel has been observing for 7 days",
                    description=(
                        "Detection logs are in this channel. If they look "
                        "accurate, enable enforcement with `/config mode` "
                        "(delete_only deletes flagged messages; full also "
                        "quarantines). Stay in observe as long as you "
                        "like - this reminder will not repeat."),
                    color=discord.Color.from_str("#2d7ab3"))
                try:
                    await channel.send(embed=embed)
                except discord.HTTPException:
                    pass
            await self.bot.store.set_setting(
                guild_id, "observe_nudge_at", time.time())

    @observe_nudge.before_loop
    async def _nudge_ready(self) -> None:
        await self.bot.wait_until_ready()

    # ------------------------------------------------------------ /setup
    @app_commands.command(
        name="setup",
        description="Configure Sentinel: mod-log channel + quarantine role")
    @app_commands.describe(
        log_channel="Staff channel that receives evidence embeds",
        appeal_channel="Optional channel quarantined members can still see")
    @app_commands.default_permissions(manage_guild=True)
    @app_commands.guild_only()
    async def setup_cmd(self, interaction: discord.Interaction,
                        log_channel: discord.TextChannel,
                        appeal_channel: discord.TextChannel | None = None):
        guild = interaction.guild
        enforcement = self.bot.enforcement

        await self.bot.store.set_setting(guild.id, "log_channel",
                                         log_channel.id)
        if appeal_channel:
            await self.bot.store.set_setting(guild.id, "appeal_channel",
                                             appeal_channel.id)

        role = await enforcement.ensure_quarantine_role(
            guild, appeal_channel.id if appeal_channel else None)
        await self.bot.store.set_setting(guild.id, "quarantine_role", role.id)

        # v1.1: new guilds start in OBSERVE mode - detection + logging
        # only, nothing deleted, until an admin opts into enforcement.
        now = time.time()
        await self.bot.store.set_setting(guild.id, "mode", "observe")
        await self.bot.store.set_setting(guild.id, "mode_changed_at", now)
        await self.bot.store.set_setting(guild.id, "setup_at", now)

        hierarchy_note = ""
        if guild.me.top_role <= role:
            hierarchy_note = (
                "\nWARNING: my highest role must sit ABOVE the quarantine "
                "role - move it up in Server Settings > Roles, or "
                "quarantine cannot assign it.")
        embed = discord.Embed(
            title="Sentinel is watching",
            description=(
                f"Mod-log: {log_channel.mention}\n"
                f"Appeal channel: {appeal_channel.mention if appeal_channel else 'not set'}\n"
                f"Quarantine role: {role.mention}\n"
                f"Mode: **observe** - I will log detections here but delete "
                f"nothing. Review the logs, then run /config mode "
                f"(delete_only or full) when you trust them.\n"
                f"Sensitivity: medium"),
            color=discord.Color.from_str("#2d7ab3"),
        )
        if hierarchy_note:
            embed.description += hierarchy_note
        await interaction.response.send_message(embed=embed, ephemeral=True)

    # ------------------------------------------------------------ /config
    config_group = app_commands.Group(
        name="config", description="View or change Sentinel settings",
        default_permissions=discord.Permissions(manage_guild=True),
        guild_only=True)

    @config_group.command(name="view", description="Show current settings")
    async def config_view(self, interaction: discord.Interaction):
        s = await self.bot.store.get_settings(interaction.guild_id)
        def ch(cid):
            c = self.bot.get_channel(cid) if cid else None
            return c.mention if c else "not set"
        embed = discord.Embed(
            title="Sentinel settings",
            color=discord.Color.from_str("#2d7ab3"))
        embed.add_field(name="Mod-log", value=ch(s["log_channel"]))
        embed.add_field(name="Appeal channel", value=ch(s["appeal_channel"]))
        embed.add_field(name="Quarantine role",
                        value=f"<@&{s['quarantine_role']}>"
                              if s["quarantine_role"] else "not set")
        embed.add_field(name="Sensitivity", value=s["sensitivity"])
        embed.add_field(name="Mode", value=s["mode"])
        embed.add_field(name="Threat network",
                        value="on" if s.get("network", 1) else "off")
        embed.add_field(name="Warning DMs",
                        value="on" if s["warn_dms"] else "off")
        await interaction.response.send_message(embed=embed, ephemeral=True)

    @config_group.command(name="sensitivity",
                          description="Detection threshold profile")
    @app_commands.choices(profile=SENSITIVITY_CHOICES)
    async def config_sensitivity(self, interaction: discord.Interaction,
                                 profile: app_commands.Choice[str]):
        await self.bot.store.set_setting(interaction.guild_id, "sensitivity",
                                         profile.value)
        await interaction.response.send_message(
            f"Sensitivity set to **{profile.value}**.", ephemeral=True)

    @config_group.command(name="mode", description="Enforcement mode")
    @app_commands.choices(mode=MODE_CHOICES)
    async def config_mode(self, interaction: discord.Interaction,
                          mode: app_commands.Choice[str]):
        await self.bot.store.set_setting(interaction.guild_id, "mode",
                                         mode.value)
        await self.bot.store.set_setting(
            interaction.guild_id, "mode_changed_at", time.time())
        await interaction.response.send_message(
            f"Enforcement mode set to **{mode.value}**.", ephemeral=True)

    @config_group.command(
        name="network",
        description="Cross-server threat network: share + receive "
                    "anonymized domain signals")
    @app_commands.choices(state=[
        app_commands.Choice(name="on", value="on"),
        app_commands.Choice(name="off", value="off"),
    ])
    async def config_network(self, interaction: discord.Interaction,
                             state: app_commands.Choice[str]):
        await self.bot.store.set_setting(
            interaction.guild_id, "network",
            1 if state.value == "on" else 0)
        await interaction.response.send_message(
            f"Threat network **{state.value}**. Only domain names of "
            f"MALICIOUS verdicts are shared - never message content or "
            f"member data.", ephemeral=True)

    # ------------------------------------------------------------ /allowlist
    allow_group = app_commands.Group(
        name="allowlist", description="Trust or untrust a domain in this "
        "server",
        default_permissions=discord.Permissions(manage_guild=True),
        guild_only=True)

    @allow_group.command(name="add")
    @app_commands.describe(domain="Registrable domain, e.g. wiki.example.com")
    async def allow_add(self, interaction: discord.Interaction,
                        domain: str):
        domain = domain.strip().lower().replace("https://", "").split("/")[0]
        await self.bot.store.allowlist_add(interaction.guild_id, domain)
        await interaction.response.send_message(
            f"`{domain}` is now trusted in this server.", ephemeral=True)

    @allow_group.command(name="remove")
    async def allow_remove(self, interaction: discord.Interaction,
                           domain: str):
        domain = domain.strip().lower().replace("https://", "").split("/")[0]
        await self.bot.store.allowlist_remove(interaction.guild_id, domain)
        await interaction.response.send_message(
            f"`{domain}` is no longer trusted.", ephemeral=True)

    # ------------------------------------------------------------ /release
    @app_commands.command(
        name="release",
        description="Restore a quarantined member (reversible enforcement)")
    @app_commands.describe(member="Member to release", reason="Why")
    @app_commands.default_permissions(moderate_members=True)
    @app_commands.guild_only()
    async def release_cmd(self, interaction: discord.Interaction,
                          member: discord.Member, reason: str):
        released = await self.bot.enforcement.release(
            interaction.guild, member.id, reason)
        await self.bot.store.audit_add(
            interaction.guild_id, member.id, interaction.channel_id,
            "", "MANUAL_RELEASE", 0, "released", reason)
        # circuit breaker: 3 automated releases in 7 days -> observe
        await self.bot.enforcement.notify_circuit_breaker(interaction.guild)
        msg = (f"{member.mention} released and roles restored."
               if released else
               f"{member.mention} had no quarantine snapshot, but the "
               f"quarantine role was removed if present.")
        await interaction.response.send_message(msg, ephemeral=False)

    # ------------------------------------------------------------ /quarantine
    @app_commands.command(
        name="quarantine",
        description="Manually quarantine a member (same audit trail)")
    @app_commands.describe(member="Member to quarantine", reason="Why")
    @app_commands.default_permissions(moderate_members=True)
    @app_commands.guild_only()
    async def quarantine_cmd(self, interaction: discord.Interaction,
                             member: discord.Member, reason: str):
        settings = await self.bot.store.get_settings(interaction.guild_id)
        role = interaction.guild.get_role(settings["quarantine_role"])
        if role is None:
            role = await self.bot.enforcement.ensure_quarantine_role(
                interaction.guild, settings["appeal_channel"])
        await self.bot.enforcement.quarantine(
            member, role, automated=False)
        self.bot.behavior_tracker.note_malicious(member.id)
        await self.bot.store.offender_note(member.id)
        await self.bot.store.audit_add(
            interaction.guild_id, member.id, interaction.channel_id,
            "", "MANUAL_QUARANTINE", 100, "quarantined", reason)
        await interaction.response.send_message(
            f"{member.mention} quarantined. `/release` restores them.",
            ephemeral=False)

    # ------------------------------------------------------------ /stats
    @app_commands.command(name="stats",
                          description="Sentinel activity in this server")
    @app_commands.default_permissions(manage_guild=True)
    @app_commands.guild_only()
    async def stats_cmd(self, interaction: discord.Interaction):
        s = self.stats.get(interaction.guild_id, defaultdict(int))
        releases = await self.bot.store.releases_recent(
            interaction.guild_id, days=7)
        embed = discord.Embed(
            title="Sentinel /stats",
            color=discord.Color.from_str("#2d7ab3"))
        embed.add_field(name="Messages scanned", value=str(s["scanned"]))
        embed.add_field(name="Deleted", value=str(s["deleted"]))
        embed.add_field(name="Quarantined", value=str(s["quarantined"]))
        embed.add_field(name="Releases (7 d)", value=str(releases))
        embed.add_field(name="Mode",
                        value=(await self.bot.store.get_settings(
                            interaction.guild_id))["mode"])
        intel = self.bot.intel.stats()
        embed.add_field(
            name="Phish feed",
            value=(f"{intel['feed_domains']} domains, "
                   f"{'STALE - REST fallback active' if intel['feed_stale'] else 'live'}"))
        embed.add_field(name="Verdict cache",
                        value=str(intel["verdict_cache"]))
        embed.add_field(name="Network domains",
                        value=str(await self.bot.store.network_size()))
        embed.set_footer(text="Releases at 3 in 7 days trip the circuit "
                              "breaker (observe-only)")
        await interaction.response.send_message(embed=embed, ephemeral=True)

    # ------------------------------------------------------------ /report
    @app_commands.command(
        name="report",
        description="Report a suspicious message or domain to staff")
    @app_commands.describe(
        message_link="Link to the suspicious message",
        domain="Domain or link in question")
    @app_commands.guild_only()
    async def report_cmd(self, interaction: discord.Interaction,
                         message_link: str | None = None,
                         domain: str | None = None):
        settings = await self.bot.store.get_settings(interaction.guild_id)
        channel = self.bot.get_channel(settings["log_channel"]) \
            if settings["log_channel"] else None
        if channel is None:
            await interaction.response.send_message(
                "Staff have not configured a mod-log yet (/setup).",
                ephemeral=True)
            return
        embed = discord.Embed(
            title="Community report",
            description=(f"From {interaction.user.mention}\n"
                         f"Link: {message_link or 'n/a'}\n"
                         f"Domain: {domain or 'n/a'}"),
            color=discord.Color.from_str("#c9a227"))
        await channel.send(embed=embed)
        await interaction.response.send_message(
            "Report sent to the staff channel. Thank you.", ephemeral=True)


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(AdminCog(bot))
