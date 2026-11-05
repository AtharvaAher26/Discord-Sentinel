"""User-install context command (v1.2) - 'Scan with Sentinel'.

Server bots cannot see member-to-member DMs; that is where most Nitro
scams land. Discord's user-installed apps close part of that gap: a
user who installs Sentinel to their ACCOUNT gets a right-click menu
on ANY message - in servers, DMs, and group chats - that runs the
full Layer 1-3 pipeline on demand and answers privately (ephemeral).

This is user-invoked, never passive: Sentinel reads exactly the one
message the user asks about, and nothing else. No enforcement, no
logging of content - a verdict embed for the asker only.

Portal setup: the application needs BOTH install contexts enabled
(Developer Portal -> Installation -> Guild Install + User Install),
or the menu only appears where the bot is a server member.
"""
import logging

import discord
from discord import app_commands
from discord.ext import commands

from sentinel import detection, qrscan
from sentinel.enforcement import VERDICT_COLORS, verdict_for

log = logging.getLogger("sentinel.userapp")


class UserAppCog(commands.Cog):
    def __init__(self, bot: commands.Bot):
        self.bot = bot
        self.scan_menu = app_commands.ContextMenu(
            name="Scan with Sentinel",
            callback=self._scan,
            allowed_installs=app_commands.AppInstallationType(
                guild=True, user=True),
            allowed_contexts=app_commands.AppCommandContext(
                guild=True, dm_channel=True, private_channel=True),
        )
        bot.tree.add_command(self.scan_menu)

    def cog_unload(self) -> None:
        self.bot.tree.remove_command(
            self.scan_menu.name, type=discord.AppCommandType.message)

    # ------------------------------------------------------------ callback
    async def _scan(self, interaction: discord.Interaction,
                    message: discord.Message) -> None:
        await interaction.response.defer(ephemeral=True)
        text = message.content or ""
        attachments = list(message.attachments)

        urls = detection.extract_urls(text)
        for u in await qrscan.extract_qr_urls(attachments):
            if u not in urls:
                urls.append(u)

        signals: list[detection.Signal] = []
        flagged: list[str] = []
        if urls:
            l2, flagged = await detection.analyze_domains(
                urls, self.bot.intel, 1.0, set(),
                network=self.bot.store.network_lookup)
            signals += l2
        signals += detection.analyze_markdown_links(text, 1.0)
        try:
            age_days = (discord.utils.utcnow()
                        - message.author.created_at).total_seconds() / 86400
        except Exception:
            age_days = None
        signals += detection.analyze_content(
            text, attachments, age_days, 1.0,
            suppress_lures=bool(urls) and not flagged)

        score = min(100, sum(s.weight for s in signals))
        verdict = verdict_for(score)

        embed = discord.Embed(
            title=f"Sentinel scan: {verdict} ({score}/100)",
            color=VERDICT_COLORS.get(verdict, discord.Color.dark_grey()))
        if not urls and not attachments:
            embed.description = (
                "This message contains no links or attachments - "
                "nothing for Sentinel to check.")
        else:
            if flagged:
                embed.add_field(name="Domains checked",
                                value=", ".join(flagged[:5]), inline=False)
            if signals:
                detail = "\n".join(
                    f"L{s.layer} {s.name} +{s.weight}: {s.detail}"
                    for s in signals[:8])
                embed.add_field(name="Signals", value=detail[:1000],
                                inline=False)
            embed.description = {
                "SAFE": "No phishing signals found. Stay alert anyway - "
                        "no scanner catches everything.",
                "SUSPICIOUS": "This message has phishing traits. Do NOT "
                              "log in, download, or scan anything it "
                              "offers. Verify through official channels.",
                "MALICIOUS": "High-confidence scam. Do NOT interact with "
                             "it. If this is in a server, tell the mods; "
                             "if a friend sent it, their account is likely "
                             "hijacked - reach them another way.",
            }[verdict]
        embed.set_footer(text="On-demand scan - Sentinel does not read "
                              "your DMs unless you ask it to check one.")
        await interaction.followup.send(embed=embed, ephemeral=True)


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(UserAppCog(bot))
