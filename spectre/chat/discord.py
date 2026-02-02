"""
Discord Adapter

Chat adapter for Discord integration using discord.py.
"""

import asyncio
from datetime import datetime
from typing import Any

import structlog

from spectre.chat.adapter import (
    ChatAdapter,
    ChatChannel,
    ChatFile,
    ChatMessage,
    ChatResponse,
    ChatUser,
    MessageType,
)

logger = structlog.get_logger(__name__)


class DiscordAdapter(ChatAdapter):
    """
    Discord chat adapter using discord.py.

    Requires:
    - DISCORD_BOT_TOKEN: Discord bot token

    Install discord.py: pip install discord.py
    """

    name = "discord"
    description = "Discord server integration"

    # Command prefix for Discord
    COMMAND_PREFIX = "/"

    def __init__(
        self,
        token: str,
        command_prefix: str = "/",
    ) -> None:
        """
        Initialize Discord adapter.

        Args:
            token: Discord bot token
            command_prefix: Prefix for commands (default: /)
        """
        super().__init__()
        self.token = token
        self.command_prefix = command_prefix
        self._client: Any = None
        self._bot_user_id: str | None = None

    async def connect(self) -> None:
        """Connect to Discord."""
        try:
            import discord

            intents = discord.Intents.default()
            intents.message_content = True
            intents.guilds = True

            self._client = discord.Client(intents=intents)
            logger.info("Discord client initialized")

        except ImportError:
            raise ImportError(
                "discord.py is required for Discord integration. "
                "Install it with: pip install discord.py"
            )

    async def disconnect(self) -> None:
        """Disconnect from Discord."""
        if self._client:
            await self._client.close()
        logger.info("Disconnected from Discord")

    def _parse_discord_message(self, message: Any) -> ChatMessage | None:
        """Parse a Discord message into a ChatMessage."""
        # Skip bot messages
        if message.author.bot:
            return None

        text = message.content

        # Check for command prefix
        if text.startswith(self.command_prefix):
            msg_type = MessageType.COMMAND
        else:
            msg_type = MessageType.TEXT

        # Get thread/channel info
        thread_id = None
        if hasattr(message.channel, "parent"):
            # This is a thread
            thread_id = str(message.channel.id)
            channel_id = str(message.channel.parent.id)
        else:
            channel_id = str(message.channel.id)

        return ChatMessage(
            id=str(message.id),
            text=text,
            user=ChatUser(
                id=str(message.author.id),
                name=message.author.name,
                display_name=message.author.display_name,
                is_bot=message.author.bot,
                platform="discord",
            ),
            channel=ChatChannel(
                id=channel_id,
                name=getattr(message.channel, "name", "DM"),
                is_private=isinstance(message.channel, type(message.author.dm_channel))
                if hasattr(message.author, "dm_channel") else False,
                platform="discord",
            ),
            timestamp=message.created_at,
            message_type=msg_type,
            thread_id=thread_id,
            attachments=[
                {"url": a.url, "filename": a.filename}
                for a in message.attachments
            ],
            metadata={"raw_message": message},
        )

    async def send_message(self, response: ChatResponse) -> str:
        """Send a message to Discord."""
        if not self._client:
            raise RuntimeError("Not connected to Discord")

        channel = self._client.get_channel(int(response.channel_id))
        if not channel:
            raise ValueError(f"Channel not found: {response.channel_id}")

        # If thread_id specified, try to get the thread
        if response.thread_id:
            thread = channel.get_thread(int(response.thread_id))
            if thread:
                channel = thread

        # Discord has a 2000 character limit
        text = response.text
        if len(text) > 2000:
            text = text[:1997] + "..."

        message = await channel.send(text)
        return str(message.id)

    async def send_file(
        self,
        channel_id: str,
        file: ChatFile,
        thread_id: str | None = None,
    ) -> str:
        """Upload a file to Discord."""
        if not self._client:
            raise RuntimeError("Not connected to Discord")

        import discord
        import io

        channel = self._client.get_channel(int(channel_id))
        if not channel:
            raise ValueError(f"Channel not found: {channel_id}")

        if thread_id:
            thread = channel.get_thread(int(thread_id))
            if thread:
                channel = thread

        discord_file = discord.File(
            io.BytesIO(file.content),
            filename=file.filename,
        )

        message = await channel.send(file=discord_file)
        return str(message.id)

    async def update_message(
        self,
        channel_id: str,
        message_id: str,
        text: str,
    ) -> None:
        """Update an existing Discord message."""
        if not self._client:
            raise RuntimeError("Not connected to Discord")

        channel = self._client.get_channel(int(channel_id))
        if not channel:
            return

        try:
            message = await channel.fetch_message(int(message_id))
            await message.edit(content=text)
        except Exception as e:
            logger.warning("Failed to update message", error=str(e))

    async def add_reaction(
        self,
        channel_id: str,
        message_id: str,
        emoji: str,
    ) -> None:
        """Add a reaction to a Discord message."""
        if not self._client:
            raise RuntimeError("Not connected to Discord")

        channel = self._client.get_channel(int(channel_id))
        if not channel:
            return

        try:
            message = await channel.fetch_message(int(message_id))
            await message.add_reaction(emoji)
        except Exception as e:
            logger.warning("Failed to add reaction", error=str(e))

    async def run(self) -> None:
        """Start listening for Discord events."""
        if not self._client:
            await self.connect()

        @self._client.event
        async def on_ready() -> None:
            self._bot_user_id = str(self._client.user.id)
            logger.info(
                "Discord bot connected",
                username=self._client.user.name,
                user_id=self._bot_user_id,
            )

        @self._client.event
        async def on_message(message: Any) -> None:
            parsed = self._parse_discord_message(message)
            if parsed:
                try:
                    response = await self.dispatch(parsed)
                    if response:
                        await self.send_message(response)
                except Exception as e:
                    logger.error("Error handling message", error=str(e))

        self._running = True
        logger.info("Discord adapter starting")

        try:
            await self._client.start(self.token)
        except asyncio.CancelledError:
            await self.disconnect()

    def format_code_block(self, text: str, language: str = "") -> str:
        """Format as Discord code block."""
        return f"```{language}\n{text}\n```"

    def format_bold(self, text: str) -> str:
        """Format as Discord bold."""
        return f"**{text}**"

    def format_italic(self, text: str) -> str:
        """Format as Discord italic."""
        return f"*{text}*"

    def format_link(self, text: str, url: str) -> str:
        """Format as Discord link (masked link)."""
        return f"[{text}]({url})"

    def format_user_mention(self, user_id: str) -> str:
        """Format as Discord user mention."""
        return f"<@{user_id}>"
