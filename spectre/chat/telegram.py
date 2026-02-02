"""
Telegram Adapter

Chat adapter for Telegram integration using python-telegram-bot.
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


class TelegramAdapter(ChatAdapter):
    """
    Telegram chat adapter using python-telegram-bot.

    Requires:
    - TELEGRAM_BOT_TOKEN: Telegram bot token from @BotFather

    Install: pip install python-telegram-bot
    """

    name = "telegram"
    description = "Telegram bot integration"

    def __init__(
        self,
        token: str,
        allowed_users: list[int] | None = None,
        allowed_chats: list[int] | None = None,
    ) -> None:
        """
        Initialize Telegram adapter.

        Args:
            token: Telegram bot token from BotFather
            allowed_users: Optional list of allowed user IDs (whitelist)
            allowed_chats: Optional list of allowed chat IDs (whitelist)
        """
        super().__init__()
        self.token = token
        self.allowed_users = set(allowed_users) if allowed_users else None
        self.allowed_chats = set(allowed_chats) if allowed_chats else None
        self._application: Any = None

    def _is_allowed(self, user_id: int, chat_id: int) -> bool:
        """Check if user/chat is allowed."""
        if self.allowed_users and user_id not in self.allowed_users:
            return False
        if self.allowed_chats and chat_id not in self.allowed_chats:
            return False
        return True

    async def connect(self) -> None:
        """Initialize Telegram bot."""
        try:
            from telegram.ext import ApplicationBuilder

            self._application = (
                ApplicationBuilder()
                .token(self.token)
                .build()
            )

            logger.info("Telegram bot initialized")

        except ImportError:
            raise ImportError(
                "python-telegram-bot is required for Telegram integration. "
                "Install it with: pip install python-telegram-bot"
            )

    async def disconnect(self) -> None:
        """Stop Telegram bot."""
        if self._application:
            await self._application.stop()
            await self._application.shutdown()
        logger.info("Disconnected from Telegram")

    def _parse_telegram_message(self, update: Any) -> ChatMessage | None:
        """Parse a Telegram update into a ChatMessage."""
        message = update.message or update.edited_message

        if not message or not message.text:
            return None

        user = message.from_user
        chat = message.chat

        # Check if allowed
        if not self._is_allowed(user.id, chat.id):
            logger.warning(
                "Unauthorized access attempt",
                user_id=user.id,
                chat_id=chat.id,
            )
            return None

        text = message.text

        # Detect command
        if text.startswith("/"):
            msg_type = MessageType.COMMAND
            # Remove bot username if present (/command@botname)
            if "@" in text.split()[0]:
                parts = text.split(maxsplit=1)
                command = parts[0].split("@")[0]
                text = command + (" " + parts[1] if len(parts) > 1 else "")
        else:
            msg_type = MessageType.TEXT

        # Handle thread (reply to message)
        thread_id = None
        if message.reply_to_message:
            thread_id = str(message.reply_to_message.message_id)

        return ChatMessage(
            id=str(message.message_id),
            text=text,
            user=ChatUser(
                id=str(user.id),
                name=user.username or str(user.id),
                display_name=user.full_name,
                is_bot=user.is_bot,
                platform="telegram",
            ),
            channel=ChatChannel(
                id=str(chat.id),
                name=chat.title or chat.username or "DM",
                is_private=chat.type == "private",
                platform="telegram",
            ),
            timestamp=message.date,
            message_type=msg_type,
            thread_id=thread_id,
            metadata={"raw_update": update},
        )

    async def send_message(self, response: ChatResponse) -> str:
        """Send a message to Telegram."""
        if not self._application:
            raise RuntimeError("Not connected to Telegram")

        kwargs: dict[str, Any] = {
            "chat_id": int(response.channel_id),
            "text": response.text,
            "parse_mode": "Markdown",
        }

        if response.thread_id:
            kwargs["reply_to_message_id"] = int(response.thread_id)

        try:
            message = await self._application.bot.send_message(**kwargs)
            return str(message.message_id)
        except Exception as e:
            # Retry without markdown if parsing fails
            logger.warning("Markdown parsing failed, retrying plain text", error=str(e))
            kwargs["parse_mode"] = None
            message = await self._application.bot.send_message(**kwargs)
            return str(message.message_id)

    async def send_file(
        self,
        channel_id: str,
        file: ChatFile,
        thread_id: str | None = None,
    ) -> str:
        """Send a file to Telegram."""
        if not self._application:
            raise RuntimeError("Not connected to Telegram")

        import io

        kwargs: dict[str, Any] = {
            "chat_id": int(channel_id),
            "document": io.BytesIO(file.content),
            "filename": file.filename,
        }

        if file.title:
            kwargs["caption"] = file.title

        if thread_id:
            kwargs["reply_to_message_id"] = int(thread_id)

        message = await self._application.bot.send_document(**kwargs)
        return str(message.message_id)

    async def update_message(
        self,
        channel_id: str,
        message_id: str,
        text: str,
    ) -> None:
        """Update an existing Telegram message."""
        if not self._application:
            raise RuntimeError("Not connected to Telegram")

        try:
            await self._application.bot.edit_message_text(
                chat_id=int(channel_id),
                message_id=int(message_id),
                text=text,
                parse_mode="Markdown",
            )
        except Exception as e:
            logger.warning("Failed to update message", error=str(e))

    async def add_reaction(
        self,
        channel_id: str,
        message_id: str,
        emoji: str,
    ) -> None:
        """Add a reaction to a Telegram message."""
        if not self._application:
            raise RuntimeError("Not connected to Telegram")

        try:
            from telegram import ReactionTypeEmoji

            await self._application.bot.set_message_reaction(
                chat_id=int(channel_id),
                message_id=int(message_id),
                reaction=[ReactionTypeEmoji(emoji=emoji)],
            )
        except Exception as e:
            # Reactions require Telegram Premium or specific permissions
            logger.debug("Could not add reaction", error=str(e))

    async def run(self) -> None:
        """Start listening for Telegram updates."""
        if not self._application:
            await self.connect()

        from telegram.ext import MessageHandler, CommandHandler, filters

        async def handle_message(update: Any, context: Any) -> None:
            """Handle incoming messages."""
            parsed = self._parse_telegram_message(update)
            if parsed:
                try:
                    response = await self.dispatch(parsed)
                    if response:
                        await self.send_message(response)
                except Exception as e:
                    logger.error("Error handling message", error=str(e))

        async def handle_command(update: Any, context: Any) -> None:
            """Handle commands."""
            parsed = self._parse_telegram_message(update)
            if parsed:
                try:
                    response = await self.dispatch(parsed)
                    if response:
                        await self.send_message(response)
                except Exception as e:
                    logger.error("Error handling command", error=str(e))

        # Register handlers
        self._application.add_handler(
            MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message)
        )
        self._application.add_handler(
            CommandHandler(list(self._handlers.keys()) + ["help", "start"], handle_command)
        )

        # Handle /start specially
        async def start_command(update: Any, context: Any) -> None:
            await update.message.reply_text(
                "👋 Welcome to SPECTRE!\n\n"
                "I'm your threat intelligence assistant. "
                "Use /help to see available commands.\n\n"
                "Try: `/investigate example.com`"
            )

        self._application.add_handler(CommandHandler("start", start_command))

        self._running = True
        logger.info("Telegram adapter starting")

        # Start polling
        await self._application.initialize()
        await self._application.start()
        await self._application.updater.start_polling(drop_pending_updates=True)

        # Keep running until stopped
        while self._running:
            await asyncio.sleep(1)

        await self._application.updater.stop()
        await self._application.stop()
        await self._application.shutdown()

    def format_code_block(self, text: str, language: str = "") -> str:
        """Format as Telegram code block (uses triple backticks)."""
        return f"```{language}\n{text}\n```"

    def format_bold(self, text: str) -> str:
        """Format as Telegram bold (Markdown)."""
        return f"*{text}*"

    def format_italic(self, text: str) -> str:
        """Format as Telegram italic (Markdown)."""
        return f"_{text}_"

    def format_link(self, text: str, url: str) -> str:
        """Format as Telegram link (Markdown)."""
        return f"[{text}]({url})"

    def format_user_mention(self, user_id: str) -> str:
        """Format as Telegram user mention."""
        return f"[User](tg://user?id={user_id})"
