"""
Chat Adapter Base

Abstract base class for chat platform adapters.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Coroutine

import structlog

logger = structlog.get_logger(__name__)


class MessageType(Enum):
    """Types of chat messages."""

    TEXT = "text"
    COMMAND = "command"
    FILE = "file"
    REACTION = "reaction"


@dataclass
class ChatUser:
    """Represents a chat user."""

    id: str
    name: str
    display_name: str | None = None
    is_bot: bool = False
    platform: str = ""


@dataclass
class ChatChannel:
    """Represents a chat channel."""

    id: str
    name: str
    is_private: bool = False
    platform: str = ""


@dataclass
class ChatMessage:
    """Incoming chat message."""

    id: str
    text: str
    user: ChatUser
    channel: ChatChannel
    timestamp: datetime
    message_type: MessageType = MessageType.TEXT
    thread_id: str | None = None
    attachments: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_command(self) -> bool:
        """Check if message is a command."""
        return self.message_type == MessageType.COMMAND or self.text.startswith("/")

    @property
    def command_name(self) -> str | None:
        """Extract command name from message."""
        if self.text.startswith("/"):
            parts = self.text[1:].split(maxsplit=1)
            return parts[0] if parts else None
        return None

    @property
    def command_args(self) -> str:
        """Extract command arguments."""
        if self.text.startswith("/"):
            parts = self.text[1:].split(maxsplit=1)
            return parts[1] if len(parts) > 1 else ""
        return self.text


@dataclass
class ChatResponse:
    """Outgoing chat response."""

    text: str
    channel_id: str
    thread_id: str | None = None
    attachments: list[dict[str, Any]] = field(default_factory=list)
    blocks: list[dict[str, Any]] = field(default_factory=list)
    ephemeral: bool = False
    user_id: str | None = None  # For ephemeral messages


@dataclass
class ChatFile:
    """File attachment for chat."""

    content: bytes
    filename: str
    mimetype: str = "application/octet-stream"
    title: str | None = None


# Type alias for message handlers
MessageHandler = Callable[[ChatMessage], Coroutine[Any, Any, ChatResponse | None]]


class ChatAdapter(ABC):
    """
    Abstract base class for chat platform adapters.

    Each platform (Slack, Discord, Telegram) implements this interface.
    """

    name: str = "base"
    description: str = "Base chat adapter"

    def __init__(self) -> None:
        """Initialize the adapter."""
        self._handlers: dict[str, MessageHandler] = {}
        self._default_handler: MessageHandler | None = None
        self._running = False

    def register_command(
        self,
        command: str,
        handler: MessageHandler,
    ) -> None:
        """
        Register a command handler.

        Args:
            command: Command name (without leading /)
            handler: Async function to handle the command
        """
        self._handlers[command.lower()] = handler
        logger.debug("Registered command handler", command=command)

    def set_default_handler(self, handler: MessageHandler) -> None:
        """Set the default handler for non-command messages."""
        self._default_handler = handler

    async def dispatch(self, message: ChatMessage) -> ChatResponse | None:
        """
        Dispatch a message to the appropriate handler.

        Args:
            message: Incoming message

        Returns:
            Response to send, or None
        """
        if message.is_command:
            command = message.command_name
            if command and command.lower() in self._handlers:
                handler = self._handlers[command.lower()]
                return await handler(message)

        # Use default handler for non-commands or unrecognized commands
        if self._default_handler:
            return await self._default_handler(message)

        return None

    @abstractmethod
    async def connect(self) -> None:
        """Connect to the chat platform."""
        pass

    @abstractmethod
    async def disconnect(self) -> None:
        """Disconnect from the chat platform."""
        pass

    @abstractmethod
    async def send_message(self, response: ChatResponse) -> str:
        """
        Send a message to a channel.

        Args:
            response: Message to send

        Returns:
            Message ID of sent message
        """
        pass

    @abstractmethod
    async def send_file(
        self,
        channel_id: str,
        file: ChatFile,
        thread_id: str | None = None,
    ) -> str:
        """
        Send a file to a channel.

        Args:
            channel_id: Channel to send to
            file: File to upload
            thread_id: Optional thread to reply in

        Returns:
            File ID
        """
        pass

    @abstractmethod
    async def update_message(
        self,
        channel_id: str,
        message_id: str,
        text: str,
    ) -> None:
        """
        Update an existing message.

        Args:
            channel_id: Channel containing the message
            message_id: ID of message to update
            text: New text content
        """
        pass

    @abstractmethod
    async def add_reaction(
        self,
        channel_id: str,
        message_id: str,
        emoji: str,
    ) -> None:
        """
        Add a reaction to a message.

        Args:
            channel_id: Channel containing the message
            message_id: ID of message to react to
            emoji: Emoji name to add
        """
        pass

    @abstractmethod
    async def run(self) -> None:
        """
        Start the adapter's event loop.

        This should listen for incoming messages and dispatch them.
        """
        pass

    async def stop(self) -> None:
        """Stop the adapter."""
        self._running = False
        await self.disconnect()

    def format_code_block(self, text: str, language: str = "") -> str:
        """Format text as a code block (platform-specific)."""
        return f"```{language}\n{text}\n```"

    def format_bold(self, text: str) -> str:
        """Format text as bold (platform-specific)."""
        return f"*{text}*"

    def format_italic(self, text: str) -> str:
        """Format text as italic (platform-specific)."""
        return f"_{text}_"

    def format_link(self, text: str, url: str) -> str:
        """Format a hyperlink (platform-specific)."""
        return f"<{url}|{text}>"

    def format_user_mention(self, user_id: str) -> str:
        """Format a user mention (platform-specific)."""
        return f"<@{user_id}>"
