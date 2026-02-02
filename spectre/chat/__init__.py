"""
SPECTRE Chat Interface Layer

Provides adapters for chat platforms (Slack, Discord, Telegram).
"""

from spectre.chat.adapter import (
    ChatAdapter,
    ChatChannel,
    ChatFile,
    ChatMessage,
    ChatResponse,
    ChatUser,
    MessageType,
)
from spectre.chat.handler import ChatHandler, ConversationPhase, ConversationState

__all__ = [
    # Adapter base
    "ChatAdapter",
    "ChatChannel",
    "ChatFile",
    "ChatMessage",
    "ChatResponse",
    "ChatUser",
    "MessageType",
    # Handler
    "ChatHandler",
    "ConversationPhase",
    "ConversationState",
]

# Platform-specific adapters are imported separately to avoid
# requiring all chat dependencies:
#
#   from spectre.chat.slack import SlackAdapter
#   from spectre.chat.discord import DiscordAdapter
#   from spectre.chat.telegram import TelegramAdapter
