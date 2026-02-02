"""
Slack Adapter

Chat adapter for Slack integration using Socket Mode.
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


class SlackAdapter(ChatAdapter):
    """
    Slack chat adapter using Socket Mode.

    Requires:
    - SLACK_BOT_TOKEN: Bot token (xoxb-...)
    - SLACK_APP_TOKEN: App-level token for Socket Mode (xapp-...)

    Install slack_sdk: pip install slack_sdk
    """

    name = "slack"
    description = "Slack workspace integration via Socket Mode"

    def __init__(
        self,
        bot_token: str,
        app_token: str,
    ) -> None:
        """
        Initialize Slack adapter.

        Args:
            bot_token: Slack bot token (xoxb-...)
            app_token: Slack app token for Socket Mode (xapp-...)
        """
        super().__init__()
        self.bot_token = bot_token
        self.app_token = app_token
        self._client: Any = None
        self._socket_client: Any = None

    async def connect(self) -> None:
        """Connect to Slack via Socket Mode."""
        try:
            from slack_sdk.web.async_client import AsyncWebClient
            from slack_sdk.socket_mode.aiohttp import SocketModeClient

            self._client = AsyncWebClient(token=self.bot_token)
            self._socket_client = SocketModeClient(
                app_token=self.app_token,
                web_client=self._client,
            )

            logger.info("Connected to Slack")

        except ImportError:
            raise ImportError(
                "slack_sdk is required for Slack integration. "
                "Install it with: pip install slack_sdk"
            )

    async def disconnect(self) -> None:
        """Disconnect from Slack."""
        if self._socket_client:
            await self._socket_client.close()
        logger.info("Disconnected from Slack")

    def _parse_slack_message(self, event: dict[str, Any]) -> ChatMessage | None:
        """Parse a Slack event into a ChatMessage."""
        # Skip bot messages
        if event.get("bot_id"):
            return None

        # Skip message edits and deletions
        subtype = event.get("subtype")
        if subtype in ("message_changed", "message_deleted"):
            return None

        user_id = event.get("user", "unknown")
        channel_id = event.get("channel", "unknown")
        text = event.get("text", "")
        ts = event.get("ts", "")
        thread_ts = event.get("thread_ts")

        # Determine message type
        if text.startswith("/"):
            msg_type = MessageType.COMMAND
        else:
            msg_type = MessageType.TEXT

        return ChatMessage(
            id=ts,
            text=text,
            user=ChatUser(
                id=user_id,
                name=user_id,  # Will be enriched later
                platform="slack",
            ),
            channel=ChatChannel(
                id=channel_id,
                name=channel_id,  # Will be enriched later
                platform="slack",
            ),
            timestamp=datetime.fromtimestamp(float(ts)) if ts else datetime.utcnow(),
            message_type=msg_type,
            thread_id=thread_ts if thread_ts != ts else None,
            attachments=event.get("files", []),
            metadata={"raw_event": event},
        )

    async def send_message(self, response: ChatResponse) -> str:
        """Send a message to Slack."""
        if not self._client:
            raise RuntimeError("Not connected to Slack")

        kwargs: dict[str, Any] = {
            "channel": response.channel_id,
            "text": response.text,
        }

        if response.thread_id:
            kwargs["thread_ts"] = response.thread_id

        if response.blocks:
            kwargs["blocks"] = response.blocks

        if response.attachments:
            kwargs["attachments"] = response.attachments

        if response.ephemeral and response.user_id:
            # Send ephemeral message only visible to user
            result = await self._client.chat_postEphemeral(
                user=response.user_id,
                **kwargs,
            )
        else:
            result = await self._client.chat_postMessage(**kwargs)

        return result.get("ts", "")

    async def send_file(
        self,
        channel_id: str,
        file: ChatFile,
        thread_id: str | None = None,
    ) -> str:
        """Upload a file to Slack."""
        if not self._client:
            raise RuntimeError("Not connected to Slack")

        kwargs: dict[str, Any] = {
            "channels": channel_id,
            "content": file.content.decode() if isinstance(file.content, bytes) else file.content,
            "filename": file.filename,
            "filetype": file.mimetype.split("/")[-1],
        }

        if file.title:
            kwargs["title"] = file.title

        if thread_id:
            kwargs["thread_ts"] = thread_id

        result = await self._client.files_upload_v2(**kwargs)
        return result.get("file", {}).get("id", "")

    async def update_message(
        self,
        channel_id: str,
        message_id: str,
        text: str,
    ) -> None:
        """Update an existing Slack message."""
        if not self._client:
            raise RuntimeError("Not connected to Slack")

        await self._client.chat_update(
            channel=channel_id,
            ts=message_id,
            text=text,
        )

    async def add_reaction(
        self,
        channel_id: str,
        message_id: str,
        emoji: str,
    ) -> None:
        """Add a reaction to a message."""
        if not self._client:
            raise RuntimeError("Not connected to Slack")

        # Remove colons if present
        emoji = emoji.strip(":")

        await self._client.reactions_add(
            channel=channel_id,
            timestamp=message_id,
            name=emoji,
        )

    async def run(self) -> None:
        """Start listening for Slack events."""
        if not self._socket_client:
            await self.connect()

        from slack_sdk.socket_mode.response import SocketModeResponse
        from slack_sdk.socket_mode.request import SocketModeRequest

        async def handle_event(client: Any, req: SocketModeRequest) -> None:
            """Handle incoming Socket Mode events."""
            # Acknowledge the event
            response = SocketModeResponse(envelope_id=req.envelope_id)
            await client.send_socket_mode_response(response)

            # Process message events
            if req.type == "events_api":
                event = req.payload.get("event", {})

                if event.get("type") == "message":
                    message = self._parse_slack_message(event)
                    if message:
                        try:
                            response = await self.dispatch(message)
                            if response:
                                await self.send_message(response)
                        except Exception as e:
                            logger.error(
                                "Error handling message",
                                error=str(e),
                            )

            # Handle slash commands
            elif req.type == "slash_commands":
                payload = req.payload
                message = ChatMessage(
                    id=payload.get("trigger_id", ""),
                    text=f"/{payload.get('command', '').lstrip('/')} {payload.get('text', '')}",
                    user=ChatUser(
                        id=payload.get("user_id", ""),
                        name=payload.get("user_name", ""),
                        platform="slack",
                    ),
                    channel=ChatChannel(
                        id=payload.get("channel_id", ""),
                        name=payload.get("channel_name", ""),
                        platform="slack",
                    ),
                    timestamp=datetime.utcnow(),
                    message_type=MessageType.COMMAND,
                )

                try:
                    response = await self.dispatch(message)
                    if response:
                        await self.send_message(response)
                except Exception as e:
                    logger.error("Error handling slash command", error=str(e))

        self._socket_client.socket_mode_request_listeners.append(handle_event)

        self._running = True
        logger.info("Slack adapter listening for events")

        await self._socket_client.connect()

        # Keep running until stopped
        while self._running:
            await asyncio.sleep(1)

    def format_code_block(self, text: str, language: str = "") -> str:
        """Format as Slack code block."""
        return f"```{language}\n{text}\n```"

    def format_bold(self, text: str) -> str:
        """Format as Slack bold."""
        return f"*{text}*"

    def format_italic(self, text: str) -> str:
        """Format as Slack italic."""
        return f"_{text}_"

    def format_link(self, text: str, url: str) -> str:
        """Format as Slack link."""
        return f"<{url}|{text}>"

    def format_user_mention(self, user_id: str) -> str:
        """Format as Slack user mention."""
        return f"<@{user_id}>"
