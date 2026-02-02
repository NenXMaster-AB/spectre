"""Tests for the SPECTRE chat interface layer."""

from datetime import datetime

import pytest

from spectre.chat.adapter import (
    ChatAdapter,
    ChatChannel,
    ChatFile,
    ChatMessage,
    ChatResponse,
    ChatUser,
    MessageType,
)
from spectre.chat.handler import (
    ChatHandler,
    ConversationPhase,
    ConversationState,
    ConversationStore,
)


class TestChatMessage:
    """Tests for ChatMessage."""

    def test_is_command_with_slash(self) -> None:
        """Test command detection with slash prefix."""
        message = ChatMessage(
            id="1",
            text="/investigate example.com",
            user=ChatUser(id="u1", name="test"),
            channel=ChatChannel(id="c1", name="general"),
            timestamp=datetime.utcnow(),
        )
        assert message.is_command is True

    def test_is_not_command(self) -> None:
        """Test non-command message."""
        message = ChatMessage(
            id="1",
            text="Hello world",
            user=ChatUser(id="u1", name="test"),
            channel=ChatChannel(id="c1", name="general"),
            timestamp=datetime.utcnow(),
        )
        assert message.is_command is False

    def test_command_name_extraction(self) -> None:
        """Test extracting command name."""
        message = ChatMessage(
            id="1",
            text="/investigate example.com",
            user=ChatUser(id="u1", name="test"),
            channel=ChatChannel(id="c1", name="general"),
            timestamp=datetime.utcnow(),
        )
        assert message.command_name == "investigate"

    def test_command_args_extraction(self) -> None:
        """Test extracting command arguments."""
        message = ChatMessage(
            id="1",
            text="/investigate example.com",
            user=ChatUser(id="u1", name="test"),
            channel=ChatChannel(id="c1", name="general"),
            timestamp=datetime.utcnow(),
        )
        assert message.command_args == "example.com"

    def test_command_no_args(self) -> None:
        """Test command with no arguments."""
        message = ChatMessage(
            id="1",
            text="/help",
            user=ChatUser(id="u1", name="test"),
            channel=ChatChannel(id="c1", name="general"),
            timestamp=datetime.utcnow(),
        )
        assert message.command_name == "help"
        assert message.command_args == ""


class TestConversationState:
    """Tests for ConversationState."""

    def test_initial_state(self) -> None:
        """Test initial conversation state."""
        state = ConversationState(
            user_id="u1",
            channel_id="c1",
        )
        assert state.phase == ConversationPhase.IDLE
        assert state.current_target is None
        assert state.findings == []
        assert state.message_count == 0

    def test_update_increments_count(self) -> None:
        """Test that update increments message count."""
        state = ConversationState(
            user_id="u1",
            channel_id="c1",
        )
        state.update()
        assert state.message_count == 1
        state.update()
        assert state.message_count == 2

    def test_is_expired(self) -> None:
        """Test expiration detection."""
        from datetime import timedelta

        state = ConversationState(
            user_id="u1",
            channel_id="c1",
        )
        assert state.is_expired is False

        # Manually set old timestamp
        state.updated_at = datetime.utcnow() - timedelta(minutes=31)
        assert state.is_expired is True


class TestConversationStore:
    """Tests for ConversationStore."""

    def test_create_and_get(self) -> None:
        """Test creating and retrieving conversation."""
        store = ConversationStore()
        state = store.create("u1", "c1")
        assert state is not None

        retrieved = store.get("u1", "c1")
        assert retrieved is state

    def test_get_nonexistent(self) -> None:
        """Test getting nonexistent conversation."""
        store = ConversationStore()
        state = store.get("u1", "c1")
        assert state is None

    def test_get_or_create_creates(self) -> None:
        """Test get_or_create creates new state."""
        store = ConversationStore()
        state = store.get_or_create("u1", "c1")
        assert state is not None
        assert state.user_id == "u1"

    def test_get_or_create_returns_existing(self) -> None:
        """Test get_or_create returns existing state."""
        store = ConversationStore()
        state1 = store.create("u1", "c1")
        state2 = store.get_or_create("u1", "c1")
        assert state1 is state2

    def test_delete(self) -> None:
        """Test deleting conversation."""
        store = ConversationStore()
        store.create("u1", "c1")
        store.delete("u1", "c1")
        assert store.get("u1", "c1") is None

    def test_thread_isolation(self) -> None:
        """Test that different threads have different states."""
        store = ConversationStore()
        state1 = store.create("u1", "c1", "t1")
        state2 = store.create("u1", "c1", "t2")
        assert state1 is not state2


class TestChatHandler:
    """Tests for ChatHandler."""

    def test_detect_entity_type_ip(self) -> None:
        """Test IP address detection."""
        handler = ChatHandler()
        assert handler._detect_entity_type("8.8.8.8") == "ip_address"

    def test_detect_entity_type_domain(self) -> None:
        """Test domain detection."""
        handler = ChatHandler()
        assert handler._detect_entity_type("example.com") == "domain"

    def test_detect_entity_type_hash_md5(self) -> None:
        """Test MD5 hash detection."""
        handler = ChatHandler()
        assert handler._detect_entity_type("d41d8cd98f00b204e9800998ecf8427e") == "hash"

    def test_detect_entity_type_hash_sha256(self) -> None:
        """Test SHA256 hash detection."""
        handler = ChatHandler()
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert handler._detect_entity_type(sha256) == "hash"

    def test_detect_entity_type_email(self) -> None:
        """Test email detection."""
        handler = ChatHandler()
        assert handler._detect_entity_type("test@example.com") == "email"

    def test_detect_entity_type_url(self) -> None:
        """Test URL detection."""
        handler = ChatHandler()
        assert handler._detect_entity_type("https://example.com/path") == "url"

    def test_commands_defined(self) -> None:
        """Test that commands are defined."""
        handler = ChatHandler()
        assert "investigate" in handler.COMMANDS
        assert "enrich" in handler.COMMANDS
        assert "help" in handler.COMMANDS
        assert "report" in handler.COMMANDS

    @pytest.mark.asyncio
    async def test_handle_help_command(self) -> None:
        """Test handling /help command."""
        handler = ChatHandler()
        message = ChatMessage(
            id="1",
            text="/help",
            user=ChatUser(id="u1", name="test"),
            channel=ChatChannel(id="c1", name="general"),
            timestamp=datetime.utcnow(),
            message_type=MessageType.COMMAND,
        )

        response = await handler.handle_message(message)
        assert response is not None
        assert "Commands" in response.text or "commands" in response.text.lower()

    @pytest.mark.asyncio
    async def test_handle_actors_command(self) -> None:
        """Test handling /actors command."""
        handler = ChatHandler()
        message = ChatMessage(
            id="1",
            text="/actors",
            user=ChatUser(id="u1", name="test"),
            channel=ChatChannel(id="c1", name="general"),
            timestamp=datetime.utcnow(),
            message_type=MessageType.COMMAND,
        )

        response = await handler.handle_message(message)
        assert response is not None
        assert "APT" in response.text or "actors" in response.text.lower()

    @pytest.mark.asyncio
    async def test_handle_status_idle(self) -> None:
        """Test handling /status with no active investigation."""
        handler = ChatHandler()
        message = ChatMessage(
            id="1",
            text="/status",
            user=ChatUser(id="u1", name="test"),
            channel=ChatChannel(id="c1", name="general"),
            timestamp=datetime.utcnow(),
            message_type=MessageType.COMMAND,
        )

        response = await handler.handle_message(message)
        assert response is not None
        assert "No active investigation" in response.text

    @pytest.mark.asyncio
    async def test_handle_unknown_command(self) -> None:
        """Test handling unknown command."""
        handler = ChatHandler()
        message = ChatMessage(
            id="1",
            text="/unknowncommand",
            user=ChatUser(id="u1", name="test"),
            channel=ChatChannel(id="c1", name="general"),
            timestamp=datetime.utcnow(),
            message_type=MessageType.COMMAND,
        )

        response = await handler.handle_message(message)
        assert response is not None
        assert "Unknown command" in response.text

    @pytest.mark.asyncio
    async def test_handle_report_no_data(self) -> None:
        """Test handling /report with no investigation data."""
        handler = ChatHandler()
        message = ChatMessage(
            id="1",
            text="/report",
            user=ChatUser(id="u1", name="test"),
            channel=ChatChannel(id="c1", name="general"),
            timestamp=datetime.utcnow(),
            message_type=MessageType.COMMAND,
        )

        response = await handler.handle_message(message)
        assert response is not None
        assert "No investigation data" in response.text or "Run" in response.text


class TestChatResponse:
    """Tests for ChatResponse."""

    def test_basic_response(self) -> None:
        """Test basic response creation."""
        response = ChatResponse(
            text="Hello world",
            channel_id="c1",
        )
        assert response.text == "Hello world"
        assert response.channel_id == "c1"
        assert response.thread_id is None

    def test_threaded_response(self) -> None:
        """Test threaded response."""
        response = ChatResponse(
            text="Reply",
            channel_id="c1",
            thread_id="t1",
        )
        assert response.thread_id == "t1"

    def test_ephemeral_response(self) -> None:
        """Test ephemeral response."""
        response = ChatResponse(
            text="Only you can see this",
            channel_id="c1",
            ephemeral=True,
            user_id="u1",
        )
        assert response.ephemeral is True
        assert response.user_id == "u1"
