"""
Chat Handler

Handles chat messages with conversation state and investigation context.
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

import structlog

from spectre.agent.planner import InvestigationPlan
from spectre.chat.adapter import ChatAdapter, ChatMessage, ChatResponse
from spectre.intel.enrichment import EnrichmentConfig, EnrichmentPipeline
from spectre.intel.report import ReportFormat, ReportGenerator
from spectre.plugins.registry import PluginRegistry

logger = structlog.get_logger(__name__)


class ConversationPhase(Enum):
    """Phases of a conversation."""

    IDLE = "idle"
    PLANNING = "planning"
    INVESTIGATING = "investigating"
    REPORTING = "reporting"
    AWAITING_INPUT = "awaiting_input"


@dataclass
class ConversationState:
    """State of an ongoing conversation."""

    user_id: str
    channel_id: str
    thread_id: str | None = None
    phase: ConversationPhase = ConversationPhase.IDLE
    current_target: str | None = None
    current_target_type: str | None = None
    investigation_plan: InvestigationPlan | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    message_count: int = 0

    def update(self) -> None:
        """Update the last activity timestamp."""
        self.updated_at = datetime.utcnow()
        self.message_count += 1

    @property
    def is_expired(self) -> bool:
        """Check if conversation has expired (30 min inactivity)."""
        return datetime.utcnow() - self.updated_at > timedelta(minutes=30)


class ConversationStore:
    """In-memory store for conversation states."""

    def __init__(self) -> None:
        self._conversations: dict[str, ConversationState] = {}

    def _key(self, user_id: str, channel_id: str, thread_id: str | None) -> str:
        """Generate storage key."""
        return f"{channel_id}:{thread_id or 'main'}:{user_id}"

    def get(
        self,
        user_id: str,
        channel_id: str,
        thread_id: str | None = None,
    ) -> ConversationState | None:
        """Get conversation state."""
        key = self._key(user_id, channel_id, thread_id)
        state = self._conversations.get(key)
        if state and state.is_expired:
            del self._conversations[key]
            return None
        return state

    def create(
        self,
        user_id: str,
        channel_id: str,
        thread_id: str | None = None,
    ) -> ConversationState:
        """Create new conversation state."""
        state = ConversationState(
            user_id=user_id,
            channel_id=channel_id,
            thread_id=thread_id,
        )
        key = self._key(user_id, channel_id, thread_id)
        self._conversations[key] = state
        return state

    def get_or_create(
        self,
        user_id: str,
        channel_id: str,
        thread_id: str | None = None,
    ) -> ConversationState:
        """Get existing or create new conversation."""
        state = self.get(user_id, channel_id, thread_id)
        if state is None:
            state = self.create(user_id, channel_id, thread_id)
        return state

    def delete(
        self,
        user_id: str,
        channel_id: str,
        thread_id: str | None = None,
    ) -> None:
        """Delete conversation state."""
        key = self._key(user_id, channel_id, thread_id)
        self._conversations.pop(key, None)

    def cleanup_expired(self) -> int:
        """Remove expired conversations. Returns count removed."""
        expired = [
            key for key, state in self._conversations.items()
            if state.is_expired
        ]
        for key in expired:
            del self._conversations[key]
        return len(expired)


class ChatHandler:
    """
    Main handler for chat messages.

    Manages conversation state and routes commands to appropriate handlers.
    """

    # Available commands
    COMMANDS = {
        "investigate": "Start an investigation on a target",
        "enrich": "Quick enrichment of an entity",
        "status": "Check status of current investigation",
        "report": "Generate a report of findings",
        "cancel": "Cancel current investigation",
        "help": "Show available commands",
        "actors": "List known threat actors",
        "attribution": "Run attribution analysis on findings",
    }

    def __init__(
        self,
        registry: PluginRegistry | None = None,
        enrichment_config: EnrichmentConfig | None = None,
    ) -> None:
        """Initialize the chat handler."""
        self.registry = registry or PluginRegistry()
        self.registry.discover_plugins()
        self.enrichment_config = enrichment_config or EnrichmentConfig()
        self.conversations = ConversationStore()
        self.report_generator = ReportGenerator()

    def _detect_entity_type(self, target: str) -> str:
        """Detect entity type from target string."""
        import re

        target = target.strip()

        # IP address
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
            return "ip_address"

        # Hash (MD5, SHA1, SHA256)
        if re.match(r"^[a-fA-F0-9]{32}$", target):
            return "hash"  # MD5
        if re.match(r"^[a-fA-F0-9]{40}$", target):
            return "hash"  # SHA1
        if re.match(r"^[a-fA-F0-9]{64}$", target):
            return "hash"  # SHA256

        # Email
        if "@" in target and "." in target.split("@")[-1]:
            return "email"

        # URL
        if target.startswith(("http://", "https://")):
            return "url"

        # Default to domain
        return "domain"

    async def handle_message(self, message: ChatMessage) -> ChatResponse:
        """
        Handle an incoming chat message.

        Args:
            message: Incoming message

        Returns:
            Response to send
        """
        # Get or create conversation state
        state = self.conversations.get_or_create(
            message.user.id,
            message.channel.id,
            message.thread_id,
        )
        state.update()

        # Handle commands
        if message.is_command:
            command = message.command_name
            if command:
                return await self._handle_command(command, message, state)

        # Handle non-command messages based on conversation phase
        return await self._handle_message_in_context(message, state)

    async def _handle_command(
        self,
        command: str,
        message: ChatMessage,
        state: ConversationState,
    ) -> ChatResponse:
        """Handle a command message."""
        command = command.lower()

        handlers = {
            "investigate": self._cmd_investigate,
            "enrich": self._cmd_enrich,
            "status": self._cmd_status,
            "report": self._cmd_report,
            "cancel": self._cmd_cancel,
            "help": self._cmd_help,
            "actors": self._cmd_actors,
            "attribution": self._cmd_attribution,
        }

        handler = handlers.get(command)
        if handler:
            return await handler(message, state)

        return ChatResponse(
            text=f"Unknown command: `/{command}`. Use `/help` to see available commands.",
            channel_id=message.channel.id,
            thread_id=message.thread_id,
        )

    async def _handle_message_in_context(
        self,
        message: ChatMessage,
        state: ConversationState,
    ) -> ChatResponse:
        """Handle a non-command message based on conversation context."""
        if state.phase == ConversationPhase.AWAITING_INPUT:
            # User is providing input we asked for
            return await self._handle_user_input(message, state)

        if state.phase == ConversationPhase.IDLE:
            # Treat as a natural language query
            return await self._handle_natural_query(message, state)

        # In other phases, provide status
        return await self._cmd_status(message, state)

    async def _handle_natural_query(
        self,
        message: ChatMessage,
        state: ConversationState,
    ) -> ChatResponse:
        """Handle a natural language query."""
        text = message.text.strip()

        # Try to detect if it's an investigation request
        if any(word in text.lower() for word in ["investigate", "check", "lookup", "scan", "analyze"]):
            # Extract potential target from message
            words = text.split()
            for word in words:
                if self._detect_entity_type(word) != "domain" or "." in word:
                    # Found potential target
                    return await self._start_investigation(word, message, state)

        return ChatResponse(
            text=(
                "I can help you investigate domains, IPs, hashes, and other entities. "
                "Try `/investigate <target>` or just tell me what you'd like to look into.\n\n"
                "Example: `/investigate example.com`"
            ),
            channel_id=message.channel.id,
            thread_id=message.thread_id,
        )

    async def _handle_user_input(
        self,
        message: ChatMessage,
        state: ConversationState,
    ) -> ChatResponse:
        """Handle input we were waiting for."""
        # Reset to idle after processing
        state.phase = ConversationPhase.IDLE

        # For now, treat as a new investigation target
        target = message.text.strip()
        return await self._start_investigation(target, message, state)

    async def _start_investigation(
        self,
        target: str,
        message: ChatMessage,
        state: ConversationState,
    ) -> ChatResponse:
        """Start an investigation on a target."""
        entity_type = self._detect_entity_type(target)

        state.current_target = target
        state.current_target_type = entity_type
        state.phase = ConversationPhase.INVESTIGATING
        state.findings = []

        # Create enrichment pipeline
        pipeline = EnrichmentPipeline(
            registry=self.registry,
            config=self.enrichment_config,
        )

        entity = {"type": entity_type, "value": target}

        # Send initial response
        initial_response = ChatResponse(
            text=f":mag: Starting investigation on `{target}` ({entity_type})...",
            channel_id=message.channel.id,
            thread_id=message.thread_id,
        )

        # Run enrichment (this would ideally be async with progress updates)
        try:
            result = await pipeline.enrich(entity)

            state.findings = result.all_findings
            state.context["enrichment_result"] = result
            state.phase = ConversationPhase.IDLE

            # Build response
            if result.is_malicious:
                emoji = ":rotating_light:"
                threat_msg = f"*MALICIOUS* - Threat Level: {result.threat_level.upper()}"
            elif result.threat_level in ("medium", "low"):
                emoji = ":warning:"
                threat_msg = f"Threat Level: {result.threat_level.upper()}"
            else:
                emoji = ":white_check_mark:"
                threat_msg = "No threats detected"

            findings_summary = []
            for finding in result.all_findings[:5]:
                finding_type = finding.get("finding_type", "unknown")
                findings_summary.append(f"• {finding_type}")

            response_text = (
                f"{emoji} *Investigation Complete: {target}*\n\n"
                f"{threat_msg}\n"
                f"Confidence: {result.confidence_score:.0%}\n\n"
                f"*Findings ({len(result.all_findings)} total):*\n"
                + "\n".join(findings_summary)
            )

            if len(result.all_findings) > 5:
                response_text += f"\n... and {len(result.all_findings) - 5} more"

            response_text += "\n\nUse `/report` to generate a detailed report."

            return ChatResponse(
                text=response_text,
                channel_id=message.channel.id,
                thread_id=message.thread_id,
            )

        except Exception as e:
            logger.error("Investigation failed", target=target, error=str(e))
            state.phase = ConversationPhase.IDLE
            return ChatResponse(
                text=f":x: Investigation failed: {e}",
                channel_id=message.channel.id,
                thread_id=message.thread_id,
            )

    async def _cmd_investigate(
        self,
        message: ChatMessage,
        state: ConversationState,
    ) -> ChatResponse:
        """Handle /investigate command."""
        args = message.command_args.strip()

        if not args:
            state.phase = ConversationPhase.AWAITING_INPUT
            return ChatResponse(
                text="What would you like to investigate? Provide a domain, IP, hash, or URL.",
                channel_id=message.channel.id,
                thread_id=message.thread_id,
            )

        return await self._start_investigation(args, message, state)

    async def _cmd_enrich(
        self,
        message: ChatMessage,
        state: ConversationState,
    ) -> ChatResponse:
        """Handle /enrich command (quick enrichment)."""
        args = message.command_args.strip()

        if not args:
            return ChatResponse(
                text="Usage: `/enrich <target>` - Quick enrichment of an entity",
                channel_id=message.channel.id,
                thread_id=message.thread_id,
            )

        # Same as investigate for now
        return await self._start_investigation(args, message, state)

    async def _cmd_status(
        self,
        message: ChatMessage,
        state: ConversationState,
    ) -> ChatResponse:
        """Handle /status command."""
        if state.phase == ConversationPhase.IDLE:
            text = ":information_source: No active investigation."
            if state.current_target:
                text += f"\nLast target: `{state.current_target}`"
                text += f"\nFindings: {len(state.findings)}"
        elif state.phase == ConversationPhase.INVESTIGATING:
            text = f":hourglass: Investigation in progress: `{state.current_target}`"
        else:
            text = f":speech_balloon: Current phase: {state.phase.value}"

        return ChatResponse(
            text=text,
            channel_id=message.channel.id,
            thread_id=message.thread_id,
        )

    async def _cmd_report(
        self,
        message: ChatMessage,
        state: ConversationState,
    ) -> ChatResponse:
        """Handle /report command."""
        if not state.current_target or not state.findings:
            return ChatResponse(
                text=":x: No investigation data to report. Run `/investigate` first.",
                channel_id=message.channel.id,
                thread_id=message.thread_id,
            )

        enrichment_result = state.context.get("enrichment_result")

        report = self.report_generator.generate_report(
            target=state.current_target,
            target_type=state.current_target_type or "unknown",
            enrichment=enrichment_result,
        )

        # Format as markdown (most chat platforms support this)
        report_text = self.report_generator.format_report(
            report, ReportFormat.MARKDOWN
        )

        # Truncate if too long for chat
        if len(report_text) > 3000:
            report_text = report_text[:2900] + "\n\n... (report truncated)"

        return ChatResponse(
            text=report_text,
            channel_id=message.channel.id,
            thread_id=message.thread_id,
        )

    async def _cmd_cancel(
        self,
        message: ChatMessage,
        state: ConversationState,
    ) -> ChatResponse:
        """Handle /cancel command."""
        if state.phase in (ConversationPhase.IDLE, ConversationPhase.AWAITING_INPUT):
            return ChatResponse(
                text=":information_source: Nothing to cancel.",
                channel_id=message.channel.id,
                thread_id=message.thread_id,
            )

        old_target = state.current_target
        state.phase = ConversationPhase.IDLE
        state.current_target = None
        state.findings = []

        return ChatResponse(
            text=f":stop_sign: Cancelled investigation on `{old_target}`.",
            channel_id=message.channel.id,
            thread_id=message.thread_id,
        )

    async def _cmd_help(
        self,
        message: ChatMessage,
        state: ConversationState,
    ) -> ChatResponse:
        """Handle /help command."""
        lines = [
            ":book: *SPECTRE Commands*\n",
        ]

        for cmd, desc in self.COMMANDS.items():
            lines.append(f"`/{cmd}` - {desc}")

        lines.append("\n*Examples:*")
        lines.append("`/investigate example.com` - Investigate a domain")
        lines.append("`/enrich 8.8.8.8` - Quick IP enrichment")
        lines.append("`/actors` - List known threat actors")

        return ChatResponse(
            text="\n".join(lines),
            channel_id=message.channel.id,
            thread_id=message.thread_id,
        )

    async def _cmd_actors(
        self,
        message: ChatMessage,
        state: ConversationState,
    ) -> ChatResponse:
        """Handle /actors command - list known threat actors."""
        from spectre.intel.attribution import AttributionPipeline

        pipeline = AttributionPipeline()
        actors = pipeline.list_actors()

        lines = [":bust_in_silhouette: *Known Threat Actors*\n"]

        for actor in actors:
            aliases = ", ".join(actor.aliases[:3])
            country = f" [{actor.attribution_country}]" if actor.attribution_country else ""
            lines.append(f"• *{actor.name}*{country} ({aliases})")

        lines.append(f"\n_{len(actors)} actors in database_")

        return ChatResponse(
            text="\n".join(lines),
            channel_id=message.channel.id,
            thread_id=message.thread_id,
        )

    async def _cmd_attribution(
        self,
        message: ChatMessage,
        state: ConversationState,
    ) -> ChatResponse:
        """Handle /attribution command - run attribution analysis."""
        if not state.findings:
            return ChatResponse(
                text=":x: No findings to analyze. Run `/investigate` first.",
                channel_id=message.channel.id,
                thread_id=message.thread_id,
            )

        from spectre.intel.attribution import AttributionPipeline

        # Extract data from findings
        malware_families = []
        tools = []

        for finding in state.findings:
            data = finding.get("data", {})
            if "malware" in data:
                malware_families.append(data["malware"])
            if "malware_families" in data:
                malware_families.extend(data["malware_families"])

        pipeline = AttributionPipeline()
        results = pipeline.attribute(
            malware_families=malware_families,
            tools=tools,
            min_score=0.05,
        )

        if not results:
            return ChatResponse(
                text=":thinking_face: No attribution matches found for current findings.",
                channel_id=message.channel.id,
                thread_id=message.thread_id,
            )

        lines = [":detective: *Attribution Analysis*\n"]

        for i, result in enumerate(results[:3]):
            confidence_emoji = (
                ":green_circle:" if result.confidence == "high"
                else ":yellow_circle:" if result.confidence == "medium"
                else ":white_circle:"
            )
            lines.append(
                f"{i + 1}. *{result.actor.name}* - "
                f"{result.overall_score:.0%} {confidence_emoji}"
            )
            if result.actor.attribution_country:
                lines.append(f"   Country: {result.actor.attribution_country}")

        return ChatResponse(
            text="\n".join(lines),
            channel_id=message.channel.id,
            thread_id=message.thread_id,
        )

    def register_with_adapter(self, adapter: ChatAdapter) -> None:
        """
        Register this handler with a chat adapter.

        Args:
            adapter: The chat adapter to register with
        """
        # Register all commands
        for command in self.COMMANDS:
            adapter.register_command(
                command,
                lambda msg, cmd=command: self.handle_message(msg),
            )

        # Set as default handler for non-commands
        adapter.set_default_handler(self.handle_message)

        logger.info(
            "Registered chat handler",
            adapter=adapter.name,
            commands=list(self.COMMANDS.keys()),
        )
