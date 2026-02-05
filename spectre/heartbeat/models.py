"""
Heartbeat Models

Data models for watches, alerts, and monitoring state.
"""

from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from spectre.plugins.base import EntityType


class WatchType(str, Enum):
    """Types of watches."""

    DOMAIN = "domain"  # Monitor a domain for changes
    IP = "ip"  # Monitor an IP for changes
    SUBDOMAIN = "subdomain"  # Watch for new subdomains
    CERTIFICATE = "certificate"  # Watch for certificate changes
    THREAT_FEED = "threat_feed"  # Watch for IOC appearances
    CAMPAIGN = "campaign"  # Monitor a campaign for updates
    ACTOR = "actor"  # Monitor a threat actor for new intel
    CVE = "cve"  # Watch for new CVEs affecting a technology


class WatchStatus(str, Enum):
    """Status of a watch."""

    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"  # One-time watch finished
    FAILED = "failed"
    DISABLED = "disabled"


class AlertSeverity(str, Enum):
    """Alert severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertChannel(str, Enum):
    """Available alert channels."""

    CLI = "cli"  # Print to console
    SLACK = "slack"
    DISCORD = "discord"
    TELEGRAM = "telegram"
    WEBHOOK = "webhook"
    EMAIL = "email"


class WatchCondition(BaseModel):
    """A condition that triggers an alert."""

    field: str  # Field to check (e.g., "subdomains", "dns_records", "threat_level")
    operator: str  # Comparison operator: eq, ne, gt, lt, contains, not_contains, changed, new
    value: Any | None = None  # Expected value (not needed for 'changed' or 'new')
    severity: AlertSeverity = AlertSeverity.MEDIUM


class AlertConfig(BaseModel):
    """Configuration for how alerts are delivered."""

    channels: list[AlertChannel] = Field(default_factory=lambda: [AlertChannel.CLI])

    # Channel-specific settings
    slack_channel: str | None = None
    slack_webhook_url: str | None = None
    discord_channel_id: str | None = None
    discord_webhook_url: str | None = None
    telegram_chat_id: str | None = None
    webhook_url: str | None = None
    email_to: list[str] = Field(default_factory=list)

    # Alert behavior
    min_severity: AlertSeverity = AlertSeverity.INFO
    dedupe_window_minutes: int = 60  # Don't repeat same alert within this window
    include_diff: bool = True  # Include diff details in alert


class Watch(BaseModel):
    """
    A watch definition for continuous monitoring.

    Watches periodically check a target and compare results to baseline,
    triggering alerts when conditions are met.
    """

    # Identity
    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    description: str = ""

    # Target
    watch_type: WatchType
    target: str  # The entity to watch (domain, IP, campaign name, etc.)
    target_type: EntityType | None = None  # More specific entity type

    # Schedule
    interval_minutes: int = 360  # Default: 6 hours
    next_run: datetime | None = None

    # Conditions
    conditions: list[WatchCondition] = Field(default_factory=list)

    # Alerts
    alert_config: AlertConfig = Field(default_factory=AlertConfig)

    # State
    status: WatchStatus = WatchStatus.ACTIVE
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_run: datetime | None = None
    last_result_id: str | None = None
    run_count: int = 0
    alert_count: int = 0
    error_count: int = 0
    last_error: str | None = None

    # Owner/context
    owner: str | None = None  # User or system that created the watch
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def schedule_next_run(self) -> None:
        """Calculate and set the next run time."""
        self.next_run = datetime.now(timezone.utc) + timedelta(minutes=self.interval_minutes)

    def mark_run_started(self) -> None:
        """Mark that a run has started."""
        self.last_run = datetime.now(timezone.utc)
        self.run_count += 1

    def mark_run_completed(self, result_id: str) -> None:
        """Mark that a run completed successfully."""
        self.last_result_id = result_id
        self.last_error = None
        self.schedule_next_run()

    def mark_run_failed(self, error: str) -> None:
        """Mark that a run failed."""
        self.error_count += 1
        self.last_error = error
        self.schedule_next_run()

    def pause(self) -> None:
        """Pause the watch."""
        self.status = WatchStatus.PAUSED
        self.next_run = None

    def resume(self) -> None:
        """Resume a paused watch."""
        self.status = WatchStatus.ACTIVE
        self.schedule_next_run()

    @property
    def is_due(self) -> bool:
        """Check if the watch is due to run."""
        if self.status != WatchStatus.ACTIVE:
            return False
        if self.next_run is None:
            return True
        return datetime.now(timezone.utc) >= self.next_run


class WatchResultChange(BaseModel):
    """A detected change in a watch result."""

    field: str
    change_type: str  # "added", "removed", "modified"
    old_value: Any | None = None
    new_value: Any | None = None
    severity: AlertSeverity = AlertSeverity.INFO


class WatchResult(BaseModel):
    """Result of a single watch execution."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    watch_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Execution info
    success: bool = True
    error: str | None = None
    duration_seconds: float = 0.0

    # Data snapshot
    data: dict[str, Any] = Field(default_factory=dict)

    # Changes detected
    changes: list[WatchResultChange] = Field(default_factory=list)
    has_changes: bool = False

    # Alerts triggered
    alerts_triggered: int = 0

    @property
    def change_count(self) -> int:
        """Number of changes detected."""
        return len(self.changes)


class Alert(BaseModel):
    """An alert generated from a watch."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    watch_id: str
    watch_name: str
    result_id: str

    # Alert content
    title: str
    message: str
    severity: AlertSeverity

    # Context
    target: str
    watch_type: WatchType
    changes: list[WatchResultChange] = Field(default_factory=list)

    # Delivery
    channels: list[AlertChannel] = Field(default_factory=list)
    delivered_to: list[str] = Field(default_factory=list)  # Successfully delivered channels
    delivery_errors: dict[str, str] = Field(default_factory=dict)  # Channel -> error

    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    delivered_at: datetime | None = None
    acknowledged_at: datetime | None = None
    acknowledged_by: str | None = None

    def mark_delivered(self, channel: str) -> None:
        """Mark alert as delivered to a channel."""
        self.delivered_to.append(channel)
        if not self.delivered_at:
            self.delivered_at = datetime.now(timezone.utc)

    def mark_delivery_failed(self, channel: str, error: str) -> None:
        """Mark a delivery failure."""
        self.delivery_errors[channel] = error

    def acknowledge(self, by: str) -> None:
        """Acknowledge the alert."""
        self.acknowledged_at = datetime.now(timezone.utc)
        self.acknowledged_by = by
