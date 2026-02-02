"""
SpectrePlugin Abstract Base Class

Defines the contract that all SPECTRE plugins must implement.
Every data source, tool, and integration is a plugin following this interface.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EntityType(str, Enum):
    """Types of entities that plugins can process and produce."""

    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    EMAIL = "email"
    HASH = "hash"
    PERSON = "person"
    ORGANIZATION = "organization"
    CERTIFICATE = "certificate"
    VULNERABILITY = "vulnerability"
    THREAT_ACTOR = "threat_actor"
    INTRUSION_SET = "intrusion_set"
    CAMPAIGN = "campaign"
    ATTACK_PATTERN = "attack_pattern"
    MALWARE = "malware"
    TOOL = "tool"
    INFRASTRUCTURE = "infrastructure"
    URL = "url"
    ASN = "asn"


class PluginCategory(str, Enum):
    """Categories of plugins."""

    OSINT = "osint"
    THREAT_INTEL = "threat_intel"
    ADVERSARY = "adversary"
    CUSTOM = "custom"


@dataclass
class RateLimit:
    """Rate limiting configuration for a plugin."""

    requests_per_minute: int = 60
    requests_per_day: int | None = None
    concurrent_requests: int = 5
    retry_after_seconds: int = 60


class Finding(BaseModel):
    """A single finding/result from a plugin execution."""

    model_config = ConfigDict(extra="allow")

    type: str = Field(..., description="Type of finding (e.g., 'dns_record', 'whois_data')")
    data: dict[str, Any] = Field(default_factory=dict, description="Finding data")
    confidence: float = Field(
        default=1.0, ge=0.0, le=1.0, description="Confidence score (0-1)"
    )
    source: str = Field(..., description="Source plugin name")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    raw_response: dict[str, Any] | None = Field(
        default=None, description="Raw API/tool response for debugging"
    )


class PluginResult(BaseModel):
    """Result returned by a plugin execution."""

    model_config = ConfigDict(extra="allow")

    success: bool = Field(..., description="Whether the plugin execution succeeded")
    plugin_name: str = Field(..., description="Name of the plugin that produced this result")
    input_entity: dict[str, Any] = Field(..., description="The input entity that was processed")
    findings: list[Finding] = Field(default_factory=list, description="List of findings")
    entities_discovered: list[dict[str, Any]] = Field(
        default_factory=list, description="New entities discovered during execution"
    )
    error: str | None = Field(default=None, description="Error message if execution failed")
    execution_time_ms: float = Field(default=0.0, description="Execution time in milliseconds")
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    def add_finding(
        self,
        finding_type: str,
        data: dict[str, Any],
        confidence: float = 1.0,
        raw_response: dict[str, Any] | None = None,
    ) -> None:
        """Add a finding to the result."""
        self.findings.append(
            Finding(
                type=finding_type,
                data=data,
                confidence=confidence,
                source=self.plugin_name,
                raw_response=raw_response,
            )
        )

    def add_entity(self, entity_type: EntityType, entity_data: dict[str, Any]) -> None:
        """Add a discovered entity to the result."""
        self.entities_discovered.append({"type": entity_type.value, **entity_data})


@dataclass
class PluginConfig:
    """Configuration for a plugin instance."""

    api_key: str | None = None
    api_url: str | None = None
    timeout_seconds: int = 30
    extra: dict[str, Any] = field(default_factory=dict)


class SpectrePlugin(ABC):
    """
    Abstract base class for all SPECTRE plugins.

    Every data source, tool, and integration must implement this interface.
    Plugins are discovered via Python entry_points for pip-installable community plugins.

    Example implementation:
        class DNSReconPlugin(SpectrePlugin):
            name = "dns_recon"
            description = "Enumerate DNS records for a domain"
            category = PluginCategory.OSINT
            input_types = [EntityType.DOMAIN]
            output_types = [EntityType.IP_ADDRESS, EntityType.DOMAIN]

            async def execute(self, entity, config):
                # Implementation here
                pass

            async def health_check(self):
                return True
    """

    # Class attributes that subclasses must define
    name: str
    description: str
    category: PluginCategory
    input_types: list[EntityType]
    output_types: list[EntityType]
    required_config: list[str] = []
    rate_limit: RateLimit | None = None

    def __init__(self) -> None:
        """Initialize the plugin."""
        self._validate_class_attributes()

    def _validate_class_attributes(self) -> None:
        """Validate that required class attributes are defined."""
        required_attrs = ["name", "description", "category", "input_types", "output_types"]
        for attr in required_attrs:
            if not hasattr(self, attr) or getattr(self, attr) is None:
                raise ValueError(f"Plugin {self.__class__.__name__} must define '{attr}'")

    @abstractmethod
    async def execute(
        self,
        entity: dict[str, Any],
        config: PluginConfig | None = None,
    ) -> PluginResult:
        """
        Execute the plugin against the given entity.

        Args:
            entity: The input entity to process (dict with 'type' and entity-specific fields)
            config: Optional configuration (API keys, timeouts, etc.)

        Returns:
            PluginResult containing findings and any discovered entities
        """
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """
        Verify that the plugin can operate (API accessible, dependencies available).

        Returns:
            True if the plugin is healthy and ready to execute
        """
        ...

    def accepts_entity(self, entity_type: EntityType) -> bool:
        """Check if this plugin accepts the given entity type as input."""
        return entity_type in self.input_types

    def get_info(self) -> dict[str, Any]:
        """Get plugin information as a dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category.value,
            "input_types": [t.value for t in self.input_types],
            "output_types": [t.value for t in self.output_types],
            "required_config": self.required_config,
            "rate_limit": {
                "requests_per_minute": self.rate_limit.requests_per_minute,
                "requests_per_day": self.rate_limit.requests_per_day,
                "concurrent_requests": self.rate_limit.concurrent_requests,
            }
            if self.rate_limit
            else None,
        }

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(name={self.name!r})>"
