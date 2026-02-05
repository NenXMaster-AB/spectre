"""
Campaign Tracker

Tracks known campaigns and monitors for updates, new IOCs, and infrastructure changes.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger(__name__)


class CampaignStatus(str, Enum):
    """Status of a tracked campaign."""
    ACTIVE = "active"  # Currently ongoing
    DORMANT = "dormant"  # No recent activity
    CONCLUDED = "concluded"  # Campaign ended
    UNKNOWN = "unknown"


class CampaignSource(str, Enum):
    """Source of campaign data."""
    MITRE_ATTACK = "mitre_attack"
    OPENCTI = "opencti"
    ALIENVAULT_OTX = "alienvault_otx"
    MANUAL = "manual"
    DETECTED = "detected"  # Auto-detected by SPECTRE


class CampaignIOC(BaseModel):
    """An indicator of compromise associated with a campaign."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    type: str  # domain, ip, hash, url, email
    value: str
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    confidence: float = 0.7
    source: str = ""
    tags: list[str] = Field(default_factory=list)

    @property
    def is_active(self) -> bool:
        """Check if IOC was seen recently (within 30 days)."""
        if not self.last_seen:
            return False
        age = (datetime.now(timezone.utc) - self.last_seen).days
        return age <= 30


class CampaignTTP(BaseModel):
    """A TTP (MITRE ATT&CK technique) used in a campaign."""
    technique_id: str  # e.g., T1566.001
    technique_name: str
    tactic: str  # e.g., initial-access
    description: str = ""
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class Campaign(BaseModel):
    """
    A tracked threat campaign.

    Campaigns represent coordinated attack operations with defined
    objectives, timeframes, and target sets.
    """
    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    aliases: list[str] = Field(default_factory=list)
    description: str = ""

    # Attribution
    attributed_actors: list[str] = Field(default_factory=list)  # Threat actor names
    attribution_confidence: float = 0.0  # 0.0 - 1.0

    # Timeline
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    status: CampaignStatus = CampaignStatus.UNKNOWN

    # Targeting
    target_sectors: list[str] = Field(default_factory=list)
    target_regions: list[str] = Field(default_factory=list)
    target_organizations: list[str] = Field(default_factory=list)

    # Technical details
    iocs: list[CampaignIOC] = Field(default_factory=list)
    ttps: list[CampaignTTP] = Field(default_factory=list)
    malware_families: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)

    # Metadata
    source: CampaignSource = CampaignSource.MANUAL
    external_references: list[dict[str, str]] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    # Tracking
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_tracked: bool = False  # Active monitoring enabled

    @property
    def ioc_count(self) -> int:
        return len(self.iocs)

    @property
    def active_iocs(self) -> list[CampaignIOC]:
        return [ioc for ioc in self.iocs if ioc.is_active]

    @property
    def ttp_count(self) -> int:
        return len(self.ttps)

    def add_ioc(self, ioc: CampaignIOC) -> bool:
        """Add IOC if not duplicate."""
        existing = {f"{i.type}:{i.value}" for i in self.iocs}
        key = f"{ioc.type}:{ioc.value}"
        if key not in existing:
            self.iocs.append(ioc)
            self.updated_at = datetime.now(timezone.utc)
            return True
        return False

    def add_ttp(self, ttp: CampaignTTP) -> bool:
        """Add TTP if not duplicate."""
        existing = {t.technique_id for t in self.ttps}
        if ttp.technique_id not in existing:
            self.ttps.append(ttp)
            self.updated_at = datetime.now(timezone.utc)
            return True
        return False


class CampaignUpdate(BaseModel):
    """An update/change detected in a campaign."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    campaign_id: str
    campaign_name: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    update_type: str  # new_ioc, new_ttp, status_change, new_target, attribution_update
    description: str
    data: dict[str, Any] = Field(default_factory=dict)
    severity: str = "info"  # critical, high, medium, low, info


class CampaignTracker:
    """
    Tracks campaigns and monitors for updates.

    Provides:
    - Campaign CRUD operations
    - IOC matching against investigation findings
    - Campaign update detection
    - Integration with threat intel sources
    """

    def __init__(self) -> None:
        self._campaigns: dict[str, Campaign] = {}
        self._updates: list[CampaignUpdate] = []

        # Index for fast IOC lookups
        self._ioc_index: dict[str, set[str]] = {}  # ioc_value -> campaign_ids

    def add_campaign(self, campaign: Campaign) -> None:
        """Add or update a campaign."""
        self._campaigns[campaign.id] = campaign
        self._index_campaign_iocs(campaign)
        logger.info("Campaign added", campaign_id=campaign.id, name=campaign.name)

    def get_campaign(self, campaign_id: str) -> Campaign | None:
        """Get a campaign by ID."""
        return self._campaigns.get(campaign_id)

    def get_campaign_by_name(self, name: str) -> Campaign | None:
        """Get a campaign by name or alias."""
        name_lower = name.lower()
        for campaign in self._campaigns.values():
            if campaign.name.lower() == name_lower:
                return campaign
            if any(alias.lower() == name_lower for alias in campaign.aliases):
                return campaign
        return None

    def list_campaigns(
        self,
        status: CampaignStatus | None = None,
        tracked_only: bool = False,
        actor: str | None = None,
        limit: int = 100,
    ) -> list[Campaign]:
        """List campaigns with optional filtering."""
        campaigns = list(self._campaigns.values())

        if status:
            campaigns = [c for c in campaigns if c.status == status]
        if tracked_only:
            campaigns = [c for c in campaigns if c.is_tracked]
        if actor:
            actor_lower = actor.lower()
            campaigns = [
                c for c in campaigns
                if any(a.lower() == actor_lower for a in c.attributed_actors)
            ]

        # Sort by last_seen (most recent first)
        campaigns.sort(
            key=lambda c: c.last_seen or c.created_at,
            reverse=True
        )

        return campaigns[:limit]

    def search_campaigns(self, query: str) -> list[Campaign]:
        """Search campaigns by name, alias, or description."""
        query_lower = query.lower()
        results = []

        for campaign in self._campaigns.values():
            if query_lower in campaign.name.lower():
                results.append(campaign)
            elif any(query_lower in alias.lower() for alias in campaign.aliases):
                results.append(campaign)
            elif query_lower in campaign.description.lower():
                results.append(campaign)

        return results

    def match_ioc(self, ioc_type: str, ioc_value: str) -> list[Campaign]:
        """Find campaigns that have a matching IOC."""
        key = f"{ioc_type}:{ioc_value}".lower()
        campaign_ids = self._ioc_index.get(key, set())
        return [self._campaigns[cid] for cid in campaign_ids if cid in self._campaigns]

    def match_iocs(self, iocs: list[dict[str, str]]) -> dict[str, list[Campaign]]:
        """Match multiple IOCs against campaigns."""
        results: dict[str, list[Campaign]] = {}

        for ioc in iocs:
            ioc_type = ioc.get("type", "")
            ioc_value = ioc.get("value", "")
            if ioc_type and ioc_value:
                key = f"{ioc_type}:{ioc_value}"
                matches = self.match_ioc(ioc_type, ioc_value)
                if matches:
                    results[key] = matches

        return results

    def start_tracking(self, campaign_id: str) -> bool:
        """Enable active tracking for a campaign."""
        campaign = self._campaigns.get(campaign_id)
        if not campaign:
            return False
        campaign.is_tracked = True
        campaign.updated_at = datetime.now(timezone.utc)
        logger.info("Campaign tracking started", campaign_id=campaign_id)
        return True

    def stop_tracking(self, campaign_id: str) -> bool:
        """Disable tracking for a campaign."""
        campaign = self._campaigns.get(campaign_id)
        if not campaign:
            return False
        campaign.is_tracked = False
        campaign.updated_at = datetime.now(timezone.utc)
        logger.info("Campaign tracking stopped", campaign_id=campaign_id)
        return True

    def record_update(self, update: CampaignUpdate) -> None:
        """Record a campaign update."""
        self._updates.append(update)
        logger.info(
            "Campaign update recorded",
            campaign_id=update.campaign_id,
            update_type=update.update_type,
        )

    def get_updates(
        self,
        campaign_id: str | None = None,
        since: datetime | None = None,
        limit: int = 50,
    ) -> list[CampaignUpdate]:
        """Get campaign updates with optional filtering."""
        updates = self._updates

        if campaign_id:
            updates = [u for u in updates if u.campaign_id == campaign_id]
        if since:
            updates = [u for u in updates if u.timestamp >= since]

        # Sort by timestamp (most recent first)
        updates.sort(key=lambda u: u.timestamp, reverse=True)

        return updates[:limit]

    def _index_campaign_iocs(self, campaign: Campaign) -> None:
        """Index campaign IOCs for fast lookup."""
        for ioc in campaign.iocs:
            key = f"{ioc.type}:{ioc.value}".lower()
            if key not in self._ioc_index:
                self._ioc_index[key] = set()
            self._ioc_index[key].add(campaign.id)

    def import_from_mitre(self, campaign_data: dict[str, Any]) -> Campaign | None:
        """Import a campaign from MITRE ATT&CK STIX data."""
        try:
            campaign = Campaign(
                name=campaign_data.get("name", "Unknown"),
                description=campaign_data.get("description", ""),
                aliases=campaign_data.get("aliases", []),
                source=CampaignSource.MITRE_ATTACK,
                first_seen=_parse_datetime(campaign_data.get("first_seen")),
                last_seen=_parse_datetime(campaign_data.get("last_seen")),
                external_references=[
                    {"source": ref.get("source_name", ""), "url": ref.get("url", "")}
                    for ref in campaign_data.get("external_references", [])
                    if ref.get("url")
                ],
            )
            self.add_campaign(campaign)
            return campaign
        except Exception as e:
            logger.error("Failed to import MITRE campaign", error=str(e))
            return None


def _parse_datetime(value: str | None) -> datetime | None:
    """Parse datetime string."""
    if not value:
        return None
    try:
        # Handle ISO format
        if "T" in value:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


# Global tracker instance
_tracker: CampaignTracker | None = None


def get_campaign_tracker() -> CampaignTracker:
    """Get the global campaign tracker instance."""
    global _tracker
    if _tracker is None:
        _tracker = CampaignTracker()
    return _tracker
