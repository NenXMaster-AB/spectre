"""
TTP Timeline

Temporal analysis of TTPs (Tactics, Techniques, and Procedures) to track
how threat actors and campaigns evolve their techniques over time.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class TTPChangeType(str, Enum):
    """Types of TTP changes observed."""
    NEW_TECHNIQUE = "new_technique"  # First observed use of technique
    DROPPED_TECHNIQUE = "dropped_technique"  # Technique no longer used
    INCREASED_USAGE = "increased_usage"  # More frequent use
    DECREASED_USAGE = "decreased_usage"  # Less frequent use
    TECHNIQUE_VARIATION = "technique_variation"  # Sub-technique change
    TACTIC_SHIFT = "tactic_shift"  # Shift in tactical focus


@dataclass
class TTPObservation:
    """A single observation of a TTP being used."""
    technique_id: str  # e.g., T1566.001
    technique_name: str
    tactic: str  # e.g., initial-access, execution
    timestamp: datetime
    source: str  # Where this was observed
    context: str = ""  # Additional context
    confidence: float = 1.0

    # Optional linking
    campaign_id: str | None = None
    actor_id: str | None = None
    investigation_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "context": self.context,
            "confidence": self.confidence,
            "campaign_id": self.campaign_id,
            "actor_id": self.actor_id,
            "investigation_id": self.investigation_id,
        }


@dataclass
class TTPChange:
    """A detected change in TTP usage."""
    change_type: TTPChangeType
    technique_id: str
    technique_name: str
    tactic: str
    detected_at: datetime
    description: str

    # Before/after state
    previous_observations: int = 0
    current_observations: int = 0
    time_window_days: int = 30

    # Context
    actor_id: str | None = None
    campaign_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "change_type": self.change_type.value,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "detected_at": self.detected_at.isoformat(),
            "description": self.description,
            "previous_observations": self.previous_observations,
            "current_observations": self.current_observations,
            "time_window_days": self.time_window_days,
            "actor_id": self.actor_id,
            "campaign_id": self.campaign_id,
        }


@dataclass
class TTPProfile:
    """TTP profile for a threat actor or campaign."""
    entity_id: str
    entity_type: str  # "actor" or "campaign"
    entity_name: str

    # Technique usage
    techniques: dict[str, list[TTPObservation]] = field(default_factory=dict)

    # By tactic
    tactics: dict[str, list[str]] = field(default_factory=dict)  # tactic -> technique_ids

    # Temporal bounds
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    # Analysis results
    primary_tactics: list[str] = field(default_factory=list)
    signature_techniques: list[str] = field(default_factory=list)  # Most distinctive TTPs

    def add_observation(self, obs: TTPObservation) -> None:
        """Add a TTP observation."""
        if obs.technique_id not in self.techniques:
            self.techniques[obs.technique_id] = []
        self.techniques[obs.technique_id].append(obs)

        # Update tactic mapping
        if obs.tactic not in self.tactics:
            self.tactics[obs.tactic] = []
        if obs.technique_id not in self.tactics[obs.tactic]:
            self.tactics[obs.tactic].append(obs.technique_id)

        # Update temporal bounds
        if self.first_seen is None or obs.timestamp < self.first_seen:
            self.first_seen = obs.timestamp
        if self.last_seen is None or obs.timestamp > self.last_seen:
            self.last_seen = obs.timestamp

    def get_technique_count(self, technique_id: str) -> int:
        """Get number of observations for a technique."""
        return len(self.techniques.get(technique_id, []))

    def get_active_techniques(self, within_days: int = 90) -> list[str]:
        """Get techniques observed within the time window."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=within_days)
        active = []
        for tech_id, observations in self.techniques.items():
            if any(obs.timestamp >= cutoff for obs in observations):
                active.append(tech_id)
        return active

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "entity_name": self.entity_name,
            "technique_count": len(self.techniques),
            "tactic_count": len(self.tactics),
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "primary_tactics": self.primary_tactics,
            "signature_techniques": self.signature_techniques,
            "techniques": {
                tech_id: [obs.to_dict() for obs in observations]
                for tech_id, observations in self.techniques.items()
            },
            "tactics": self.tactics,
        }


@dataclass
class TimelineEvent:
    """An event in a TTP timeline."""
    timestamp: datetime
    technique_id: str
    technique_name: str
    tactic: str
    event_type: str  # "observation", "change"
    description: str
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "event_type": self.event_type,
            "description": self.description,
            "data": self.data,
        }


@dataclass
class TTPComparison:
    """Comparison of TTPs between two entities."""
    entity_a_id: str
    entity_a_name: str
    entity_b_id: str
    entity_b_name: str

    # Overlap analysis
    shared_techniques: list[str] = field(default_factory=list)
    unique_to_a: list[str] = field(default_factory=list)
    unique_to_b: list[str] = field(default_factory=list)

    # Tactic comparison
    shared_tactics: list[str] = field(default_factory=list)

    # Similarity score
    jaccard_similarity: float = 0.0
    technique_overlap_ratio: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_a": {"id": self.entity_a_id, "name": self.entity_a_name},
            "entity_b": {"id": self.entity_b_id, "name": self.entity_b_name},
            "shared_techniques": self.shared_techniques,
            "unique_to_a": self.unique_to_a,
            "unique_to_b": self.unique_to_b,
            "shared_tactics": self.shared_tactics,
            "jaccard_similarity": self.jaccard_similarity,
            "technique_overlap_ratio": self.technique_overlap_ratio,
        }


class TTPTimeline:
    """
    Tracks and analyzes TTP usage over time.

    Provides:
    - Temporal TTP tracking for actors and campaigns
    - Change detection (new techniques, dropped techniques, shifts)
    - TTP evolution analysis
    - Actor/campaign TTP comparison
    """

    # Time windows for analysis
    RECENT_WINDOW_DAYS = 30
    ACTIVE_WINDOW_DAYS = 90
    HISTORICAL_WINDOW_DAYS = 365

    def __init__(self) -> None:
        # Profiles by entity
        self._actor_profiles: dict[str, TTPProfile] = {}
        self._campaign_profiles: dict[str, TTPProfile] = {}

        # All observations (for cross-entity analysis)
        self._all_observations: list[TTPObservation] = []

        # Detected changes
        self._changes: list[TTPChange] = []

    def record_observation(
        self,
        technique_id: str,
        technique_name: str,
        tactic: str,
        timestamp: datetime | None = None,
        source: str = "",
        context: str = "",
        confidence: float = 1.0,
        actor_id: str | None = None,
        actor_name: str | None = None,
        campaign_id: str | None = None,
        campaign_name: str | None = None,
        investigation_id: str | None = None,
    ) -> TTPObservation:
        """
        Record a TTP observation.

        Args:
            technique_id: MITRE ATT&CK technique ID (e.g., T1566.001)
            technique_name: Human-readable technique name
            tactic: MITRE ATT&CK tactic (e.g., initial-access)
            timestamp: When observed (defaults to now)
            source: Source of observation
            context: Additional context
            confidence: Confidence score (0-1)
            actor_id: Associated threat actor ID
            actor_name: Associated threat actor name
            campaign_id: Associated campaign ID
            campaign_name: Associated campaign name
            investigation_id: Associated investigation ID

        Returns:
            The recorded observation
        """
        obs = TTPObservation(
            technique_id=technique_id,
            technique_name=technique_name,
            tactic=tactic,
            timestamp=timestamp or datetime.now(timezone.utc),
            source=source,
            context=context,
            confidence=confidence,
            actor_id=actor_id,
            campaign_id=campaign_id,
            investigation_id=investigation_id,
        )

        self._all_observations.append(obs)

        # Add to actor profile
        if actor_id:
            if actor_id not in self._actor_profiles:
                self._actor_profiles[actor_id] = TTPProfile(
                    entity_id=actor_id,
                    entity_type="actor",
                    entity_name=actor_name or actor_id,
                )
            self._actor_profiles[actor_id].add_observation(obs)

        # Add to campaign profile
        if campaign_id:
            if campaign_id not in self._campaign_profiles:
                self._campaign_profiles[campaign_id] = TTPProfile(
                    entity_id=campaign_id,
                    entity_type="campaign",
                    entity_name=campaign_name or campaign_id,
                )
            self._campaign_profiles[campaign_id].add_observation(obs)

        logger.debug(
            "Recorded TTP observation",
            technique_id=technique_id,
            actor_id=actor_id,
            campaign_id=campaign_id,
        )

        return obs

    def get_actor_profile(self, actor_id: str) -> TTPProfile | None:
        """Get TTP profile for a threat actor."""
        return self._actor_profiles.get(actor_id)

    def get_campaign_profile(self, campaign_id: str) -> TTPProfile | None:
        """Get TTP profile for a campaign."""
        return self._campaign_profiles.get(campaign_id)

    def get_timeline(
        self,
        actor_id: str | None = None,
        campaign_id: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
    ) -> list[TimelineEvent]:
        """
        Get a timeline of TTP events.

        Args:
            actor_id: Filter by actor
            campaign_id: Filter by campaign
            since: Start of time range
            until: End of time range
            limit: Maximum events to return

        Returns:
            List of timeline events, sorted by timestamp
        """
        # Filter observations
        observations = self._all_observations

        if actor_id:
            observations = [o for o in observations if o.actor_id == actor_id]
        if campaign_id:
            observations = [o for o in observations if o.campaign_id == campaign_id]
        if since:
            observations = [o for o in observations if o.timestamp >= since]
        if until:
            observations = [o for o in observations if o.timestamp <= until]

        # Convert to timeline events
        events = [
            TimelineEvent(
                timestamp=obs.timestamp,
                technique_id=obs.technique_id,
                technique_name=obs.technique_name,
                tactic=obs.tactic,
                event_type="observation",
                description=f"Observed {obs.technique_name} ({obs.technique_id})",
                data={"source": obs.source, "context": obs.context},
            )
            for obs in observations
        ]

        # Add change events for the entity
        if actor_id:
            changes = [c for c in self._changes if c.actor_id == actor_id]
            for change in changes:
                if (not since or change.detected_at >= since) and (not until or change.detected_at <= until):
                    events.append(TimelineEvent(
                        timestamp=change.detected_at,
                        technique_id=change.technique_id,
                        technique_name=change.technique_name,
                        tactic=change.tactic,
                        event_type="change",
                        description=change.description,
                        data={"change_type": change.change_type.value},
                    ))

        # Sort by timestamp
        events.sort(key=lambda e: e.timestamp, reverse=True)

        return events[:limit]

    def detect_changes(
        self,
        actor_id: str | None = None,
        campaign_id: str | None = None,
        window_days: int = 30,
    ) -> list[TTPChange]:
        """
        Detect TTP changes within a time window.

        Args:
            actor_id: Actor to analyze
            campaign_id: Campaign to analyze
            window_days: Time window for comparison

        Returns:
            List of detected changes
        """
        profile = None
        if actor_id:
            profile = self._actor_profiles.get(actor_id)
        elif campaign_id:
            profile = self._campaign_profiles.get(campaign_id)

        if not profile:
            return []

        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(days=window_days)
        prior_cutoff = cutoff - timedelta(days=window_days)

        changes = []

        for tech_id, observations in profile.techniques.items():
            # Count observations in current and prior windows
            current_count = sum(1 for o in observations if o.timestamp >= cutoff)
            prior_count = sum(1 for o in observations if prior_cutoff <= o.timestamp < cutoff)

            # Determine the technique name and tactic from most recent observation
            recent_obs = max(observations, key=lambda o: o.timestamp)
            tech_name = recent_obs.technique_name
            tactic = recent_obs.tactic

            if prior_count == 0 and current_count > 0:
                # New technique
                changes.append(TTPChange(
                    change_type=TTPChangeType.NEW_TECHNIQUE,
                    technique_id=tech_id,
                    technique_name=tech_name,
                    tactic=tactic,
                    detected_at=now,
                    description=f"New technique observed: {tech_name} ({tech_id})",
                    previous_observations=prior_count,
                    current_observations=current_count,
                    time_window_days=window_days,
                    actor_id=actor_id,
                    campaign_id=campaign_id,
                ))
            elif prior_count > 0 and current_count == 0:
                # Dropped technique
                changes.append(TTPChange(
                    change_type=TTPChangeType.DROPPED_TECHNIQUE,
                    technique_id=tech_id,
                    technique_name=tech_name,
                    tactic=tactic,
                    detected_at=now,
                    description=f"Technique no longer observed: {tech_name} ({tech_id})",
                    previous_observations=prior_count,
                    current_observations=current_count,
                    time_window_days=window_days,
                    actor_id=actor_id,
                    campaign_id=campaign_id,
                ))
            elif current_count > prior_count * 1.5 and current_count >= 3:
                # Increased usage (50% increase, minimum 3 observations)
                changes.append(TTPChange(
                    change_type=TTPChangeType.INCREASED_USAGE,
                    technique_id=tech_id,
                    technique_name=tech_name,
                    tactic=tactic,
                    detected_at=now,
                    description=f"Increased usage of {tech_name} ({prior_count} -> {current_count})",
                    previous_observations=prior_count,
                    current_observations=current_count,
                    time_window_days=window_days,
                    actor_id=actor_id,
                    campaign_id=campaign_id,
                ))
            elif prior_count > 0 and current_count < prior_count * 0.5:
                # Decreased usage (50% decrease)
                changes.append(TTPChange(
                    change_type=TTPChangeType.DECREASED_USAGE,
                    technique_id=tech_id,
                    technique_name=tech_name,
                    tactic=tactic,
                    detected_at=now,
                    description=f"Decreased usage of {tech_name} ({prior_count} -> {current_count})",
                    previous_observations=prior_count,
                    current_observations=current_count,
                    time_window_days=window_days,
                    actor_id=actor_id,
                    campaign_id=campaign_id,
                ))

        # Store changes
        self._changes.extend(changes)

        return changes

    def detect_tactic_shift(
        self,
        actor_id: str | None = None,
        campaign_id: str | None = None,
        window_days: int = 30,
    ) -> TTPChange | None:
        """
        Detect if there's been a shift in tactical focus.

        Returns a TTPChange if a significant tactic shift is detected.
        """
        profile = None
        if actor_id:
            profile = self._actor_profiles.get(actor_id)
        elif campaign_id:
            profile = self._campaign_profiles.get(campaign_id)

        if not profile:
            return None

        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(days=window_days)
        prior_cutoff = cutoff - timedelta(days=window_days)

        # Count observations by tactic in each window
        current_tactics: dict[str, int] = defaultdict(int)
        prior_tactics: dict[str, int] = defaultdict(int)

        for observations in profile.techniques.values():
            for obs in observations:
                if obs.timestamp >= cutoff:
                    current_tactics[obs.tactic] += 1
                elif obs.timestamp >= prior_cutoff:
                    prior_tactics[obs.tactic] += 1

        if not current_tactics or not prior_tactics:
            return None

        # Find primary tactic in each window
        current_primary = max(current_tactics.keys(), key=lambda t: current_tactics[t])
        prior_primary = max(prior_tactics.keys(), key=lambda t: prior_tactics[t])

        if current_primary != prior_primary:
            change = TTPChange(
                change_type=TTPChangeType.TACTIC_SHIFT,
                technique_id="",
                technique_name="",
                tactic=current_primary,
                detected_at=now,
                description=f"Tactic shift from {prior_primary} to {current_primary}",
                previous_observations=prior_tactics[prior_primary],
                current_observations=current_tactics[current_primary],
                time_window_days=window_days,
                actor_id=actor_id,
                campaign_id=campaign_id,
            )
            self._changes.append(change)
            return change

        return None

    def compare_profiles(
        self,
        profile_a: TTPProfile,
        profile_b: TTPProfile,
    ) -> TTPComparison:
        """
        Compare TTP profiles of two entities.

        Args:
            profile_a: First profile
            profile_b: Second profile

        Returns:
            Comparison results
        """
        techniques_a = set(profile_a.techniques.keys())
        techniques_b = set(profile_b.techniques.keys())

        shared = techniques_a & techniques_b
        unique_a = techniques_a - techniques_b
        unique_b = techniques_b - techniques_a

        # Jaccard similarity
        union = techniques_a | techniques_b
        jaccard = len(shared) / len(union) if union else 0.0

        # Overlap ratio (what percentage of the smaller set is shared)
        smaller = min(len(techniques_a), len(techniques_b))
        overlap_ratio = len(shared) / smaller if smaller > 0 else 0.0

        # Tactic comparison
        tactics_a = set(profile_a.tactics.keys())
        tactics_b = set(profile_b.tactics.keys())
        shared_tactics = list(tactics_a & tactics_b)

        return TTPComparison(
            entity_a_id=profile_a.entity_id,
            entity_a_name=profile_a.entity_name,
            entity_b_id=profile_b.entity_id,
            entity_b_name=profile_b.entity_name,
            shared_techniques=list(shared),
            unique_to_a=list(unique_a),
            unique_to_b=list(unique_b),
            shared_tactics=shared_tactics,
            jaccard_similarity=jaccard,
            technique_overlap_ratio=overlap_ratio,
        )

    def get_technique_frequency(
        self,
        since: datetime | None = None,
        limit: int = 20,
    ) -> list[tuple[str, str, int]]:
        """
        Get most frequently observed techniques.

        Args:
            since: Start of time range
            limit: Maximum techniques to return

        Returns:
            List of (technique_id, technique_name, count) tuples
        """
        observations = self._all_observations
        if since:
            observations = [o for o in observations if o.timestamp >= since]

        # Count by technique
        counts: dict[str, int] = defaultdict(int)
        names: dict[str, str] = {}
        for obs in observations:
            counts[obs.technique_id] += 1
            names[obs.technique_id] = obs.technique_name

        # Sort by count
        sorted_techniques = sorted(counts.items(), key=lambda x: x[1], reverse=True)

        return [
            (tech_id, names.get(tech_id, ""), count)
            for tech_id, count in sorted_techniques[:limit]
        ]

    def get_trending_techniques(
        self,
        window_days: int = 30,
        limit: int = 10,
    ) -> list[tuple[str, str, float]]:
        """
        Get techniques with increasing usage.

        Args:
            window_days: Time window for comparison
            limit: Maximum techniques to return

        Returns:
            List of (technique_id, technique_name, growth_rate) tuples
        """
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(days=window_days)
        prior_cutoff = cutoff - timedelta(days=window_days)

        # Count in each window
        current: dict[str, int] = defaultdict(int)
        prior: dict[str, int] = defaultdict(int)
        names: dict[str, str] = {}

        for obs in self._all_observations:
            if obs.timestamp >= cutoff:
                current[obs.technique_id] += 1
            elif obs.timestamp >= prior_cutoff:
                prior[obs.technique_id] += 1
            names[obs.technique_id] = obs.technique_name

        # Calculate growth rates
        growth_rates: list[tuple[str, str, float]] = []
        for tech_id in set(current.keys()) | set(prior.keys()):
            curr = current.get(tech_id, 0)
            prev = prior.get(tech_id, 0)
            if prev > 0:
                rate = (curr - prev) / prev
            elif curr > 0:
                rate = 1.0  # New technique
            else:
                rate = 0.0
            growth_rates.append((tech_id, names.get(tech_id, ""), rate))

        # Sort by growth rate
        growth_rates.sort(key=lambda x: x[2], reverse=True)

        return growth_rates[:limit]

    def analyze_profile(self, profile: TTPProfile) -> dict[str, Any]:
        """
        Analyze a TTP profile to identify patterns.

        Returns analysis including primary tactics, signature techniques, etc.
        """
        # Count observations by tactic
        tactic_counts: dict[str, int] = defaultdict(int)
        for tech_id, observations in profile.techniques.items():
            for obs in observations:
                tactic_counts[obs.tactic] += len(observations)
                break  # Only count once per technique

        # Primary tactics (top 3)
        sorted_tactics = sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True)
        profile.primary_tactics = [t for t, _ in sorted_tactics[:3]]

        # Signature techniques (most used, unique to this actor)
        technique_counts = {
            tech_id: len(observations)
            for tech_id, observations in profile.techniques.items()
        }
        sorted_techniques = sorted(technique_counts.items(), key=lambda x: x[1], reverse=True)
        profile.signature_techniques = [t for t, _ in sorted_techniques[:5]]

        # Calculate activity periods
        if profile.first_seen and profile.last_seen:
            active_days = (profile.last_seen - profile.first_seen).days
        else:
            active_days = 0

        return {
            "entity_id": profile.entity_id,
            "entity_name": profile.entity_name,
            "total_techniques": len(profile.techniques),
            "total_tactics": len(profile.tactics),
            "total_observations": sum(len(obs) for obs in profile.techniques.values()),
            "primary_tactics": profile.primary_tactics,
            "signature_techniques": profile.signature_techniques,
            "tactic_distribution": dict(tactic_counts),
            "active_days": active_days,
            "first_seen": profile.first_seen.isoformat() if profile.first_seen else None,
            "last_seen": profile.last_seen.isoformat() if profile.last_seen else None,
        }


# Global timeline instance
_timeline: TTPTimeline | None = None


def get_ttp_timeline() -> TTPTimeline:
    """Get the global TTP timeline instance."""
    global _timeline
    if _timeline is None:
        _timeline = TTPTimeline()
    return _timeline
