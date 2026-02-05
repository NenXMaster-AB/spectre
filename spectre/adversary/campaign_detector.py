"""
Campaign Detector

AI-powered clustering to detect unreported campaigns from investigation findings.
Uses multiple signals: temporal patterns, infrastructure overlap, TTP consistency,
tooling fingerprints, and victimology patterns.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

import structlog

from spectre.adversary.campaign_tracker import (
    Campaign,
    CampaignIOC,
    CampaignSource,
    CampaignStatus,
    CampaignTTP,
    get_campaign_tracker,
)

logger = structlog.get_logger(__name__)


class ClusterSignal(str, Enum):
    """Types of signals used for campaign clustering."""
    TEMPORAL = "temporal"  # Multiple targets hit within time window
    INFRASTRUCTURE = "infrastructure"  # Shared C2, registrants, hosting
    TTP = "ttp"  # Same attack patterns/techniques
    TOOLING = "tooling"  # Same malware families or tools
    VICTIMOLOGY = "victimology"  # Same sector/geography targets


@dataclass
class ClusterEvidence:
    """Evidence supporting a cluster signal."""
    signal_type: ClusterSignal
    description: str
    confidence: float  # 0.0 - 1.0
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "signal_type": self.signal_type.value,
            "description": self.description,
            "confidence": self.confidence,
            "data": self.data,
        }


@dataclass
class InvestigationFindings:
    """Findings from an investigation to be clustered."""
    id: str
    target: str  # Primary target (domain, IP, org)
    timestamp: datetime

    # IOCs discovered
    domains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    hashes: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)

    # Infrastructure signals
    registrars: list[str] = field(default_factory=list)
    hosting_providers: list[str] = field(default_factory=list)
    ssl_issuers: list[str] = field(default_factory=list)
    nameservers: list[str] = field(default_factory=list)

    # TTP signals
    techniques: list[str] = field(default_factory=list)  # MITRE ATT&CK IDs

    # Tooling signals
    malware_families: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)

    # Victimology
    sector: str | None = None
    region: str | None = None
    organization: str | None = None

    # Additional context
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class DetectedCluster:
    """A detected potential campaign cluster."""
    id: str
    name: str  # Auto-generated name
    created_at: datetime

    # Cluster members
    investigation_ids: list[str] = field(default_factory=list)
    targets: list[str] = field(default_factory=list)

    # Supporting evidence
    evidence: list[ClusterEvidence] = field(default_factory=list)

    # Aggregated IOCs
    shared_domains: list[str] = field(default_factory=list)
    shared_ips: list[str] = field(default_factory=list)
    shared_hashes: list[str] = field(default_factory=list)

    # Aggregated signals
    shared_techniques: list[str] = field(default_factory=list)
    shared_malware: list[str] = field(default_factory=list)
    shared_tools: list[str] = field(default_factory=list)

    # Scoring
    overall_confidence: float = 0.0
    signal_scores: dict[str, float] = field(default_factory=dict)

    # Temporal bounds
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "created_at": self.created_at.isoformat(),
            "investigation_count": len(self.investigation_ids),
            "targets": self.targets,
            "overall_confidence": self.overall_confidence,
            "signal_scores": self.signal_scores,
            "evidence": [e.to_dict() for e in self.evidence],
            "shared_iocs": {
                "domains": self.shared_domains,
                "ips": self.shared_ips,
                "hashes": self.shared_hashes,
            },
            "shared_ttps": self.shared_techniques,
            "shared_malware": self.shared_malware,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }

    def to_campaign(self) -> Campaign:
        """Convert detected cluster to a Campaign for tracking."""
        iocs = []
        now = datetime.now(timezone.utc)

        for domain in self.shared_domains:
            iocs.append(CampaignIOC(
                type="domain",
                value=domain,
                first_seen=self.first_seen,
                last_seen=self.last_seen,
                confidence=self.overall_confidence,
                source="campaign_detector",
            ))

        for ip in self.shared_ips:
            iocs.append(CampaignIOC(
                type="ip",
                value=ip,
                first_seen=self.first_seen,
                last_seen=self.last_seen,
                confidence=self.overall_confidence,
                source="campaign_detector",
            ))

        for hash_val in self.shared_hashes:
            iocs.append(CampaignIOC(
                type="hash",
                value=hash_val,
                first_seen=self.first_seen,
                last_seen=self.last_seen,
                confidence=self.overall_confidence,
                source="campaign_detector",
            ))

        ttps = []
        for technique_id in self.shared_techniques:
            ttps.append(CampaignTTP(
                technique_id=technique_id,
                technique_name="",  # Would need ATT&CK lookup
                tactic="",
                first_seen=self.first_seen,
                last_seen=self.last_seen,
            ))

        return Campaign(
            id=self.id,
            name=self.name,
            description=f"Auto-detected campaign cluster with {len(self.investigation_ids)} related investigations.",
            status=CampaignStatus.ACTIVE if (now - (self.last_seen or now)).days <= 30 else CampaignStatus.DORMANT,
            source=CampaignSource.DETECTED,
            first_seen=self.first_seen,
            last_seen=self.last_seen,
            iocs=iocs,
            ttps=ttps,
            malware_families=self.shared_malware,
            tools=self.shared_tools,
            tags=["auto-detected", "needs-review"],
            attribution_confidence=0.0,  # No attribution yet
        )


class CampaignDetector:
    """
    Detects potential campaigns by clustering investigation findings.

    Uses multiple signals weighted by reliability:
    - Temporal clustering (0.15): Multiple targets in time window
    - Infrastructure overlap (0.30): Shared C2, registrants, hosting
    - TTP consistency (0.25): Same MITRE ATT&CK techniques
    - Tooling fingerprint (0.20): Same malware/tools
    - Victimology pattern (0.10): Shared targeting characteristics
    """

    # Signal weights for overall confidence
    SIGNAL_WEIGHTS = {
        ClusterSignal.TEMPORAL: 0.15,
        ClusterSignal.INFRASTRUCTURE: 0.30,
        ClusterSignal.TTP: 0.25,
        ClusterSignal.TOOLING: 0.20,
        ClusterSignal.VICTIMOLOGY: 0.10,
    }

    # Minimum thresholds
    MIN_CLUSTER_SIZE = 2  # At least 2 investigations
    MIN_CONFIDENCE = 0.40  # 40% confidence to report
    TEMPORAL_WINDOW_DAYS = 30  # Time window for temporal clustering

    def __init__(self) -> None:
        self._findings: list[InvestigationFindings] = []
        self._clusters: list[DetectedCluster] = []

    def add_findings(self, findings: InvestigationFindings) -> None:
        """Add investigation findings for clustering."""
        self._findings.append(findings)
        logger.debug("Added findings for clustering", target=findings.target)

    def clear_findings(self) -> None:
        """Clear all stored findings."""
        self._findings.clear()
        self._clusters.clear()

    def detect_campaigns(
        self,
        min_confidence: float | None = None,
        min_size: int | None = None,
    ) -> list[DetectedCluster]:
        """
        Run campaign detection on all stored findings.

        Args:
            min_confidence: Minimum confidence to include (default: 0.40)
            min_size: Minimum cluster size (default: 2)

        Returns:
            List of detected campaign clusters
        """
        min_conf = min_confidence or self.MIN_CONFIDENCE
        min_sz = min_size or self.MIN_CLUSTER_SIZE

        if len(self._findings) < min_sz:
            logger.info("Not enough findings for clustering", count=len(self._findings))
            return []

        logger.info("Running campaign detection", findings_count=len(self._findings))

        # Build similarity matrix between all findings
        clusters = self._cluster_findings()

        # Filter by confidence and size
        filtered = [
            c for c in clusters
            if len(c.investigation_ids) >= min_sz and c.overall_confidence >= min_conf
        ]

        # Sort by confidence
        filtered.sort(key=lambda c: c.overall_confidence, reverse=True)

        self._clusters = filtered

        logger.info(
            "Campaign detection complete",
            clusters_found=len(filtered),
            total_candidates=len(clusters),
        )

        return filtered

    def _cluster_findings(self) -> list[DetectedCluster]:
        """Cluster findings using multi-signal similarity."""
        if not self._findings:
            return []

        # Build pairwise similarity scores
        n = len(self._findings)
        similarity: dict[tuple[int, int], dict[ClusterSignal, float]] = {}

        for i in range(n):
            for j in range(i + 1, n):
                scores = self._compute_similarity(self._findings[i], self._findings[j])
                if any(s > 0 for s in scores.values()):
                    similarity[(i, j)] = scores

        # Simple greedy clustering: merge pairs with high similarity
        # This is a simplified approach; production would use proper clustering algorithms
        clusters: list[DetectedCluster] = []
        used: set[int] = set()

        # Sort pairs by weighted similarity
        sorted_pairs = sorted(
            similarity.items(),
            key=lambda x: sum(
                score * self.SIGNAL_WEIGHTS[signal]
                for signal, score in x[1].items()
            ),
            reverse=True,
        )

        for (i, j), scores in sorted_pairs:
            # Check if either is already in a cluster
            existing_cluster = None
            for cluster in clusters:
                if self._findings[i].id in cluster.investigation_ids:
                    if self._findings[j].id not in cluster.investigation_ids:
                        existing_cluster = cluster
                        # Add j to cluster
                        self._add_to_cluster(existing_cluster, self._findings[j], scores)
                        used.add(j)
                    break
                elif self._findings[j].id in cluster.investigation_ids:
                    if self._findings[i].id not in cluster.investigation_ids:
                        existing_cluster = cluster
                        # Add i to cluster
                        self._add_to_cluster(existing_cluster, self._findings[i], scores)
                        used.add(i)
                    break

            if existing_cluster is None and i not in used and j not in used:
                # Create new cluster
                cluster = self._create_cluster(self._findings[i], self._findings[j], scores)
                clusters.append(cluster)
                used.add(i)
                used.add(j)

        return clusters

    def _compute_similarity(
        self,
        a: InvestigationFindings,
        b: InvestigationFindings,
    ) -> dict[ClusterSignal, float]:
        """Compute similarity scores between two investigations."""
        scores: dict[ClusterSignal, float] = {}

        # Temporal similarity
        scores[ClusterSignal.TEMPORAL] = self._temporal_similarity(a, b)

        # Infrastructure similarity
        scores[ClusterSignal.INFRASTRUCTURE] = self._infrastructure_similarity(a, b)

        # TTP similarity
        scores[ClusterSignal.TTP] = self._ttp_similarity(a, b)

        # Tooling similarity
        scores[ClusterSignal.TOOLING] = self._tooling_similarity(a, b)

        # Victimology similarity
        scores[ClusterSignal.VICTIMOLOGY] = self._victimology_similarity(a, b)

        return scores

    def _temporal_similarity(self, a: InvestigationFindings, b: InvestigationFindings) -> float:
        """Compute temporal proximity score."""
        delta = abs((a.timestamp - b.timestamp).days)
        if delta <= self.TEMPORAL_WINDOW_DAYS:
            # Linear decay within window
            return 1.0 - (delta / self.TEMPORAL_WINDOW_DAYS)
        return 0.0

    def _infrastructure_similarity(self, a: InvestigationFindings, b: InvestigationFindings) -> float:
        """Compute infrastructure overlap score."""
        scores = []

        # Domain overlap
        if a.domains and b.domains:
            overlap = len(set(a.domains) & set(b.domains))
            if overlap > 0:
                scores.append(min(1.0, overlap / max(len(a.domains), len(b.domains)) * 2))

        # IP overlap
        if a.ips and b.ips:
            overlap = len(set(a.ips) & set(b.ips))
            if overlap > 0:
                scores.append(min(1.0, overlap / max(len(a.ips), len(b.ips)) * 2))

        # Registrar overlap (weaker signal)
        if a.registrars and b.registrars:
            overlap = len(set(a.registrars) & set(b.registrars))
            if overlap > 0:
                scores.append(overlap / max(len(a.registrars), len(b.registrars)) * 0.3)

        # Hosting provider overlap
        if a.hosting_providers and b.hosting_providers:
            overlap = len(set(a.hosting_providers) & set(b.hosting_providers))
            if overlap > 0:
                scores.append(overlap / max(len(a.hosting_providers), len(b.hosting_providers)) * 0.5)

        # Nameserver overlap
        if a.nameservers and b.nameservers:
            overlap = len(set(a.nameservers) & set(b.nameservers))
            if overlap > 0:
                scores.append(overlap / max(len(a.nameservers), len(b.nameservers)) * 0.4)

        return max(scores) if scores else 0.0

    def _ttp_similarity(self, a: InvestigationFindings, b: InvestigationFindings) -> float:
        """Compute TTP overlap score."""
        if not a.techniques or not b.techniques:
            return 0.0

        overlap = len(set(a.techniques) & set(b.techniques))
        if overlap == 0:
            return 0.0

        # Jaccard similarity with bonus for more overlaps
        total = len(set(a.techniques) | set(b.techniques))
        jaccard = overlap / total

        # Bonus for having multiple matching techniques
        bonus = min(0.3, overlap * 0.1)

        return min(1.0, jaccard + bonus)

    def _tooling_similarity(self, a: InvestigationFindings, b: InvestigationFindings) -> float:
        """Compute tooling/malware overlap score."""
        scores = []

        # Malware family overlap (strong signal)
        if a.malware_families and b.malware_families:
            overlap = len(set(a.malware_families) & set(b.malware_families))
            if overlap > 0:
                scores.append(1.0)  # Any malware match is significant

        # Hash overlap (very strong signal)
        if a.hashes and b.hashes:
            overlap = len(set(a.hashes) & set(b.hashes))
            if overlap > 0:
                scores.append(1.0)  # Any hash match is definitive

        # Tool overlap
        if a.tools and b.tools:
            overlap = len(set(a.tools) & set(b.tools))
            if overlap > 0:
                total = len(set(a.tools) | set(b.tools))
                scores.append(overlap / total)

        return max(scores) if scores else 0.0

    def _victimology_similarity(self, a: InvestigationFindings, b: InvestigationFindings) -> float:
        """Compute victimology pattern score."""
        score = 0.0

        # Same sector
        if a.sector and b.sector and a.sector.lower() == b.sector.lower():
            score += 0.5

        # Same region
        if a.region and b.region and a.region.lower() == b.region.lower():
            score += 0.3

        # Same organization type (from tags)
        a_tags = set(t.lower() for t in a.tags)
        b_tags = set(t.lower() for t in b.tags)
        if a_tags & b_tags:
            score += 0.2

        return min(1.0, score)

    def _create_cluster(
        self,
        a: InvestigationFindings,
        b: InvestigationFindings,
        scores: dict[ClusterSignal, float],
    ) -> DetectedCluster:
        """Create a new cluster from two findings."""
        now = datetime.now(timezone.utc)

        # Generate cluster name
        name = self._generate_cluster_name(a, b)

        # Compute overall confidence
        overall = sum(
            score * self.SIGNAL_WEIGHTS[signal]
            for signal, score in scores.items()
        )

        # Build evidence
        evidence = self._build_evidence(a, b, scores)

        # Compute shared IOCs
        shared_domains = list(set(a.domains) & set(b.domains))
        shared_ips = list(set(a.ips) & set(b.ips))
        shared_hashes = list(set(a.hashes) & set(b.hashes))
        shared_techniques = list(set(a.techniques) & set(b.techniques))
        shared_malware = list(set(a.malware_families) & set(b.malware_families))
        shared_tools = list(set(a.tools) & set(b.tools))

        return DetectedCluster(
            id=str(uuid4()),
            name=name,
            created_at=now,
            investigation_ids=[a.id, b.id],
            targets=[a.target, b.target],
            evidence=evidence,
            shared_domains=shared_domains,
            shared_ips=shared_ips,
            shared_hashes=shared_hashes,
            shared_techniques=shared_techniques,
            shared_malware=shared_malware,
            shared_tools=shared_tools,
            overall_confidence=overall,
            signal_scores={s.value: v for s, v in scores.items()},
            first_seen=min(a.timestamp, b.timestamp),
            last_seen=max(a.timestamp, b.timestamp),
        )

    def _add_to_cluster(
        self,
        cluster: DetectedCluster,
        findings: InvestigationFindings,
        scores: dict[ClusterSignal, float],
    ) -> None:
        """Add findings to an existing cluster."""
        cluster.investigation_ids.append(findings.id)
        cluster.targets.append(findings.target)

        # Update shared IOCs (intersection with new findings)
        cluster.shared_domains = list(
            set(cluster.shared_domains) & set(findings.domains)
        ) if cluster.shared_domains else findings.domains

        cluster.shared_ips = list(
            set(cluster.shared_ips) & set(findings.ips)
        ) if cluster.shared_ips else findings.ips

        cluster.shared_techniques = list(
            set(cluster.shared_techniques) & set(findings.techniques)
        ) if cluster.shared_techniques else findings.techniques

        # Update temporal bounds
        if cluster.first_seen is None or findings.timestamp < cluster.first_seen:
            cluster.first_seen = findings.timestamp
        if cluster.last_seen is None or findings.timestamp > cluster.last_seen:
            cluster.last_seen = findings.timestamp

        # Recalculate confidence (average with new scores)
        new_overall = sum(
            score * self.SIGNAL_WEIGHTS[signal]
            for signal, score in scores.items()
        )
        cluster.overall_confidence = (
            cluster.overall_confidence * (len(cluster.investigation_ids) - 1) + new_overall
        ) / len(cluster.investigation_ids)

    def _generate_cluster_name(
        self,
        a: InvestigationFindings,
        b: InvestigationFindings,
    ) -> str:
        """Generate a descriptive name for the cluster."""
        # Use sector if available
        sector = a.sector or b.sector
        if sector:
            return f"Detected-{sector.title()}-Campaign"

        # Use malware if available
        malware = set(a.malware_families) | set(b.malware_families)
        if malware:
            return f"Detected-{list(malware)[0]}-Campaign"

        # Use region if available
        region = a.region or b.region
        if region:
            return f"Detected-{region.title()}-Campaign"

        # Fallback to timestamp-based name
        return f"Detected-Campaign-{datetime.now(timezone.utc).strftime('%Y%m%d')}"

    def _build_evidence(
        self,
        a: InvestigationFindings,
        b: InvestigationFindings,
        scores: dict[ClusterSignal, float],
    ) -> list[ClusterEvidence]:
        """Build evidence descriptions for the cluster."""
        evidence = []

        if scores[ClusterSignal.TEMPORAL] > 0:
            delta = abs((a.timestamp - b.timestamp).days)
            evidence.append(ClusterEvidence(
                signal_type=ClusterSignal.TEMPORAL,
                description=f"Investigations occurred within {delta} days of each other",
                confidence=scores[ClusterSignal.TEMPORAL],
                data={"days_apart": delta},
            ))

        if scores[ClusterSignal.INFRASTRUCTURE] > 0:
            shared = []
            if set(a.domains) & set(b.domains):
                shared.append("domains")
            if set(a.ips) & set(b.ips):
                shared.append("IPs")
            if set(a.nameservers) & set(b.nameservers):
                shared.append("nameservers")
            evidence.append(ClusterEvidence(
                signal_type=ClusterSignal.INFRASTRUCTURE,
                description=f"Shared infrastructure: {', '.join(shared)}",
                confidence=scores[ClusterSignal.INFRASTRUCTURE],
                data={"shared_types": shared},
            ))

        if scores[ClusterSignal.TTP] > 0:
            shared = list(set(a.techniques) & set(b.techniques))
            evidence.append(ClusterEvidence(
                signal_type=ClusterSignal.TTP,
                description=f"Shared {len(shared)} MITRE ATT&CK technique(s)",
                confidence=scores[ClusterSignal.TTP],
                data={"techniques": shared},
            ))

        if scores[ClusterSignal.TOOLING] > 0:
            shared_malware = list(set(a.malware_families) & set(b.malware_families))
            shared_hashes = list(set(a.hashes) & set(b.hashes))
            desc_parts = []
            if shared_malware:
                desc_parts.append(f"malware: {', '.join(shared_malware)}")
            if shared_hashes:
                desc_parts.append(f"{len(shared_hashes)} matching hash(es)")
            evidence.append(ClusterEvidence(
                signal_type=ClusterSignal.TOOLING,
                description=f"Shared tooling - {'; '.join(desc_parts)}",
                confidence=scores[ClusterSignal.TOOLING],
                data={"malware": shared_malware, "hash_count": len(shared_hashes)},
            ))

        if scores[ClusterSignal.VICTIMOLOGY] > 0:
            patterns = []
            if a.sector and b.sector and a.sector.lower() == b.sector.lower():
                patterns.append(f"sector: {a.sector}")
            if a.region and b.region and a.region.lower() == b.region.lower():
                patterns.append(f"region: {a.region}")
            evidence.append(ClusterEvidence(
                signal_type=ClusterSignal.VICTIMOLOGY,
                description=f"Similar targeting - {', '.join(patterns)}",
                confidence=scores[ClusterSignal.VICTIMOLOGY],
                data={"patterns": patterns},
            ))

        return evidence

    def match_to_known_campaigns(
        self,
        cluster: DetectedCluster,
    ) -> list[tuple[Campaign, float]]:
        """
        Match a detected cluster against known campaigns.

        Returns list of (campaign, similarity_score) tuples.
        """
        tracker = get_campaign_tracker()
        matches = []

        # Match by IOCs
        for domain in cluster.shared_domains:
            campaign_matches = tracker.match_ioc("domain", domain)
            for campaign in campaign_matches:
                matches.append((campaign, 0.9))  # High confidence for IOC match

        for ip in cluster.shared_ips:
            campaign_matches = tracker.match_ioc("ip", ip)
            for campaign in campaign_matches:
                matches.append((campaign, 0.9))

        for hash_val in cluster.shared_hashes:
            campaign_matches = tracker.match_ioc("hash", hash_val)
            for campaign in campaign_matches:
                matches.append((campaign, 0.95))  # Very high for hash match

        # Deduplicate and average scores
        campaign_scores: dict[str, list[float]] = defaultdict(list)
        campaign_map: dict[str, Campaign] = {}
        for campaign, score in matches:
            campaign_scores[campaign.id].append(score)
            campaign_map[campaign.id] = campaign

        result = []
        for campaign_id, scores in campaign_scores.items():
            avg_score = sum(scores) / len(scores)
            result.append((campaign_map[campaign_id], avg_score))

        result.sort(key=lambda x: x[1], reverse=True)
        return result


# Global detector instance
_detector: CampaignDetector | None = None


def get_campaign_detector() -> CampaignDetector:
    """Get the global campaign detector instance."""
    global _detector
    if _detector is None:
        _detector = CampaignDetector()
    return _detector
