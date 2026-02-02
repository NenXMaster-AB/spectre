"""
Attribution Pipeline

Multi-stage attribution scoring for threat actor identification.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

import structlog

from spectre.intel.mitre_attack import MITREAttack, TTPMatch

logger = structlog.get_logger(__name__)


class AttributionStage(Enum):
    """Stages of the attribution pipeline."""

    TTP_MATCHING = "ttp_matching"
    INFRASTRUCTURE = "infrastructure"
    TOOLING = "tooling"
    VICTIMOLOGY = "victimology"


@dataclass
class ThreatActor:
    """Known threat actor profile."""

    name: str
    aliases: list[str] = field(default_factory=list)
    description: str = ""
    known_ttps: list[str] = field(default_factory=list)  # Technique IDs
    known_tools: list[str] = field(default_factory=list)
    known_infrastructure: list[str] = field(default_factory=list)  # Domains, IPs, patterns
    target_sectors: list[str] = field(default_factory=list)
    target_countries: list[str] = field(default_factory=list)
    attribution_country: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    references: list[str] = field(default_factory=list)


@dataclass
class AttributionScore:
    """Score for a single attribution stage."""

    stage: AttributionStage
    score: float  # 0.0 to 1.0
    evidence: list[str]
    weight: float = 1.0

    @property
    def weighted_score(self) -> float:
        """Calculate weighted score."""
        return self.score * self.weight


@dataclass
class AttributionResult:
    """Complete attribution result for a threat actor."""

    actor: ThreatActor
    stage_scores: list[AttributionScore]
    overall_score: float
    confidence: str  # "high", "medium", "low"
    timestamp: datetime = field(default_factory=datetime.utcnow)

    @classmethod
    def calculate_confidence(cls, score: float) -> str:
        """Determine confidence level from score."""
        if score >= 0.7:
            return "high"
        elif score >= 0.4:
            return "medium"
        else:
            return "low"


class AttributionPipeline:
    """
    4-Stage Attribution Pipeline.

    Stages:
    1. TTP Matching - Compare observed TTPs against known actor profiles
    2. Infrastructure - Match domains, IPs, certificates against known infrastructure
    3. Tooling - Match malware families and tools
    4. Victimology - Analyze target sectors and geographies

    Each stage produces a weighted score that contributes to overall attribution.
    """

    # Stage weights (total = 1.0)
    STAGE_WEIGHTS = {
        AttributionStage.TTP_MATCHING: 0.30,
        AttributionStage.INFRASTRUCTURE: 0.30,
        AttributionStage.TOOLING: 0.25,
        AttributionStage.VICTIMOLOGY: 0.15,
    }

    # Known threat actors (sample profiles)
    KNOWN_ACTORS: list[ThreatActor] = [
        ThreatActor(
            name="APT28",
            aliases=["Fancy Bear", "Sofacy", "Sednit", "STRONTIUM"],
            description="Russian state-sponsored threat group",
            known_ttps=["T1566.001", "T1059.001", "T1071.001", "T1547.001", "T1003.001"],
            known_tools=["X-Agent", "Zebrocy", "Koadic", "Mimikatz"],
            target_sectors=["government", "military", "defense", "media"],
            target_countries=["US", "UA", "DE", "FR", "GB"],
            attribution_country="RU",
        ),
        ThreatActor(
            name="APT29",
            aliases=["Cozy Bear", "The Dukes", "NOBELIUM"],
            description="Russian state-sponsored threat group focused on espionage",
            known_ttps=["T1566.002", "T1059.001", "T1071.001", "T1078", "T1027"],
            known_tools=["SUNBURST", "TEARDROP", "Cobalt Strike", "EnvyScout"],
            target_sectors=["government", "technology", "think_tanks"],
            target_countries=["US", "GB", "EU"],
            attribution_country="RU",
        ),
        ThreatActor(
            name="Lazarus Group",
            aliases=["Hidden Cobra", "Guardians of Peace", "ZINC"],
            description="North Korean state-sponsored threat group",
            known_ttps=["T1566.001", "T1059.001", "T1486", "T1005", "T1041"],
            known_tools=["DTrack", "HOPLIGHT", "ELECTRICFISH"],
            target_sectors=["financial", "cryptocurrency", "media", "aerospace"],
            target_countries=["US", "KR", "JP"],
            attribution_country="KP",
        ),
        ThreatActor(
            name="APT41",
            aliases=["Double Dragon", "Winnti", "BARIUM"],
            description="Chinese state-sponsored threat group with dual missions",
            known_ttps=["T1190", "T1059.001", "T1003", "T1055", "T1021.002"],
            known_tools=["ShadowPad", "Cobalt Strike", "PlugX", "Winnti"],
            target_sectors=["healthcare", "technology", "gaming", "telecommunications"],
            target_countries=["US", "GB", "AU", "JP", "TW"],
            attribution_country="CN",
        ),
        ThreatActor(
            name="FIN7",
            aliases=["Carbanak", "Navigator Group"],
            description="Financially motivated threat group",
            known_ttps=["T1566.001", "T1059.001", "T1059.005", "T1547.001", "T1005"],
            known_tools=["Carbanak", "GRIFFON", "HALFBAKED", "Cobalt Strike"],
            target_sectors=["retail", "hospitality", "financial"],
            target_countries=["US", "GB", "AU"],
            attribution_country=None,
        ),
        ThreatActor(
            name="Conti",
            aliases=["Wizard Spider"],
            description="Ransomware-focused cybercrime group",
            known_ttps=["T1486", "T1059.001", "T1021.002", "T1003.001", "T1041"],
            known_tools=["Conti Ransomware", "BazarLoader", "TrickBot", "Cobalt Strike"],
            target_sectors=["healthcare", "government", "manufacturing", "technology"],
            target_countries=["US", "GB", "DE", "AU"],
            attribution_country="RU",
        ),
    ]

    def __init__(self, mitre: MITREAttack | None = None) -> None:
        """Initialize the attribution pipeline."""
        self.mitre = mitre
        self._actors: dict[str, ThreatActor] = {
            actor.name.lower(): actor for actor in self.KNOWN_ACTORS
        }
        # Add aliases
        for actor in self.KNOWN_ACTORS:
            for alias in actor.aliases:
                self._actors[alias.lower()] = actor

    def get_actor(self, name: str) -> ThreatActor | None:
        """Get a threat actor by name or alias."""
        return self._actors.get(name.lower())

    def list_actors(self) -> list[ThreatActor]:
        """List all known threat actors."""
        # Return unique actors
        seen = set()
        actors = []
        for actor in self._actors.values():
            if actor.name not in seen:
                seen.add(actor.name)
                actors.append(actor)
        return actors

    def _score_ttp_matching(
        self,
        actor: ThreatActor,
        observed_ttps: list[str],
        ttp_matches: list[TTPMatch] | None = None,
    ) -> AttributionScore:
        """
        Stage 1: Score based on TTP overlap.

        Compares observed TTPs against actor's known TTPs.
        """
        evidence = []
        matching_ttps = set(observed_ttps) & set(actor.known_ttps)

        if not actor.known_ttps:
            return AttributionScore(
                stage=AttributionStage.TTP_MATCHING,
                score=0.0,
                evidence=["No known TTPs for actor"],
                weight=self.STAGE_WEIGHTS[AttributionStage.TTP_MATCHING],
            )

        # Calculate overlap percentage
        overlap = len(matching_ttps) / len(actor.known_ttps)

        for ttp in matching_ttps:
            evidence.append(f"TTP match: {ttp}")

        # Bonus for matching high-confidence TTP detections
        if ttp_matches:
            for match in ttp_matches:
                if match.technique.technique_id in actor.known_ttps and match.confidence > 0.7:
                    overlap = min(overlap + 0.1, 1.0)
                    evidence.append(
                        f"High-confidence TTP: {match.technique.technique_id} "
                        f"({match.confidence:.0%})"
                    )

        return AttributionScore(
            stage=AttributionStage.TTP_MATCHING,
            score=overlap,
            evidence=evidence,
            weight=self.STAGE_WEIGHTS[AttributionStage.TTP_MATCHING],
        )

    def _score_infrastructure(
        self,
        actor: ThreatActor,
        domains: list[str],
        ips: list[str],
        certificates: list[dict[str, Any]] | None = None,
    ) -> AttributionScore:
        """
        Stage 2: Score based on infrastructure overlap.

        Compares observed infrastructure against known actor infrastructure.
        """
        evidence = []
        score = 0.0

        # Check domains
        for domain in domains:
            domain_lower = domain.lower()
            for known in actor.known_infrastructure:
                if known.lower() in domain_lower or domain_lower in known.lower():
                    score += 0.3
                    evidence.append(f"Domain pattern match: {domain}")
                    break

        # Check IPs
        for ip in ips:
            if ip in actor.known_infrastructure:
                score += 0.4
                evidence.append(f"Known IP: {ip}")

        # Check for certificate patterns (if available)
        if certificates:
            for cert in certificates:
                issuer = cert.get("issuer", "")
                for known in actor.known_infrastructure:
                    if known in issuer:
                        score += 0.2
                        evidence.append(f"Certificate issuer match: {issuer}")
                        break

        return AttributionScore(
            stage=AttributionStage.INFRASTRUCTURE,
            score=min(score, 1.0),
            evidence=evidence if evidence else ["No infrastructure matches"],
            weight=self.STAGE_WEIGHTS[AttributionStage.INFRASTRUCTURE],
        )

    def _score_tooling(
        self,
        actor: ThreatActor,
        malware_families: list[str],
        tools: list[str],
    ) -> AttributionScore:
        """
        Stage 3: Score based on tooling overlap.

        Compares observed malware and tools against known actor tools.
        """
        evidence = []
        score = 0.0

        all_observed = [m.lower() for m in malware_families + tools]
        known_tools_lower = [t.lower() for t in actor.known_tools]

        for observed in all_observed:
            for known in known_tools_lower:
                if known in observed or observed in known:
                    # Exact match worth more
                    if known == observed:
                        score += 0.5
                        evidence.append(f"Exact tool match: {observed}")
                    else:
                        score += 0.2
                        evidence.append(f"Partial tool match: {observed} ~ {known}")

        return AttributionScore(
            stage=AttributionStage.TOOLING,
            score=min(score, 1.0),
            evidence=evidence if evidence else ["No tooling matches"],
            weight=self.STAGE_WEIGHTS[AttributionStage.TOOLING],
        )

    def _score_victimology(
        self,
        actor: ThreatActor,
        target_sectors: list[str],
        target_countries: list[str],
    ) -> AttributionScore:
        """
        Stage 4: Score based on victimology overlap.

        Compares observed targets against known actor targeting patterns.
        """
        evidence = []
        score = 0.0

        # Check sector overlap
        sector_matches = set(s.lower() for s in target_sectors) & set(
            s.lower() for s in actor.target_sectors
        )
        if sector_matches:
            sector_score = len(sector_matches) / max(len(actor.target_sectors), 1)
            score += sector_score * 0.5
            for sector in sector_matches:
                evidence.append(f"Target sector match: {sector}")

        # Check country overlap
        country_matches = set(c.upper() for c in target_countries) & set(
            c.upper() for c in actor.target_countries
        )
        if country_matches:
            country_score = len(country_matches) / max(len(actor.target_countries), 1)
            score += country_score * 0.5
            for country in country_matches:
                evidence.append(f"Target country match: {country}")

        return AttributionScore(
            stage=AttributionStage.VICTIMOLOGY,
            score=min(score, 1.0),
            evidence=evidence if evidence else ["No victimology matches"],
            weight=self.STAGE_WEIGHTS[AttributionStage.VICTIMOLOGY],
        )

    def attribute(
        self,
        observed_ttps: list[str] | None = None,
        ttp_matches: list[TTPMatch] | None = None,
        domains: list[str] | None = None,
        ips: list[str] | None = None,
        certificates: list[dict[str, Any]] | None = None,
        malware_families: list[str] | None = None,
        tools: list[str] | None = None,
        target_sectors: list[str] | None = None,
        target_countries: list[str] | None = None,
        min_score: float = 0.1,
    ) -> list[AttributionResult]:
        """
        Run the full 4-stage attribution pipeline.

        Args:
            observed_ttps: List of observed MITRE ATT&CK technique IDs
            ttp_matches: TTP matches from keyword matching
            domains: Observed domains
            ips: Observed IP addresses
            certificates: Certificate information
            malware_families: Detected malware families
            tools: Detected tools
            target_sectors: Observed target sectors
            target_countries: Observed target countries
            min_score: Minimum score to include in results

        Returns:
            List of attribution results, sorted by score
        """
        observed_ttps = observed_ttps or []
        domains = domains or []
        ips = ips or []
        malware_families = malware_families or []
        tools = tools or []
        target_sectors = target_sectors or []
        target_countries = target_countries or []

        results = []

        for actor in self.list_actors():
            stage_scores = [
                self._score_ttp_matching(actor, observed_ttps, ttp_matches),
                self._score_infrastructure(actor, domains, ips, certificates),
                self._score_tooling(actor, malware_families, tools),
                self._score_victimology(actor, target_sectors, target_countries),
            ]

            # Calculate weighted overall score
            overall_score = sum(s.weighted_score for s in stage_scores)

            if overall_score >= min_score:
                results.append(
                    AttributionResult(
                        actor=actor,
                        stage_scores=stage_scores,
                        overall_score=overall_score,
                        confidence=AttributionResult.calculate_confidence(overall_score),
                    )
                )

        # Sort by score descending
        results.sort(key=lambda r: r.overall_score, reverse=True)
        return results

    def explain_attribution(self, result: AttributionResult) -> str:
        """
        Generate human-readable explanation of attribution.

        Args:
            result: Attribution result to explain

        Returns:
            Formatted explanation string
        """
        lines = [
            f"Attribution Analysis: {result.actor.name}",
            f"Aliases: {', '.join(result.actor.aliases)}",
            f"Overall Score: {result.overall_score:.1%}",
            f"Confidence: {result.confidence.upper()}",
            "",
            "Stage Breakdown:",
        ]

        for score in result.stage_scores:
            lines.append(f"\n{score.stage.value.replace('_', ' ').title()}:")
            lines.append(f"  Score: {score.score:.1%} (weight: {score.weight:.0%})")
            lines.append(f"  Weighted: {score.weighted_score:.1%}")
            if score.evidence:
                lines.append("  Evidence:")
                for ev in score.evidence[:5]:
                    lines.append(f"    - {ev}")

        if result.actor.attribution_country:
            lines.append(f"\nAttributed Country: {result.actor.attribution_country}")

        return "\n".join(lines)
