"""
TTP Auto-Tagger

Automatically tags findings with MITRE ATT&CK techniques.
"""

from dataclasses import dataclass, field
from typing import Any

import structlog

from spectre.intel.mitre_attack import MITREAttack, TTPMatch
from spectre.plugins.base import PluginResult

logger = structlog.get_logger(__name__)


@dataclass
class TaggedFinding:
    """A finding with TTP tags."""

    finding: dict[str, Any]
    ttp_matches: list[TTPMatch]
    plugin_name: str


@dataclass
class TTPSummary:
    """Summary of all TTPs detected in an investigation."""

    techniques: dict[str, int]  # technique_id -> count
    tactics: dict[str, int]  # tactic -> count
    matches: list[TTPMatch]

    @property
    def top_techniques(self) -> list[tuple[str, int]]:
        """Get techniques sorted by frequency."""
        return sorted(self.techniques.items(), key=lambda x: x[1], reverse=True)

    @property
    def top_tactics(self) -> list[tuple[str, int]]:
        """Get tactics sorted by frequency."""
        return sorted(self.tactics.items(), key=lambda x: x[1], reverse=True)


class TTPTagger:
    """
    Automatic TTP tagging for investigation findings.

    Analyzes text from findings and tags them with relevant
    MITRE ATT&CK techniques.
    """

    # Additional keyword patterns for common indicators
    INDICATOR_PATTERNS: dict[str, list[str]] = {
        "T1566": ["phish", "spearphish"],
        "T1059.001": ["powershell", "-enc", "invoke-", "iex"],
        "T1059.003": ["cmd.exe", "cmd /c"],
        "T1059.005": ["wscript", "cscript", ".vbs"],
        "T1059.006": ["python", ".py"],
        "T1059.007": ["javascript", ".js", "jscript"],
        "T1071.001": ["http://", "https://", "user-agent"],
        "T1071.004": ["dns tunnel", "txt record", "dns query"],
        "T1486": ["ransom", "encrypt", "decrypt", "bitcoin", "payment"],
        "T1027": ["base64", "encoded", "obfuscat", "packed"],
        "T1055": ["inject", "hollowing", "dll inject"],
        "T1003": ["mimikatz", "lsass", "credential", "dump"],
        "T1547.001": ["hklm\\software\\microsoft\\windows\\currentversion\\run"],
        "T1021.001": ["rdp", "3389", "remote desktop"],
        "T1021.002": ["smb", "445", "admin$", "c$"],
        "T1070": ["clear", "delete", "wipe", "logs"],
        "T1190": ["cve-", "exploit", "vulnerability"],
        "T1110": ["brute", "spray", "credential stuff"],
    }

    def __init__(self, mitre: MITREAttack | None = None) -> None:
        """Initialize the TTP tagger."""
        self.mitre = mitre or MITREAttack()

    async def initialize(self) -> None:
        """Initialize MITRE ATT&CK data."""
        await self.mitre.load()

    def _extract_text(self, finding: dict[str, Any]) -> str:
        """Extract searchable text from a finding."""
        texts = []

        # Get data dict
        data = finding.get("data", {})

        # Extract string values
        for key, value in data.items():
            if isinstance(value, str):
                texts.append(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str):
                        texts.append(item)

        # Add finding type
        texts.append(finding.get("finding_type", ""))

        return " ".join(texts)

    def _match_indicators(self, text: str) -> list[TTPMatch]:
        """Match text against indicator patterns."""
        text_lower = text.lower()
        matches = []

        for technique_id, patterns in self.INDICATOR_PATTERNS.items():
            matched = [p for p in patterns if p.lower() in text_lower]
            if matched:
                technique = self.mitre.get_technique(technique_id)
                if technique:
                    confidence = min(0.5 + (len(matched) * 0.15), 0.95)
                    matches.append(
                        TTPMatch(
                            technique=technique,
                            confidence=confidence,
                            matched_keywords=matched,
                            source="indicator_pattern",
                        )
                    )

        return matches

    def tag_finding(
        self,
        finding: dict[str, Any],
        plugin_name: str = "",
        min_confidence: float = 0.4,
    ) -> TaggedFinding:
        """
        Tag a single finding with TTPs.

        Args:
            finding: Finding dict from PluginResult
            plugin_name: Name of the plugin that produced the finding
            min_confidence: Minimum confidence for matches

        Returns:
            TaggedFinding with TTP matches
        """
        text = self._extract_text(finding)

        # Get matches from MITRE ATT&CK keywords
        mitre_matches = self.mitre.match_ttps(text, min_confidence)

        # Get matches from indicator patterns
        indicator_matches = self._match_indicators(text)

        # Combine and deduplicate
        all_matches = mitre_matches + indicator_matches
        seen_ids = set()
        unique_matches = []
        for match in all_matches:
            if match.technique.technique_id not in seen_ids:
                seen_ids.add(match.technique.technique_id)
                unique_matches.append(match)

        # Sort by confidence
        unique_matches.sort(key=lambda m: m.confidence, reverse=True)

        return TaggedFinding(
            finding=finding,
            ttp_matches=unique_matches,
            plugin_name=plugin_name,
        )

    def tag_results(
        self,
        results: list[PluginResult],
        min_confidence: float = 0.4,
    ) -> list[TaggedFinding]:
        """
        Tag all findings from multiple plugin results.

        Args:
            results: List of PluginResults
            min_confidence: Minimum confidence for matches

        Returns:
            List of TaggedFindings
        """
        tagged = []
        for result in results:
            for finding in result.findings:
                tagged_finding = self.tag_finding(
                    finding, result.plugin_name, min_confidence
                )
                if tagged_finding.ttp_matches:
                    tagged.append(tagged_finding)

        return tagged

    def summarize_ttps(self, tagged_findings: list[TaggedFinding]) -> TTPSummary:
        """
        Create a summary of all TTPs found.

        Args:
            tagged_findings: List of tagged findings

        Returns:
            TTPSummary with technique and tactic frequencies
        """
        techniques: dict[str, int] = {}
        tactics: dict[str, int] = {}
        all_matches: list[TTPMatch] = []

        for tagged in tagged_findings:
            for match in tagged.ttp_matches:
                tid = match.technique.technique_id
                techniques[tid] = techniques.get(tid, 0) + 1

                for tactic in match.technique.tactics:
                    tactics[tactic] = tactics.get(tactic, 0) + 1

                all_matches.append(match)

        return TTPSummary(
            techniques=techniques,
            tactics=tactics,
            matches=all_matches,
        )

    def get_detection_recommendations(
        self,
        summary: TTPSummary,
    ) -> list[dict[str, Any]]:
        """
        Get detection recommendations based on detected TTPs.

        Args:
            summary: TTP summary from analysis

        Returns:
            List of detection recommendations
        """
        recommendations = []
        seen = set()

        for technique_id, _ in summary.top_techniques[:10]:
            if technique_id in seen:
                continue
            seen.add(technique_id)

            technique = self.mitre.get_technique(technique_id)
            if technique and technique.detection:
                recommendations.append({
                    "technique_id": technique_id,
                    "technique_name": technique.name,
                    "detection": technique.detection[:500],
                    "data_sources": technique.data_sources,
                    "tactics": technique.tactics,
                })

        return recommendations
