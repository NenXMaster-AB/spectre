"""
MITRE ATT&CK Integration

Integrates with MITRE ATT&CK framework for TTP mapping and analysis.
Uses local cached data with optional TAXII 2.1 updates.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class Technique:
    """Represents a MITRE ATT&CK technique."""

    technique_id: str
    name: str
    description: str
    tactics: list[str]
    platforms: list[str]
    detection: str | None = None
    data_sources: list[str] = field(default_factory=list)
    is_subtechnique: bool = False
    parent_id: str | None = None
    url: str | None = None


@dataclass
class Tactic:
    """Represents a MITRE ATT&CK tactic."""

    tactic_id: str
    name: str
    shortname: str
    description: str
    url: str | None = None


@dataclass
class TTPMatch:
    """Result of a TTP matching operation."""

    technique: Technique
    confidence: float
    matched_keywords: list[str]
    source: str


class MITREAttack:
    """
    MITRE ATT&CK Framework Integration.

    Provides:
    - TTP lookup and search
    - Technique-to-tactic mapping
    - Keyword-based TTP matching
    - TAXII 2.1 data updates
    """

    # MITRE ATT&CK STIX/TAXII endpoints
    ATTACK_GITHUB_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

    # Common TTP keywords for matching
    TTP_KEYWORDS: dict[str, list[str]] = {
        "T1566": ["phishing", "spearphishing", "email attachment", "malicious link"],
        "T1566.001": ["spearphishing attachment", "macro", "office document"],
        "T1566.002": ["spearphishing link", "credential harvesting"],
        "T1059": ["command", "scripting", "powershell", "cmd", "bash", "python"],
        "T1059.001": ["powershell", "ps1", "invoke-expression"],
        "T1059.003": ["cmd", "command prompt", "batch"],
        "T1059.004": ["bash", "shell", "unix shell"],
        "T1059.005": ["vbscript", "visual basic"],
        "T1059.006": ["python", "py"],
        "T1059.007": ["javascript", "jscript", "js"],
        "T1071": ["c2", "command and control", "c&c", "beacon"],
        "T1071.001": ["http", "https", "web traffic"],
        "T1071.004": ["dns tunneling", "dns c2"],
        "T1486": ["ransomware", "encryption", "ransom"],
        "T1082": ["system information discovery", "systeminfo", "hostname"],
        "T1083": ["file and directory discovery", "dir", "ls"],
        "T1005": ["data from local system", "data collection"],
        "T1041": ["exfiltration", "data exfil", "exfil over c2"],
        "T1027": ["obfuscation", "obfuscated", "encoded", "packed"],
        "T1055": ["process injection", "inject", "dll injection"],
        "T1055.001": ["dll injection", "loadlibrary"],
        "T1055.002": ["portable executable injection"],
        "T1055.012": ["process hollowing"],
        "T1547": ["persistence", "startup", "autorun"],
        "T1547.001": ["registry run keys", "run key", "autostart"],
        "T1548": ["privilege escalation", "bypass uac", "elevation"],
        "T1003": ["credential dumping", "credentials", "lsass", "mimikatz"],
        "T1003.001": ["lsass memory", "lsass dump"],
        "T1003.002": ["sam database", "security account manager"],
        "T1003.003": ["ntds.dit", "domain controller"],
        "T1021": ["lateral movement", "remote services"],
        "T1021.001": ["rdp", "remote desktop"],
        "T1021.002": ["smb", "windows admin shares"],
        "T1021.004": ["ssh", "secure shell"],
        "T1562": ["defense evasion", "disable security"],
        "T1562.001": ["disable security tools", "disable antivirus"],
        "T1070": ["indicator removal", "clear logs", "delete logs"],
        "T1070.001": ["clear windows event logs"],
        "T1070.004": ["file deletion", "delete files"],
        "T1190": ["exploit public-facing", "web exploit", "cve"],
        "T1133": ["external remote services", "vpn", "citrix", "rdp exposed"],
        "T1078": ["valid accounts", "compromised credentials", "stolen credentials"],
        "T1110": ["brute force", "password spraying", "credential stuffing"],
        "T1110.001": ["password guessing"],
        "T1110.003": ["password spraying"],
    }

    def __init__(self, cache_dir: Path | None = None) -> None:
        """Initialize MITRE ATT&CK integration."""
        self.cache_dir = cache_dir or Path.home() / ".spectre" / "mitre"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = self.cache_dir / "enterprise-attack.json"

        self._techniques: dict[str, Technique] = {}
        self._tactics: dict[str, Tactic] = {}
        self._loaded = False

    async def load(self, force_update: bool = False) -> None:
        """
        Load ATT&CK data from cache or download.

        Args:
            force_update: Force download even if cache exists
        """
        if self._loaded and not force_update:
            return

        # Check cache
        if self.cache_file.exists() and not force_update:
            try:
                await self._load_from_cache()
                self._loaded = True
                logger.info(
                    "Loaded MITRE ATT&CK from cache",
                    techniques=len(self._techniques),
                    tactics=len(self._tactics),
                )
                return
            except Exception as e:
                logger.warning("Failed to load cache, will download", error=str(e))

        # Download fresh data
        await self._download_attack_data()
        await self._load_from_cache()
        self._loaded = True

        logger.info(
            "Downloaded and loaded MITRE ATT&CK",
            techniques=len(self._techniques),
            tactics=len(self._tactics),
        )

    async def _download_attack_data(self) -> None:
        """Download ATT&CK data from GitHub."""
        async with httpx.AsyncClient(timeout=60) as client:
            response = await client.get(self.ATTACK_GITHUB_URL)
            response.raise_for_status()

            # Save to cache
            self.cache_file.write_text(response.text)
            logger.debug("Downloaded MITRE ATT&CK data")

    async def _load_from_cache(self) -> None:
        """Load ATT&CK data from cache file."""
        data = json.loads(self.cache_file.read_text())
        objects = data.get("objects", [])

        self._techniques = {}
        self._tactics = {}

        # First pass: extract tactics
        for obj in objects:
            if obj.get("type") == "x-mitre-tactic":
                tactic = self._parse_tactic(obj)
                if tactic:
                    self._tactics[tactic.shortname] = tactic

        # Second pass: extract techniques
        for obj in objects:
            if obj.get("type") == "attack-pattern":
                technique = self._parse_technique(obj)
                if technique:
                    self._techniques[technique.technique_id] = technique

    def _parse_tactic(self, obj: dict[str, Any]) -> Tactic | None:
        """Parse a STIX tactic object."""
        try:
            external_refs = obj.get("external_references", [])
            tactic_id = next(
                (r["external_id"] for r in external_refs if r.get("source_name") == "mitre-attack"),
                None,
            )
            url = next(
                (r["url"] for r in external_refs if r.get("source_name") == "mitre-attack"),
                None,
            )

            shortname = obj.get("x_mitre_shortname", "")

            return Tactic(
                tactic_id=tactic_id or "",
                name=obj.get("name", ""),
                shortname=shortname,
                description=obj.get("description", ""),
                url=url,
            )
        except Exception as e:
            logger.debug("Failed to parse tactic", error=str(e))
            return None

    def _parse_technique(self, obj: dict[str, Any]) -> Technique | None:
        """Parse a STIX technique object."""
        try:
            # Skip revoked/deprecated
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                return None

            external_refs = obj.get("external_references", [])
            technique_id = next(
                (r["external_id"] for r in external_refs if r.get("source_name") == "mitre-attack"),
                None,
            )
            url = next(
                (r["url"] for r in external_refs if r.get("source_name") == "mitre-attack"),
                None,
            )

            if not technique_id:
                return None

            # Extract tactics from kill chain phases
            tactics = []
            for phase in obj.get("kill_chain_phases", []):
                if phase.get("kill_chain_name") == "mitre-attack":
                    tactics.append(phase.get("phase_name", ""))

            # Check if subtechnique
            is_subtechnique = obj.get("x_mitre_is_subtechnique", False)
            parent_id = None
            if is_subtechnique and "." in technique_id:
                parent_id = technique_id.split(".")[0]

            return Technique(
                technique_id=technique_id,
                name=obj.get("name", ""),
                description=obj.get("description", "")[:2000],
                tactics=tactics,
                platforms=obj.get("x_mitre_platforms", []),
                detection=obj.get("x_mitre_detection"),
                data_sources=obj.get("x_mitre_data_sources", []),
                is_subtechnique=is_subtechnique,
                parent_id=parent_id,
                url=url,
            )
        except Exception as e:
            logger.debug("Failed to parse technique", error=str(e))
            return None

    def get_technique(self, technique_id: str) -> Technique | None:
        """Get a technique by ID."""
        return self._techniques.get(technique_id)

    def get_tactic(self, shortname: str) -> Tactic | None:
        """Get a tactic by shortname."""
        return self._tactics.get(shortname)

    def search_techniques(
        self,
        query: str,
        tactics: list[str] | None = None,
        limit: int = 20,
    ) -> list[Technique]:
        """
        Search techniques by name or description.

        Args:
            query: Search query
            tactics: Optional list of tactics to filter by
            limit: Maximum results to return

        Returns:
            List of matching techniques
        """
        query_lower = query.lower()
        results = []

        for technique in self._techniques.values():
            # Skip if tactic filter doesn't match
            if tactics and not any(t in technique.tactics for t in tactics):
                continue

            # Check name and description
            if (
                query_lower in technique.name.lower()
                or query_lower in technique.description.lower()
            ):
                results.append(technique)

            if len(results) >= limit:
                break

        return results

    def get_techniques_by_tactic(self, tactic: str) -> list[Technique]:
        """Get all techniques for a given tactic."""
        return [t for t in self._techniques.values() if tactic in t.tactics]

    def match_ttps(
        self,
        text: str,
        min_confidence: float = 0.5,
    ) -> list[TTPMatch]:
        """
        Match text against known TTP keywords.

        Args:
            text: Text to analyze (IOC descriptions, reports, etc.)
            min_confidence: Minimum confidence threshold

        Returns:
            List of TTP matches with confidence scores
        """
        text_lower = text.lower()
        matches = []

        for technique_id, keywords in self.TTP_KEYWORDS.items():
            matched_keywords = []
            for keyword in keywords:
                if keyword in text_lower:
                    matched_keywords.append(keyword)

            if matched_keywords:
                technique = self.get_technique(technique_id)
                if technique:
                    # Confidence based on number of keywords matched
                    confidence = min(len(matched_keywords) / len(keywords) + 0.3, 1.0)

                    if confidence >= min_confidence:
                        matches.append(
                            TTPMatch(
                                technique=technique,
                                confidence=confidence,
                                matched_keywords=matched_keywords,
                                source="keyword_match",
                            )
                        )

        # Sort by confidence
        matches.sort(key=lambda m: m.confidence, reverse=True)
        return matches

    def get_subtechniques(self, parent_id: str) -> list[Technique]:
        """Get all subtechniques for a parent technique."""
        return [
            t for t in self._techniques.values()
            if t.parent_id == parent_id
        ]

    def export_matrix(self) -> dict[str, list[dict[str, Any]]]:
        """
        Export techniques organized by tactic (ATT&CK matrix format).

        Returns:
            Dict mapping tactic shortnames to lists of techniques
        """
        matrix: dict[str, list[dict[str, Any]]] = {}

        for tactic in self._tactics.values():
            techniques = self.get_techniques_by_tactic(tactic.shortname)
            matrix[tactic.shortname] = [
                {
                    "technique_id": t.technique_id,
                    "name": t.name,
                    "is_subtechnique": t.is_subtechnique,
                    "platforms": t.platforms,
                }
                for t in techniques
                if not t.is_subtechnique  # Only top-level in matrix
            ]

        return matrix
