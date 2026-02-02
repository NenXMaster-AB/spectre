"""
SPECTRE Intelligence Layer

Threat intelligence processing, enrichment, and analysis.
"""

from spectre.intel.attribution import (
    AttributionPipeline,
    AttributionResult,
    ThreatActor,
)
from spectre.intel.enrichment import (
    EnrichmentConfig,
    EnrichmentPipeline,
    EnrichmentResult,
)
from spectre.intel.mitre_attack import MITREAttack, Technique, TTPMatch
from spectre.intel.report import (
    InvestigationReport,
    ReportFormat,
    ReportGenerator,
)
from spectre.intel.ttp_tagger import TTPSummary, TTPTagger

__all__ = [
    # Enrichment
    "EnrichmentConfig",
    "EnrichmentPipeline",
    "EnrichmentResult",
    # MITRE ATT&CK
    "MITREAttack",
    "Technique",
    "TTPMatch",
    # Attribution
    "AttributionPipeline",
    "AttributionResult",
    "ThreatActor",
    # TTP Tagger
    "TTPSummary",
    "TTPTagger",
    # Reporting
    "InvestigationReport",
    "ReportFormat",
    "ReportGenerator",
]
