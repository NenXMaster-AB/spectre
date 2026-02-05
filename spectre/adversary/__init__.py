"""
Adversary Intelligence Module

Threat actor profiling, attribution, and campaign tracking.

Provides:
- Threat actor profiling and dossier generation
- AI-driven attribution engine
- Campaign lifecycle tracking
- Campaign detection via clustering
- TTP analysis and timeline tracking
"""

from spectre.adversary.campaign_tracker import (
    Campaign,
    CampaignStatus,
    CampaignSource,
    CampaignIOC,
    CampaignTTP,
    CampaignUpdate,
    CampaignTracker,
    get_campaign_tracker,
)

from spectre.adversary.campaign_detector import (
    CampaignDetector,
    ClusterSignal,
    ClusterEvidence,
    DetectedCluster,
    InvestigationFindings,
    get_campaign_detector,
)
from spectre.adversary.ttp_timeline import (
    TTPTimeline,
    TTPObservation,
    TTPChange,
    TTPChangeType,
    TTPProfile,
    TTPComparison,
    TimelineEvent,
    get_ttp_timeline,
)

__all__ = [
    # Campaign Tracker
    "Campaign",
    "CampaignStatus",
    "CampaignSource",
    "CampaignIOC",
    "CampaignTTP",
    "CampaignUpdate",
    "CampaignTracker",
    "get_campaign_tracker",
    # Campaign Detector
    "CampaignDetector",
    "ClusterSignal",
    "ClusterEvidence",
    "DetectedCluster",
    "InvestigationFindings",
    "get_campaign_detector",
    # TTP Timeline
    "TTPTimeline",
    "TTPObservation",
    "TTPChange",
    "TTPChangeType",
    "TTPProfile",
    "TTPComparison",
    "TimelineEvent",
    "get_ttp_timeline",
]
