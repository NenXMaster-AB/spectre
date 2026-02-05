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

# TODO: Remaining Phase 6 items
# from spectre.adversary.campaign_detector import CampaignDetector
# from spectre.adversary.ttp_timeline import TTPTimeline

__all__ = [
    "Campaign",
    "CampaignStatus",
    "CampaignSource",
    "CampaignIOC",
    "CampaignTTP",
    "CampaignUpdate",
    "CampaignTracker",
    "get_campaign_tracker",
]
