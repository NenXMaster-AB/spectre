"""Plugin engine - data sources, tools, and integrations."""

from spectre.plugins.base import (
    EntityType,
    PluginResult,
    RateLimit,
    SpectrePlugin,
)
from spectre.plugins.registry import PluginRegistry

__all__ = [
    "SpectrePlugin",
    "PluginResult",
    "EntityType",
    "RateLimit",
    "PluginRegistry",
]
