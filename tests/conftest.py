"""
Pytest configuration and shared fixtures.
"""

import pytest

from spectre.plugins.base import PluginConfig
from spectre.plugins.registry import PluginRegistry, reset_registry


@pytest.fixture
def plugin_config() -> PluginConfig:
    """Default plugin configuration for tests."""
    return PluginConfig(timeout_seconds=10)


@pytest.fixture
def registry() -> PluginRegistry:
    """Fresh plugin registry for each test."""
    reset_registry()
    reg = PluginRegistry()
    reg.discover_plugins()
    return reg


@pytest.fixture
def domain_entity() -> dict[str, str]:
    """Sample domain entity for testing."""
    return {"type": "domain", "value": "example.com"}


@pytest.fixture
def ip_entity() -> dict[str, str]:
    """Sample IP entity for testing."""
    return {"type": "ip_address", "value": "93.184.216.34"}


@pytest.fixture
def google_domain_entity() -> dict[str, str]:
    """Google domain entity for live testing."""
    return {"type": "domain", "value": "google.com"}
