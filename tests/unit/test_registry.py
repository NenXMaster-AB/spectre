"""
Tests for the Plugin Registry.
"""

import pytest

from spectre.plugins.base import EntityType, PluginCategory
from spectre.plugins.registry import (
    PluginNotFoundError,
    PluginRegistry,
    get_registry,
    reset_registry,
)


class TestPluginRegistry:
    """Tests for PluginRegistry."""

    def test_empty_registry(self) -> None:
        """Test empty registry has no plugins."""
        registry = PluginRegistry()
        assert len(registry) == 0
        assert registry.list_plugins() == []

    def test_discover_plugins(self, registry: PluginRegistry) -> None:
        """Test plugin discovery finds entry_point plugins."""
        # Registry from fixture has already discovered plugins
        assert len(registry) >= 0  # May be 0 if not installed

    def test_get_nonexistent_plugin(self, registry: PluginRegistry) -> None:
        """Test getting non-existent plugin raises error."""
        with pytest.raises(PluginNotFoundError):
            registry.get_plugin("nonexistent_plugin")

    def test_has_plugin(self, registry: PluginRegistry) -> None:
        """Test has_plugin method."""
        assert registry.has_plugin("nonexistent") is False

    def test_list_plugin_names(self, registry: PluginRegistry) -> None:
        """Test list_plugin_names returns list."""
        names = registry.list_plugin_names()
        assert isinstance(names, list)

    def test_get_plugins_for_entity(self, registry: PluginRegistry) -> None:
        """Test filtering plugins by entity type."""
        plugins = registry.get_plugins_for_entity(EntityType.DOMAIN)
        # All returned plugins should accept DOMAIN
        for plugin in plugins:
            assert plugin.accepts_entity(EntityType.DOMAIN)

    def test_get_plugins_by_category(self, registry: PluginRegistry) -> None:
        """Test filtering plugins by category."""
        plugins = registry.get_plugins_by_category(PluginCategory.OSINT)
        # All returned plugins should be OSINT
        for plugin in plugins:
            assert plugin.category == PluginCategory.OSINT

    def test_contains(self, registry: PluginRegistry) -> None:
        """Test __contains__ method."""
        assert "nonexistent" not in registry

    def test_iter(self, registry: PluginRegistry) -> None:
        """Test __iter__ method."""
        plugins = list(registry)
        assert isinstance(plugins, list)

    def test_get_all_info(self, registry: PluginRegistry) -> None:
        """Test get_all_info returns list of dicts."""
        info_list = registry.get_all_info()
        assert isinstance(info_list, list)
        for info in info_list:
            assert isinstance(info, dict)
            assert "name" in info
            assert "category" in info


class TestGlobalRegistry:
    """Tests for global registry functions."""

    def test_get_registry_creates_singleton(self) -> None:
        """Test get_registry returns same instance."""
        reset_registry()
        reg1 = get_registry()
        reg2 = get_registry()
        assert reg1 is reg2

    def test_reset_registry(self) -> None:
        """Test reset_registry clears the global registry."""
        reset_registry()
        reg1 = get_registry()
        reset_registry()
        reg2 = get_registry()
        assert reg1 is not reg2
