"""
Plugin Registry

Handles plugin discovery, loading, and management.
Plugins are discovered via Python entry_points for pip-installable community plugins.
"""

import importlib.metadata
from collections.abc import Iterator
from typing import Any

import structlog

from spectre.plugins.base import (
    EntityType,
    PluginCategory,
    PluginConfig,
    PluginResult,
    SpectrePlugin,
)

logger = structlog.get_logger(__name__)

# Entry point group for SPECTRE plugins
PLUGIN_ENTRY_POINT = "spectre.plugins"


class PluginLoadError(Exception):
    """Raised when a plugin fails to load."""

    pass


class PluginNotFoundError(Exception):
    """Raised when a requested plugin is not found."""

    pass


class PluginRegistry:
    """
    Registry for discovering, loading, and managing SPECTRE plugins.

    Plugins are discovered via Python entry_points, allowing community plugins
    to be pip-installed and automatically available.

    Usage:
        registry = PluginRegistry()
        registry.discover_plugins()

        # Get a specific plugin
        dns_plugin = registry.get_plugin("dns_recon")

        # List all plugins
        for plugin in registry.list_plugins():
            print(plugin.name)

        # Execute a plugin
        result = await registry.execute_plugin("dns_recon", entity, config)
    """

    def __init__(self) -> None:
        """Initialize an empty registry."""
        self._plugins: dict[str, SpectrePlugin] = {}
        self._plugin_classes: dict[str, type[SpectrePlugin]] = {}
        self._discovered = False

    def discover_plugins(self) -> int:
        """
        Discover and load plugins from entry_points.

        Returns:
            Number of plugins discovered
        """
        if self._discovered:
            return len(self._plugins)

        discovered_count = 0

        # Discover via entry_points
        try:
            entry_points = importlib.metadata.entry_points(group=PLUGIN_ENTRY_POINT)
            for ep in entry_points:
                try:
                    plugin_class = ep.load()
                    self._register_plugin_class(ep.name, plugin_class)
                    discovered_count += 1
                    logger.debug("Discovered plugin via entry_point", plugin=ep.name)
                except Exception as e:
                    logger.warning(
                        "Failed to load plugin from entry_point",
                        plugin=ep.name,
                        error=str(e),
                    )
        except Exception as e:
            logger.warning("Failed to load entry_points", error=str(e))

        self._discovered = True
        logger.info("Plugin discovery complete", count=discovered_count)
        return discovered_count

    def register_plugin(self, plugin: SpectrePlugin) -> None:
        """
        Manually register a plugin instance.

        Args:
            plugin: The plugin instance to register
        """
        if plugin.name in self._plugins:
            logger.warning("Overwriting existing plugin", plugin=plugin.name)
        self._plugins[plugin.name] = plugin
        logger.debug("Registered plugin", plugin=plugin.name)

    def _register_plugin_class(
        self, name: str, plugin_class: type[SpectrePlugin]
    ) -> None:
        """Register a plugin class (lazy instantiation)."""
        if not issubclass(plugin_class, SpectrePlugin):
            raise PluginLoadError(
                f"Plugin class {plugin_class} must inherit from SpectrePlugin"
            )
        self._plugin_classes[name] = plugin_class

    def get_plugin(self, name: str) -> SpectrePlugin:
        """
        Get a plugin by name.

        Args:
            name: The plugin name

        Returns:
            The plugin instance

        Raises:
            PluginNotFoundError: If the plugin is not found
        """
        # Check if already instantiated
        if name in self._plugins:
            return self._plugins[name]

        # Try to instantiate from class
        if name in self._plugin_classes:
            try:
                plugin = self._plugin_classes[name]()
                self._plugins[name] = plugin
                return plugin
            except Exception as e:
                raise PluginLoadError(f"Failed to instantiate plugin {name}: {e}") from e

        raise PluginNotFoundError(f"Plugin '{name}' not found")

    def has_plugin(self, name: str) -> bool:
        """Check if a plugin exists."""
        return name in self._plugins or name in self._plugin_classes

    def list_plugins(self) -> list[SpectrePlugin]:
        """
        List all available plugins.

        Returns:
            List of plugin instances
        """
        # Ensure all plugins are instantiated
        all_names = set(self._plugins.keys()) | set(self._plugin_classes.keys())
        plugins = []
        for name in sorted(all_names):
            try:
                plugins.append(self.get_plugin(name))
            except PluginLoadError as e:
                logger.warning("Failed to load plugin for listing", plugin=name, error=str(e))
        return plugins

    def list_plugin_names(self) -> list[str]:
        """List all available plugin names."""
        return sorted(set(self._plugins.keys()) | set(self._plugin_classes.keys()))

    def get_plugins_by_category(self, category: PluginCategory) -> list[SpectrePlugin]:
        """Get all plugins in a specific category."""
        return [p for p in self.list_plugins() if p.category == category]

    def get_plugins_for_entity(self, entity_type: EntityType) -> list[SpectrePlugin]:
        """Get all plugins that accept a specific entity type as input."""
        return [p for p in self.list_plugins() if p.accepts_entity(entity_type)]

    def iter_plugins(self) -> Iterator[SpectrePlugin]:
        """Iterate over all plugins."""
        yield from self.list_plugins()

    async def execute_plugin(
        self,
        name: str,
        entity: dict[str, Any],
        config: PluginConfig | None = None,
    ) -> PluginResult:
        """
        Execute a plugin by name.

        Args:
            name: The plugin name
            entity: The entity to process
            config: Optional plugin configuration

        Returns:
            PluginResult from the plugin execution
        """
        plugin = self.get_plugin(name)
        return await plugin.execute(entity, config)

    async def check_plugin_health(self, name: str) -> bool:
        """
        Check health of a specific plugin.

        Args:
            name: The plugin name

        Returns:
            True if the plugin is healthy
        """
        plugin = self.get_plugin(name)
        return await plugin.health_check()

    async def check_all_health(self) -> dict[str, bool]:
        """
        Check health of all plugins.

        Returns:
            Dict mapping plugin names to health status
        """
        results = {}
        for plugin in self.list_plugins():
            try:
                results[plugin.name] = await plugin.health_check()
            except Exception as e:
                logger.warning("Health check failed", plugin=plugin.name, error=str(e))
                results[plugin.name] = False
        return results

    def get_plugin_info(self, name: str) -> dict[str, Any]:
        """Get information about a specific plugin."""
        plugin = self.get_plugin(name)
        return plugin.get_info()

    def get_all_info(self) -> list[dict[str, Any]]:
        """Get information about all plugins."""
        return [p.get_info() for p in self.list_plugins()]

    def __len__(self) -> int:
        return len(set(self._plugins.keys()) | set(self._plugin_classes.keys()))

    def __contains__(self, name: str) -> bool:
        return self.has_plugin(name)

    def __iter__(self) -> Iterator[SpectrePlugin]:
        return self.iter_plugins()


# Global registry instance
_global_registry: PluginRegistry | None = None


def get_registry() -> PluginRegistry:
    """
    Get the global plugin registry.

    Creates and initializes the registry on first call.

    Returns:
        The global PluginRegistry instance
    """
    global _global_registry
    if _global_registry is None:
        _global_registry = PluginRegistry()
        _global_registry.discover_plugins()
    return _global_registry


def reset_registry() -> None:
    """Reset the global registry (mainly for testing)."""
    global _global_registry
    _global_registry = None
