"""Plugins router - plugin listing and status."""

from fastapi import APIRouter
from pydantic import BaseModel

from spectre.plugins.registry import PluginRegistry


router = APIRouter(prefix="/plugins")


class PluginInfo(BaseModel):
    """Plugin information."""

    name: str
    description: str
    category: str
    enabled: bool
    input_types: list[str]
    output_types: list[str]
    requires_config: list[str]


class PluginHealthResponse(BaseModel):
    """Plugin health check response."""

    name: str
    healthy: bool
    message: str | None = None


class PluginListResponse(BaseModel):
    """List of plugins response."""

    plugins: list[PluginInfo]
    total: int


@router.get("", response_model=PluginListResponse)
async def list_plugins() -> PluginListResponse:
    """List all available plugins."""
    registry = PluginRegistry()
    plugins = []

    for name, plugin_class in registry.plugins.items():
        # Instantiate to get metadata
        try:
            plugin = plugin_class()
            plugins.append(
                PluginInfo(
                    name=plugin.name,
                    description=plugin.description,
                    category=getattr(plugin, "category", "osint"),
                    enabled=True,
                    input_types=[t.value if hasattr(t, "value") else str(t) for t in plugin.input_types],
                    output_types=[t.value if hasattr(t, "value") else str(t) for t in plugin.output_types],
                    requires_config=list(plugin.required_config) if plugin.required_config else [],
                )
            )
        except Exception:
            # Plugin failed to instantiate, skip it
            continue

    return PluginListResponse(plugins=plugins, total=len(plugins))


@router.get("/{plugin_name}/health", response_model=PluginHealthResponse)
async def plugin_health(plugin_name: str) -> PluginHealthResponse:
    """Check health of a specific plugin."""
    registry = PluginRegistry()

    if plugin_name not in registry.plugins:
        return PluginHealthResponse(
            name=plugin_name,
            healthy=False,
            message=f"Plugin '{plugin_name}' not found",
        )

    try:
        plugin_class = registry.plugins[plugin_name]
        plugin = plugin_class()
        is_healthy = await plugin.health_check()
        return PluginHealthResponse(
            name=plugin_name,
            healthy=is_healthy,
            message="Plugin is operational" if is_healthy else "Plugin health check failed",
        )
    except Exception as e:
        return PluginHealthResponse(
            name=plugin_name,
            healthy=False,
            message=str(e),
        )
