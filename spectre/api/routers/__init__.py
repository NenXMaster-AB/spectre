"""API Routers."""

from .system import router as system_router
from .plugins import router as plugins_router
from .investigations import router as investigations_router
from .entities import router as entities_router
from .threat_actors import router as threat_actors_router
from .reports import router as reports_router

__all__ = [
    "system_router",
    "plugins_router",
    "investigations_router",
    "entities_router",
    "threat_actors_router",
    "reports_router",
]
