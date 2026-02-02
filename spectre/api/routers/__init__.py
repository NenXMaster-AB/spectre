"""API Routers."""

from .system import router as system_router
from .plugins import router as plugins_router

__all__ = ["system_router", "plugins_router"]
