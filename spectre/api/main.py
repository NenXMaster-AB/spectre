"""SPECTRE API - FastAPI Application."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from spectre.api.config import settings
from spectre.api.routers import system_router, plugins_router
from spectre.api.websocket import ConnectionManager


# Global WebSocket connection manager
ws_manager = ConnectionManager()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    # Startup
    app.state.ws_manager = ws_manager
    yield
    # Shutdown
    await ws_manager.disconnect_all()


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title=settings.title,
        description=settings.description,
        version=settings.version,
        lifespan=lifespan,
        docs_url=f"{settings.api_prefix}/docs",
        redoc_url=f"{settings.api_prefix}/redoc",
        openapi_url=f"{settings.api_prefix}/openapi.json",
    )

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Include routers
    app.include_router(system_router, prefix=settings.api_prefix, tags=["System"])
    app.include_router(plugins_router, prefix=settings.api_prefix, tags=["Plugins"])

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "spectre.api.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
    )
