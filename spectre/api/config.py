"""API Configuration."""

from pydantic_settings import BaseSettings


class APISettings(BaseSettings):
    """Settings for the SPECTRE API."""

    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = True

    # CORS
    cors_origins: list[str] = [
        "http://localhost:5173",  # Vite dev server
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
    ]

    # API
    api_prefix: str = "/api/v1"
    title: str = "SPECTRE API"
    description: str = "Security Platform for Enrichment, Collection, Threat Research & Evaluation"
    version: str = "0.1.0"

    # WebSocket
    ws_heartbeat_interval: int = 30  # seconds

    class Config:
        env_prefix = "SPECTRE_API_"


settings = APISettings()
