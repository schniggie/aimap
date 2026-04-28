"""Application configuration loaded from environment variables."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """AIMap backend settings.

    All values are loaded from environment variables or a .env file.
    """

    # Third-party API keys
    SHODAN_API_KEY: str = ""
    CENSYS_API_ID: str = ""
    CENSYS_API_SECRET: str = ""
    ANTHROPIC_API_KEY: str = ""

    # MongoDB
    MONGODB_URI: str = "mongodb://localhost:27017"
    MONGODB_DB: str = "aimap"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # Modal serverless (when True, attacks/scans dispatch to Modal containers)
    MODAL_ENABLED: bool = False

    # Clerk auth (set to enable JWT verification, e.g. https://abc-123.clerk.accounts.dev)
    CLERK_ISSUER: str = ""
    CLERK_AUDIENCE: str = ""

    # CORS
    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:80"

    model_config = {
        "env_file": (".env", "../.env"),
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
    }


settings = Settings()
