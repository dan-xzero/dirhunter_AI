import os
from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings shared by scanner, API, worker, and Slack handlers."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "DirHunter AI"
    environment: str = Field(default="local", validation_alias="DIRHUNTER_ENV")
    database_url: str = Field(
        default="postgresql+asyncpg://dirhunter:dirhunter@localhost:5432/dirhunter",
        validation_alias="DATABASE_URL",
    )
    redis_url: str = Field(default="redis://localhost:6379/0", validation_alias="REDIS_URL")
    portal_base_url: str = Field(default="http://localhost:3000", validation_alias="PORTAL_BASE_URL")
    report_base_url: str | None = Field(default=None, validation_alias="REPORT_BASE_URL")
    slack_signing_secret: str | None = Field(default=None, validation_alias="SLACK_SIGNING_SECRET")
    openai_api_key: str | None = Field(default=None, validation_alias="OPENAI_API_KEY")
    openai_model_vision: str = Field(default="gpt-5.5", validation_alias="OPENAI_MODEL_VISION")
    openai_model_validator: str = Field(default="gpt-5.5", validation_alias="OPENAI_MODEL_VALIDATOR")
    openai_model_fallback: str = Field(default="gpt-5-mini", validation_alias="OPENAI_MODEL_FALLBACK")
    llm_budget_usd: float = Field(default=25.0, validation_alias="LLM_BUDGET_USD")
    screenshot_root: Path = Field(default=Path("results/screenshots"), validation_alias="SCREENSHOT_ROOT")
    allowed_email_domains: str = Field(default="", validation_alias="ALLOWED_EMAIL_DOMAINS")
    session_secret: str = Field(default="change-me", validation_alias="SESSION_SECRET")

    @property
    def allowed_domains(self) -> set[str]:
        return {item.strip().lower() for item in self.allowed_email_domains.split(",") if item.strip()}

    @property
    def effective_portal_url(self) -> str:
        return self.portal_base_url.rstrip("/")

    def sync_database_url(self) -> str:
        """Return a sync SQLAlchemy URL for Alembic and utility scripts."""
        return self.database_url.replace("+asyncpg", "+psycopg")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
