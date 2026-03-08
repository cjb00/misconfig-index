"""
Centralised application settings loaded from environment variables / .env file.

All configuration lives here so every other module imports from one place
instead of scattering os.getenv() calls throughout the codebase.
"""
from __future__ import annotations

from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",          # silently ignore unknown vars (e.g. GITHUB_TOKEN)
    )

    # ── Database ─────────────────────────────────────────────────────────────
    # SQLite for local dev; override with a postgres:// URL in production.
    DATABASE_URL: str = "sqlite:///./misconfig_index.db"

    # ── Server ────────────────────────────────────────────────────────────────
    ENVIRONMENT: str = "development"   # "development" | "production"
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    API_WORKERS: int = 1               # increase to cpu_count() in production

    # ── CORS ─────────────────────────────────────────────────────────────────
    # Comma-separated list of allowed origins, or "*" to allow all.
    # In production set this to your actual frontend domain.
    CORS_ORIGINS: str = "*"

    # ── GitHub OAuth ─────────────────────────────────────────────────────────
    GITHUB_CLIENT_ID: str = ""
    GITHUB_CLIENT_SECRET: str = ""

    # ── JWT ───────────────────────────────────────────────────────────────────
    JWT_SECRET: str = "change-me-in-production"   # override in .env!
    JWT_EXPIRE_DAYS: int = 7

    # ── URLs ─────────────────────────────────────────────────────────────────
    API_URL: str = "https://api.misconfig.dev"       # used in OAuth redirect URI
    FRONTEND_URL: str = "https://misconfig.dev"      # redirect after login

    # ── Stripe billing ────────────────────────────────────────────────────────
    STRIPE_SECRET_KEY: str = ""           # sk_live_... or sk_test_...
    STRIPE_PUBLISHABLE_KEY: str = ""      # pk_live_... or pk_test_...
    STRIPE_WEBHOOK_SECRET: str = ""       # whsec_...  (from Stripe dashboard → Webhooks)
    STRIPE_PRO_PRICE_ID: str = ""         # price_...  (monthly Pro recurring price)

    # ── Rate limiting (slowapi format: "N/period") ────────────────────────────
    RATE_LIMIT_PUBLIC: str = "60/minute"   # unauthenticated read endpoints
    RATE_LIMIT_BADGE: str = "120/minute"   # badge SVG (bots hit this a lot)
    RATE_LIMIT_AUTH: str = "300/minute"    # authenticated endpoints

    # ── Derived helpers ───────────────────────────────────────────────────────

    @property
    def cors_origins_list(self) -> List[str]:
        if self.CORS_ORIGINS.strip() == "*":
            return ["*"]
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @property
    def is_sqlite(self) -> bool:
        return self.DATABASE_URL.startswith("sqlite")

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() == "production"


# Single shared instance — import this everywhere.
settings = Settings()
