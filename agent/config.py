"""
Configuration loader for AutoPatch-Agent.
All environment variables are sourced from .env (never hardcoded).
"""

import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    # ── LLM ──────────────────────────────────────────
    OPENAI_API_KEY: str  = os.getenv("OPENAI_API_KEY", "")
    OPENAI_MODEL: str    = os.getenv("OPENAI_MODEL", "gpt-4o")

    # ── Datadog ──────────────────────────────────────
    DATADOG_API_KEY: str = os.getenv("DATADOG_API_KEY", "")
    DATADOG_APP_KEY: str = os.getenv("DATADOG_APP_KEY", "")
    DATADOG_SITE: str    = os.getenv("DATADOG_SITE", "datadoghq.com")

    # ── Nimble ───────────────────────────────────────
    NIMBLE_API_KEY: str  = os.getenv("NIMBLE_API_KEY", "")

    # ── ClickHouse ───────────────────────────────────
    CLICKHOUSE_HOST: str     = os.getenv("CLICKHOUSE_HOST", "")
    CLICKHOUSE_PORT: int     = int(os.getenv("CLICKHOUSE_PORT", "8443"))
    CLICKHOUSE_DB: str       = os.getenv("CLICKHOUSE_DB", "autopatch")
    CLICKHOUSE_USER: str     = os.getenv("CLICKHOUSE_USER", "default")
    CLICKHOUSE_PASSWORD: str = os.getenv("CLICKHOUSE_PASSWORD", "")

    # ── Senso.ai ─────────────────────────────────────
    SENSO_API_KEY: str   = os.getenv("SENSO_API_KEY", "")
    SENSO_BASE_URL: str  = os.getenv("SENSO_BASE_URL", "https://api.senso.ai")

    # ── AWS ──────────────────────────────────────────
    AWS_REGION: str            = os.getenv("AWS_REGION", "us-east-1")
    AWS_ACCESS_KEY_ID: str     = os.getenv("AWS_ACCESS_KEY_ID", "")
    AWS_SECRET_ACCESS_KEY: str = os.getenv("AWS_SECRET_ACCESS_KEY", "")

    # ── Agent Behaviour ──────────────────────────────
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    DRY_RUN: bool  = os.getenv("DRY_RUN", "true").lower() == "true"
    USE_MOCKS: bool = os.getenv("USE_MOCKS", "true").lower() == "true"

    @classmethod
    def validate(cls):
        """Warn about missing keys without crashing — mocks fill the gaps."""
        warnings = []
        if cls.USE_MOCKS:
            print("[config] Running in MOCK mode — no real API keys required.")
            return
        if not cls.OPENAI_API_KEY:
            warnings.append("OPENAI_API_KEY is not set")
        if not cls.DATADOG_API_KEY:
            warnings.append("DATADOG_API_KEY is not set")
        if not cls.NIMBLE_API_KEY:
            warnings.append("NIMBLE_API_KEY is not set")
        if not cls.CLICKHOUSE_HOST:
            warnings.append("CLICKHOUSE_HOST is not set")
        for w in warnings:
            print(f"[config] WARNING: {w}")
