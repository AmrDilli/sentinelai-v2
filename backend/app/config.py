"""Central configuration. All settings come from environment variables (.env)."""
import os
from pathlib import Path

# Load .env if present (no external dependency)
_env_path = Path(__file__).resolve().parents[2] / ".env"
if _env_path.exists():
    for line in _env_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())


class Settings:
    # AI provider: "deepseek", "claude", or "mock" (no API key needed)
    AI_PROVIDER: str = os.getenv("AI_PROVIDER", "mock")
    DEEPSEEK_API_KEY: str = os.getenv("DEEPSEEK_API_KEY", "")
    DEEPSEEK_BASE_URL: str = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1")
    DEEPSEEK_MODEL: str = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
    ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
    CLAUDE_MODEL: str = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-6")

    # Threat intel enrichment (optional — modules degrade gracefully without keys)
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")

    # Pipeline
    UPLOAD_DIR: Path = Path(os.getenv("UPLOAD_DIR", "/tmp/sentinelai_uploads"))
    MAX_UPLOAD_MB: int = int(os.getenv("MAX_UPLOAD_MB", "200"))
    MAX_OBSERVATIONS_TO_AI: int = int(os.getenv("MAX_OBSERVATIONS_TO_AI", "80"))

    # AI quality toggles
    AI_SELF_VERIFY: bool = os.getenv("AI_SELF_VERIFY", "0") not in ("0", "false", "False", "")
    AI_CACHE: bool = os.getenv("AI_CACHE", "1") not in ("0", "false", "False", "")

    # Persistence (SQLite path; cases survive restart)
    DB_PATH: str = os.getenv("DB_PATH", str(Path(os.getenv("UPLOAD_DIR", "/tmp/sentinelai_uploads")) / "sentinelai.db"))

    # SOAR thresholds (0-100 score)
    SOAR_NOTIFY_THRESHOLD: int = 1     # low
    SOAR_APPROVAL_THRESHOLD: int = 40  # medium
    SOAR_AUTO_THRESHOLD: int = 70      # high/critical


settings = Settings()
settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
