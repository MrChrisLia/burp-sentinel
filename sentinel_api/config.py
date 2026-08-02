"""Environment-driven configuration. No hardcoded paths (design rule 6/7)."""
import os
from pathlib import Path


def _load_dotenv(path: Path) -> None:
    if not path.is_file():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key or key in os.environ:
            continue
        if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
            value = value[1:-1]
        os.environ[key] = value


_ROOT_DIR = Path(__file__).resolve().parent.parent
_CWD_DOTENV = Path.cwd() / ".env"
_ROOT_DOTENV = _ROOT_DIR / ".env"
if _CWD_DOTENV.is_file():
    _load_dotenv(_CWD_DOTENV)
elif _ROOT_DOTENV.is_file():
    _load_dotenv(_ROOT_DOTENV)


class Settings:
    provider: str = os.getenv("SENTINEL_PROVIDER", "mock")
    base_url: str = os.getenv("SENTINEL_BASE_URL", "")
    model: str = os.getenv("SENTINEL_MODEL", "")
    api_key: str = os.getenv("SENTINEL_API_KEY", "")
    db_path: str = os.getenv("SENTINEL_DB_PATH", "sentinel_api/data/sentinel.sqlite")


settings = Settings()
