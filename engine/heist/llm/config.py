"""Environment loading for the LLM clients."""

import os
from pathlib import Path


def load_env(path: Path) -> None:
    """Tiny .env parser. Sets os.environ without overriding existing values."""
    if not path.exists():
        return
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key.strip(), value)


def env(name: str) -> str:
    return os.environ.get(name, "").strip()
