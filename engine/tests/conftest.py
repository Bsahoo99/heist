import shutil
import subprocess
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

FIXTURES_DIR = Path(__file__).parent.resolve() / "fixtures"


@pytest.fixture
def vuln_app_path() -> Path:
    return FIXTURES_DIR / "vuln_app"


@pytest.fixture
def clean_app_path() -> Path:
    return FIXTURES_DIR / "clean_app"


@pytest.fixture
def tmp_copy(tmp_path: Path) -> Callable[[Path], Path]:
    def _copy(path: Path) -> Path:
        dest = tmp_path / path.name
        shutil.copytree(path, dest)
        return dest

    return _copy


def _docker_up() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        res = subprocess.run(["docker", "info"], capture_output=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return res.returncode == 0


@pytest.fixture(scope="session")
def pg_container() -> Iterator[Any]:
    """One throwaway Postgres 16 for every `docker` test; skips them when Docker is not running."""
    if not _docker_up():
        pytest.skip("Docker is not running")
    from testcontainers.community.postgres import PostgresContainer

    with PostgresContainer("postgres:16", driver=None) as pg:
        yield pg


@pytest.fixture(scope="session")
def pg_dsn(pg_container: Any) -> str:
    return pg_container.get_connection_url()
