import shutil
from collections.abc import Callable
from pathlib import Path

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
