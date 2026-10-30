"""The Modal app must import (to deploy it, and inside its container) with no Modal login."""

import importlib
import re
import sys
from typing import Any

import modal
import pytest

ORIGIN = "https://heist.example.test"


def _fresh_import(monkeypatch: pytest.MonkeyPatch, tmp_path, origins: str | None) -> Any:
    for name in ("MODAL_TOKEN_ID", "MODAL_TOKEN_SECRET", "MODAL_PROFILE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("MODAL_CONFIG_PATH", str(tmp_path / "no-modal.toml"))
    if origins is None:
        monkeypatch.delenv("HEIST_WEB_ORIGINS", raising=False)
    else:
        monkeypatch.setenv("HEIST_WEB_ORIGINS", origins)
    sys.modules.pop("heist.modal_app", None)
    return importlib.import_module("heist.modal_app")


def test_modal_app_imports_without_credentials(monkeypatch: pytest.MonkeyPatch, tmp_path):
    modal_app = _fresh_import(monkeypatch, tmp_path, ORIGIN)
    assert modal_app.app.name == "heist-engine"
    assert modal_app.SECRET_NAMES == ("heist-meta", "heist-supabase")
    assert modal_app.CONTAINER_ENV == {
        "HEIST_PROVER": "modal",
        "HEIST_WEB_ORIGINS": ORIGIN,
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    # One container, always up: the live registry, joins and the rate limiter live in its
    # memory, and its analysis threads must not be scaled away.
    assert modal_app.MIN_CONTAINERS == modal_app.MAX_CONTAINERS == 1
    assert modal_app.MAX_CONCURRENT_INPUTS >= 500
    assert isinstance(modal_app.web, modal.Function)


@pytest.mark.parametrize("origins", [None, "", "  "])
def test_a_deploy_without_the_web_origin_stops(monkeypatch: pytest.MonkeyPatch, tmp_path, origins):
    with pytest.raises(SystemExit, match="HEIST_WEB_ORIGINS"):
        _fresh_import(monkeypatch, tmp_path, origins)
    sys.modules.pop("heist.modal_app", None)


def test_the_image_pins_the_scanners(monkeypatch: pytest.MonkeyPatch, tmp_path):
    modal_app = _fresh_import(monkeypatch, tmp_path, ORIGIN)
    assert modal_app.SEMGREP_VERSION.count(".") == 2
    assert modal_app.GITLEAKS_VERSION.count(".") == 2
    assert modal_app.GITLEAKS_VERSION in modal_app.GITLEAKS_URL
    assert re.fullmatch(r"[0-9a-f]{64}", modal_app.GITLEAKS_SHA256)
