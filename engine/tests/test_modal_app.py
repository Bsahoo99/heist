"""The Modal app must import (to deploy it, and inside its container) with no Modal login."""

import importlib
import sys

import modal
import pytest


def test_modal_app_imports_without_credentials(monkeypatch: pytest.MonkeyPatch, tmp_path):
    for name in ("MODAL_TOKEN_ID", "MODAL_TOKEN_SECRET", "MODAL_PROFILE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("MODAL_CONFIG_PATH", str(tmp_path / "no-modal.toml"))
    sys.modules.pop("heist.modal_app", None)
    modal_app = importlib.import_module("heist.modal_app")
    assert modal_app.app.name == "heist-engine"
    assert modal_app.SECRET_NAMES == ("heist-meta", "heist-supabase")
    assert modal_app.CONTAINER_ENV["HEIST_PROVER"] == "modal"
    # One container: the live registry, joins and the rate limiter live in its memory.
    assert modal_app.MAX_CONTAINERS == 1
    assert isinstance(modal_app.web, modal.Function)


def test_the_image_pins_the_scanners():
    from heist import modal_app

    assert modal_app.SEMGREP_VERSION.count(".") == 2
    assert modal_app.GITLEAKS_VERSION.count(".") == 2
    assert modal_app.GITLEAKS_VERSION in modal_app.GITLEAKS_URL
