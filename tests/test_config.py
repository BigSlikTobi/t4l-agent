from __future__ import annotations

import pytest

from t4l_agent.config import env


def test_env_returns_process_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("T4L_TEST_VALUE", "configured-runtime")

    assert env("T4L_TEST_VALUE", "fallback") == "configured-runtime"


def test_env_returns_default_when_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("T4L_TEST_VALUE", raising=False)

    assert env("T4L_TEST_VALUE", "fallback") == "fallback"
