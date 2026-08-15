from __future__ import annotations

import json
from typing import Any
from urllib.request import Request

import pytest

from t4l_agent.video_verification import YouTubeOEmbedVerifier


class FakeResponse:
    def __init__(self, title: str) -> None:
        self._title = title

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps({"title": self._title}).encode()


def test_oembed_verifier_checks_live_title_for_exact_variation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_urlopen(request: Request, timeout: float) -> FakeResponse:
        captured["url"] = request.full_url
        captured["timeout"] = timeout
        return FakeResponse("Double Dumbbell Row — strict setup")

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    verifier = YouTubeOEmbedVerifier(timeout_seconds=3)

    assert verifier.verify(
        exercise_id="double_dumbbell_row",
        name="Double Dumbbell Row",
        url="https://www.youtube.com/shorts/t7VDDNKBNx8",
    )
    assert str(captured["url"]).startswith("https://www.youtube.com/oembed?")
    assert captured["timeout"] == 3


def test_oembed_verifier_rejects_wrong_variation_title(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda request, timeout: FakeResponse("Barbell Back Squat"),
    )

    assert not YouTubeOEmbedVerifier().verify(
        exercise_id="double_dumbbell_row",
        name="Double Dumbbell Row",
        url="https://www.youtube.com/shorts/t7VDDNKBNx8",
    )


def test_oembed_verifier_rejects_noncanonical_url_without_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_urlopen(*args: object, **kwargs: object) -> FakeResponse:
        raise AssertionError("noncanonical URL reached the network")

    monkeypatch.setattr("urllib.request.urlopen", fail_urlopen)

    assert not YouTubeOEmbedVerifier().verify(
        exercise_id="push_up",
        name="Push-Up",
        url="https://www.youtube.com/watch?v=qFFtrj0mdBQ",
    )
