from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Protocol

_SHORT_RE = re.compile(
    r"^https://www\.youtube\.com/shorts/(?P<video_id>[A-Za-z0-9_-]{11})$"
)
_WORD_RE = re.compile(r"[a-z0-9]+")
_IGNORED_WORDS = frozenset(
    {"the", "and", "with", "how", "to", "proper", "form", "tutorial", "exercise"}
)


class ExerciseVideoVerifier(Protocol):
    def verify(self, *, exercise_id: str, name: str, url: str) -> bool: ...


@dataclass(frozen=True)
class YouTubeOEmbedVerifier:
    """Fail-closed existence and title check for a model-selected Short."""

    timeout_seconds: float = 8.0

    def verify(self, *, exercise_id: str, name: str, url: str) -> bool:
        del exercise_id
        if _SHORT_RE.fullmatch(url) is None:
            return False
        query = urllib.parse.urlencode({"url": url, "format": "json"})
        request = urllib.request.Request(
            f"https://www.youtube.com/oembed?{query}",
            headers={"accept": "application/json"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(
                request,
                timeout=self.timeout_seconds,
            ) as response:
                decoded = json.loads(response.read().decode("utf-8"))
        except (OSError, urllib.error.HTTPError, json.JSONDecodeError):
            return False
        if not isinstance(decoded, dict):
            return False
        title = decoded.get("title")
        return isinstance(title, str) and _title_matches(name, title)


def _title_matches(exercise_name: str, title: str) -> bool:
    expected = {
        word
        for word in _WORD_RE.findall(exercise_name.casefold())
        if len(word) >= 3 and word not in _IGNORED_WORDS
    }
    actual = set(_WORD_RE.findall(title.casefold()))
    return bool(expected) and expected.issubset(actual)
