from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class LoopConfig:
    server_url: str
    api_key: str
    poll_seconds: float
    once: bool
    recent_chat_limit: int
    instruction_bundle_dir: Path | None = None


def env(
    name: str,
    default: str = "",
) -> str:
    if name in os.environ:
        return os.environ[name]
    return default
