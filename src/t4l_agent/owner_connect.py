from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from .pairing import VerifiedOwnerIdentity
from .runtime_adapter import ConnectResult, RuntimeAdapter, RuntimeTarget

_CONNECT_PREFIX_RE = re.compile(r"^\s*/t4l\s+connect(?:\s|$)", re.IGNORECASE)
_CONNECT_COMMAND_RE = re.compile(
    r"^\s*/t4l\s+connect\s+([A-Za-z0-9-]{4,64})\s*$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class PreModelResult:
    handled: bool
    reply: str = ""
    connect_result: ConnectResult | None = None


class PreModelHandler(Protocol):
    def handle(
        self,
        message: Mapping[str, Any],
        *,
        verified_owner: VerifiedOwnerIdentity | None = None,
    ) -> PreModelResult: ...


@dataclass
class OwnerConnectInterceptor:
    """Consumes owner pairing commands before any model sees their contents."""

    adapter: RuntimeAdapter
    target: RuntimeTarget

    def handle(
        self,
        message: Mapping[str, Any],
        *,
        verified_owner: VerifiedOwnerIdentity | None = None,
    ) -> PreModelResult:
        content = message.get("content")
        text = content if isinstance(content, str) else ""
        if not _CONNECT_PREFIX_RE.search(text):
            return PreModelResult(handled=False)
        match = _CONNECT_COMMAND_RE.fullmatch(text)
        if match is None:
            return PreModelResult(
                handled=True,
                reply="Use the exact command /t4l connect CODE.",
            )
        result = self.adapter.consume_owner_connect(
            self.target,
            code=match.group(1),
            owner=verified_owner,
        )
        return PreModelResult(
            handled=True,
            reply=result.message,
            connect_result=result,
        )
