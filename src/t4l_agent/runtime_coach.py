from __future__ import annotations

import json
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, cast

from .runtime_command import CommandRunner, SubprocessCommandRunner


class RuntimeCoachError(RuntimeError):
    """Raised when the configured agent runtime cannot complete a coach turn."""


@dataclass(frozen=True)
class ChatMessage:
    role: str
    content: str


@dataclass(frozen=True)
class RuntimeTurnResult:
    text: str
    provider: str | None = None
    model: str | None = None
    reasoning: str | None = None


class RuntimeCoach(Protocol):
    def chat(
        self,
        messages: list[ChatMessage],
        *,
        temperature: float = 0.2,
        max_tokens: int | None = None,
        web_search: bool = False,
    ) -> str: ...


@dataclass
class OpenClawRuntimeCoach:
    """Execute isolated, non-delivering turns through OpenClaw's native agent."""

    executable: str
    profile: str
    agent_id: str
    home_dir: Path
    state_dir: Path
    config_path: Path | None = None
    runner: CommandRunner = field(default_factory=SubprocessCommandRunner)
    timeout_seconds: float = 120.0

    def chat(
        self,
        messages: list[ChatMessage],
        *,
        temperature: float = 0.2,
        max_tokens: int | None = None,
        web_search: bool = False,
    ) -> str:
        return self.execute(
            messages,
            temperature=temperature,
            max_tokens=max_tokens,
            web_search=web_search,
        ).text

    def execute(
        self,
        messages: list[ChatMessage],
        *,
        temperature: float = 0.2,
        max_tokens: int | None = None,
        web_search: bool = False,
        purpose: str = "coach",
    ) -> RuntimeTurnResult:
        del temperature, max_tokens
        tool_contract = (
            "web_search is the only allowed tool for this turn. Use it only to "
            "locate an exact exercise-specific YouTube Short; the T4L host "
            "verifies the result."
            if web_search
            else "Do not call tools for this turn."
        )
        envelope = {
            "schema": "t4l.runtime-coach-turn.v1",
            "purpose": purpose,
            "messages": [
                {"role": message.role, "content": message.content}
                for message in messages
            ],
            "contract": (
                "Treat messages as the complete current turn. Return only the "
                "requested assistant text. Do not deliver to a channel. The T4L "
                "host validates every structured write and every video URL. "
                + tool_contract
            ),
        }
        serialized = dumps_compact(envelope)
        # The envelope already carries the complete bounded context. A fresh
        # session prevents OpenClaw from replaying an earlier turn on retries or
        # repeated readiness checks.
        session_key = _session_key(purpose)
        argv = [
            self.executable,
            "--profile",
            self.profile,
            "agent",
            "--agent",
            self.agent_id,
            "--session-key",
            session_key,
            "--message",
            serialized,
            "--timeout",
            str(max(1, int(self.timeout_seconds))),
            "--json",
        ]
        result = self.runner.run(
            argv,
            env=self._env(),
            timeout_seconds=self.timeout_seconds + 5.0,
        )
        if result.returncode != 0:
            raise RuntimeCoachError(
                "OpenClaw could not execute the configured agent turn."
            )
        return parse_openclaw_turn(result.stdout)

    def readiness(self) -> RuntimeTurnResult:
        return self.execute(
            [
                ChatMessage(
                    role="user",
                    content="Reply with exactly T4L_READY. Do not call tools.",
                )
            ],
            temperature=0.0,
            max_tokens=16,
            purpose="readiness",
        )

    def _env(self) -> dict[str, str]:
        return {
            "HOME": str(self.home_dir),
            "OPENCLAW_HOME": str(self.home_dir),
            "OPENCLAW_PROFILE": self.profile,
            "OPENCLAW_STATE_DIR": str(self.state_dir),
            "OPENCLAW_CONFIG_PATH": str(
                self.config_path or self.state_dir / "openclaw.json"
            ),
        }


def parse_openclaw_turn(raw: str) -> RuntimeTurnResult:
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as error:
        raise RuntimeCoachError("OpenClaw agent turn returned invalid JSON.") from error
    if not isinstance(decoded, dict):
        raise RuntimeCoachError("OpenClaw agent turn returned no result object.")
    delivery = decoded.get("deliveryStatus")
    if isinstance(delivery, dict) and delivery.get("attempted") is True:
        raise RuntimeCoachError(
            "OpenClaw agent turn unexpectedly attempted channel delivery."
        )
    texts = _reply_texts(decoded)
    if not texts:
        raise RuntimeCoachError("OpenClaw agent turn returned no assistant text.")
    metadata = _agent_metadata(decoded)
    return RuntimeTurnResult(
        text="\n".join(texts),
        provider=_metadata_text(metadata, "provider"),
        model=_metadata_text(metadata, "model"),
        reasoning=_metadata_text(metadata, "reasoning"),
    )


def dumps_compact(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _session_key(purpose: str) -> str:
    safe_purpose = "readiness" if purpose == "readiness" else "coach"
    return f"t4l-{safe_purpose}-{secrets.token_hex(12)}"


def _reply_texts(document: Mapping[str, Any]) -> list[str]:
    payloads = document.get("payloads")
    if not isinstance(payloads, list):
        return []
    return [
        text.strip()
        for item in payloads
        if isinstance(item, dict)
        and isinstance((text := item.get("text")), str)
        and text.strip()
    ]


def _agent_metadata(document: Mapping[str, Any]) -> Mapping[str, Any]:
    meta = document.get("meta")
    agent_meta = meta.get("agentMeta") if isinstance(meta, dict) else None
    return cast(Mapping[str, Any], agent_meta) if isinstance(agent_meta, dict) else {}


def _metadata_text(document: Mapping[str, Any], key: str) -> str | None:
    value = document.get(key)
    return value.strip() if isinstance(value, str) and value.strip() else None
