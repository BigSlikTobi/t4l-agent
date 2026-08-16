from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

from t4l_agent.runtime_coach import (
    ChatMessage,
    OpenClawRuntimeCoach,
    RuntimeCoachError,
    parse_openclaw_turn,
)
from t4l_agent.runtime_command import CommandResult


class RecordingRunner:
    def __init__(self, result: CommandResult) -> None:
        self.result = result
        self.calls: list[tuple[list[str], dict[str, str], float]] = []

    def run(
        self,
        argv: Sequence[str],
        *,
        env: Mapping[str, str],
        timeout_seconds: float,
    ) -> CommandResult:
        self.calls.append((list(argv), dict(env), timeout_seconds))
        return self.result


def _result(
    text: str = '{"reply":"ok"}',
    *,
    provider: str = "customer-provider",
    model: str = "customer-model",
) -> CommandResult:
    return CommandResult(
        0,
        json.dumps(
            {
                "payloads": [{"text": text}],
                "deliveryStatus": {"attempted": False},
                "meta": {
                    "agentMeta": {
                        "provider": provider,
                        "model": model,
                        "reasoning": "customer-default",
                    }
                },
            }
        ),
    )


def _coach(runner: RecordingRunner) -> OpenClawRuntimeCoach:
    return OpenClawRuntimeCoach(
        executable="openclaw",
        profile="coach-a",
        agent_id="coach-a",
        home_dir=Path("/srv/agents/coach-a/home"),
        state_dir=Path("/srv/agents/coach-a/state"),
        runner=runner,
        timeout_seconds=42,
    )


def test_executes_configured_runtime_without_provider_or_reasoning_override() -> None:
    runner = RecordingRunner(_result())
    coach = _coach(runner)

    reply = coach.chat(
        [
            ChatMessage(role="system", content="Return JSON."),
            ChatMessage(role="user", content="Build my plan."),
        ],
        temperature=0.0,
        max_tokens=900,
        web_search=True,
    )

    assert reply == '{"reply":"ok"}'
    argv, environment, timeout = runner.calls[0]
    assert argv[:6] == [
        "openclaw",
        "--profile",
        "coach-a",
        "agent",
        "--agent",
        "coach-a",
    ]
    assert "--json" in argv
    assert "--deliver" not in argv
    assert "--thinking" not in argv
    assert "--provider" not in argv
    assert "--model" not in argv
    assert environment == {
        "HOME": "/srv/agents/coach-a/home",
        "OPENCLAW_HOME": "/srv/agents/coach-a/home",
        "OPENCLAW_PROFILE": "coach-a",
        "OPENCLAW_STATE_DIR": "/srv/agents/coach-a/state",
        "OPENCLAW_CONFIG_PATH": "/srv/agents/coach-a/state/openclaw.json",
    }
    assert timeout == 47

    message = argv[argv.index("--message") + 1]
    envelope = json.loads(message)
    assert envelope["messages"] == [
        {"role": "system", "content": "Return JSON."},
        {"role": "user", "content": "Build my plan."},
    ]
    assert "hostHints" not in envelope
    assert "web_search is the only allowed tool" in envelope["contract"]


def test_metadata_is_descriptive_and_accepts_any_runtime_values() -> None:
    parsed = parse_openclaw_turn(
        _result(provider="any-provider", model="any-model").stdout
    )

    assert parsed.text == '{"reply":"ok"}'
    assert parsed.provider == "any-provider"
    assert parsed.model == "any-model"
    assert parsed.reasoning == "customer-default"


def test_readiness_uses_runtime_defaults_and_does_not_deliver() -> None:
    runner = RecordingRunner(_result("T4L_READY"))

    result = _coach(runner).readiness()

    assert result.text == "T4L_READY"
    argv = runner.calls[0][0]
    assert "--deliver" not in argv
    assert "--thinking" not in argv
    assert "--provider" not in argv
    assert "--model" not in argv


def test_identical_turns_use_fresh_sessions_without_history_replay() -> None:
    runner = RecordingRunner(_result())
    coach = _coach(runner)
    messages = [ChatMessage(role="user", content="same bounded turn")]

    coach.chat(messages)
    coach.chat(messages)

    first = runner.calls[0][0]
    second = runner.calls[1][0]
    first_key = first[first.index("--session-key") + 1]
    second_key = second[second.index("--session-key") + 1]
    assert first_key.startswith("t4l-coach-")
    assert second_key.startswith("t4l-coach-")
    assert first_key != second_key


@pytest.mark.parametrize(
    ("command_result", "message"),
    [
        (CommandResult(1, stderr="failed"), "could not execute"),
        (CommandResult(0, "not json"), "invalid JSON"),
        (CommandResult(0, "{}"), "no assistant text"),
    ],
)
def test_runtime_failures_are_fail_closed(
    command_result: CommandResult, message: str
) -> None:
    runner = RecordingRunner(command_result)

    with pytest.raises(RuntimeCoachError, match=message):
        _coach(runner).chat([ChatMessage(role="user", content="hello")])


def test_rejects_any_attempted_channel_delivery() -> None:
    raw = json.dumps(
        {
            "payloads": [{"text": "T4L_READY"}],
            "deliveryStatus": {"attempted": True},
        }
    )

    with pytest.raises(RuntimeCoachError, match="channel delivery"):
        parse_openclaw_turn(raw)
