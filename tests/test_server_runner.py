from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest
from t4l_server.connector import SetupAdapter

from t4l_agent.cli import _is_canonical_owner_identity, _is_loopback_bind, main
from t4l_agent.server_runner import EmbeddedT4LServer


def test_loopback_connector_relies_on_gateway_https_and_disables_legacy_token(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    captured: dict[str, Any] = {}

    def fake_create_server(config: Any) -> object:
        captured["config"] = config
        return object()

    monkeypatch.setattr("t4l_agent.server_runner.create_server", fake_create_server)
    EmbeddedT4LServer(
        data_dir=tmp_path,
        host="127.0.0.1",
        port=8787,
        api_key="server-test-key",
        agent_id="agent-01",
        agent_name="Atlas",
        agent_runtime="openclaw",
        agent_provider="customer-provider",
        agent_model="customer-model",
        agent_reasoning="runtime-default",
        connector_runtime_token="runtime-test-token",
        connector_setup_adapter=cast(SetupAdapter, object()),
    )

    assert captured["config"].require_https is False
    assert captured["config"].allow_legacy_app_token is False


def test_only_explicit_loopback_hosts_are_safe_defaults() -> None:
    assert _is_loopback_bind("127.0.0.1")
    assert _is_loopback_bind("::1")
    assert _is_loopback_bind("localhost")
    assert not _is_loopback_bind("0.0.0.0")
    assert not _is_loopback_bind("10.0.0.4")


def test_public_connector_keeps_server_https_enforcement(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    captured: dict[str, Any] = {}
    monkeypatch.setattr(
        "t4l_agent.server_runner.create_server",
        lambda config: captured.setdefault("config", config) or object(),
    )
    EmbeddedT4LServer(
        data_dir=tmp_path,
        host="0.0.0.0",
        port=8787,
        api_key="server-test-key",
        agent_id="agent-01",
        agent_name="Atlas",
        agent_runtime="openclaw",
        agent_provider=None,
        agent_model=None,
        agent_reasoning=None,
        connector_runtime_token="runtime-test-token",
        connector_setup_adapter=cast(SetupAdapter, object()),
    )

    assert captured["config"].require_https is True


def test_owner_allowlist_uses_channel_account_sender_identity() -> None:
    assert _is_canonical_owner_identity("slack:T012345:U012345")
    assert _is_canonical_owner_identity("webchat:local:owner-01")
    assert not _is_canonical_owner_identity("U012345")
    assert not _is_canonical_owner_identity("slack::U012345")
    assert not _is_canonical_owner_identity(" slack:T012345:U012345")


def test_server_only_fails_before_exposing_pairing_without_chat_loop(
    capsys: pytest.CaptureFixture[str],
) -> None:
    status = main(["run", "--server-only"])

    assert status == 2
    assert "active in-app coach loop" in capsys.readouterr().err


def test_manual_run_rejects_the_signed_host_installer_flag(
    capsys: pytest.CaptureFixture[str],
) -> None:
    status = main(["run", "--bootstrap-plugin-preinstalled"])

    assert status == 2
    assert "reserved for the signed host installer" in capsys.readouterr().err


def test_manual_wheel_run_rejects_relative_plugin_path(
    capsys: pytest.CaptureFixture[str],
) -> None:
    status = main(
        [
            "run",
            "--bootstrap-plugin-preinstalled",
            "--release-state-file",
            "/tmp/t4l-release.json",
            "--openclaw-plugin-dir",
            "extensions/t4l-connect",
        ]
    )

    assert status == 2
    assert "must be absolute" in capsys.readouterr().err
