from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from t4l_agent.pairing import VerifiedOwnerIdentity
from t4l_agent.runtime_adapter import (
    AdapterStatus,
    BootstrapResult,
    BootstrapSpec,
    ConnectResult,
    RuntimeAdapter,
    RuntimeKind,
    RuntimeProbe,
    RuntimeTarget,
)
from t4l_agent.runtime_cli import run_runtime_adapter_cli


class RecordingAdapter(RuntimeAdapter):
    def __init__(self) -> None:
        self.applied: tuple[BootstrapSpec, str] | None = None

    def probe(self, target: RuntimeTarget) -> RuntimeProbe:
        return RuntimeProbe(
            runtime=target.runtime,
            status=AdapterStatus.READY,
            supported=True,
            agent_id=target.agent_id,
            profile=target.profile,
        )

    def snapshot(self, target: RuntimeTarget) -> BootstrapResult:
        return BootstrapResult(
            AdapterStatus.SNAPSHOTTED,
            "snapshot",
            self.probe(target),
            rollback_id="a" * 32,
            checks={"snapshot": True},
        )

    def apply(self, spec: BootstrapSpec, rollback_id: str) -> BootstrapResult:
        self.applied = (spec, rollback_id)
        return BootstrapResult(
            AdapterStatus.CONFIGURED,
            "configured",
            self.probe(spec.target),
            rollback_id=rollback_id,
            checks={"identity": True},
        )

    def verify(self, spec: BootstrapSpec) -> BootstrapResult:
        raise AssertionError("not used")

    def rollback(self, target: RuntimeTarget, rollback_id: str) -> BootstrapResult:
        raise AssertionError("not used")

    def consume_owner_connect(
        self,
        target: RuntimeTarget,
        *,
        code: str,
        owner: VerifiedOwnerIdentity | None,
        request_id: str | None = None,
    ) -> ConnectResult:
        raise AssertionError("not used")


def _envelope(tmp_path: Path) -> dict[str, object]:
    return {
        "action": "apply",
        "agent": {
            "agentId": "agent-01",
            "runtime": "openclaw",
            "profile": "agent-01",
            "homeDir": str(tmp_path / "home"),
            "stateDir": str(tmp_path / "state"),
            "executable": "openclaw",
        },
        "spec": {
            "t4lServerUrl": "http://127.0.0.1:8787/mcp",
            "instructionBundleDir": str(tmp_path / "instructions"),
            "t4lTokenEnv": "MCP_T4L_API_KEY",
            "connectorBaseUrl": "http://127.0.0.1:8787",
            "connectorRuntimeTokenEnv": "T4L_CONNECTOR_RUNTIME_TOKEN",
            "openclawPluginDir": str(tmp_path / "plugin"),
        },
        "rollbackId": "a" * 32,
    }


def test_runtime_adapter_cli_maps_canonical_json_without_secret_values(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    adapter = RecordingAdapter()
    monkeypatch.setattr("t4l_agent.runtime_cli.adapter_for", lambda runtime: adapter)
    output = io.StringIO()

    status = run_runtime_adapter_cli(
        input_stream=io.StringIO(json.dumps(_envelope(tmp_path))),
        output_stream=output,
    )

    assert status == 0
    response = json.loads(output.getvalue())
    assert response["ok"] is True
    assert response["code"] == "configured"
    assert response["rollbackId"] == "a" * 32
    assert adapter.applied is not None
    spec, rollback_id = adapter.applied
    assert rollback_id == "a" * 32
    assert spec.target.agent_id == "agent-01"
    assert spec.target.runtime is RuntimeKind.OPENCLAW
    assert spec.connector_runtime_token_env == "T4L_CONNECTOR_RUNTIME_TOKEN"
    assert spec.openclaw_plugin_dir == tmp_path / "plugin"


def test_runtime_adapter_cli_rejects_secret_fields_before_dispatch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        "t4l_agent.runtime_cli.adapter_for",
        lambda runtime: (_ for _ in ()).throw(AssertionError("adapter called")),
    )
    envelope = _envelope(tmp_path)
    envelope["providerApiKey"] = "must-not-cross-stdin"
    output = io.StringIO()

    status = run_runtime_adapter_cli(
        input_stream=io.StringIO(json.dumps(envelope)),
        output_stream=output,
    )

    assert status == 1
    response = json.loads(output.getvalue())
    assert response["ok"] is False
    assert "secret field is forbidden" in response["message"]
    assert "must-not-cross-stdin" not in output.getvalue()
