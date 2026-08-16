from __future__ import annotations

import json
import re
import shutil
from collections.abc import Mapping, Sequence
from pathlib import Path

import yaml

from t4l_agent.pairing import (
    PairingConfirmation,
    VerifiedOwnerIdentity,
)
from t4l_agent.runtime_adapter import (
    AdapterStatus,
    BootstrapSpec,
    HermesRuntimeAdapter,
    OpenClawRuntimeAdapter,
    RuntimeKind,
    RuntimeTarget,
    verify_instruction_bundle,
)
from t4l_agent.runtime_command import CommandResult


class FakeHermesRunner:
    def __init__(
        self,
        config_path: Path,
        *,
        provider: str = "customer-provider",
        model: str = "customer-model",
        mcp_ok: bool = True,
    ) -> None:
        self.config_path = config_path
        self.provider = provider
        self.model = model
        self.mcp_ok = mcp_ok
        self.calls: list[tuple[str, ...]] = []

    def run(
        self,
        argv: Sequence[str],
        *,
        env: Mapping[str, str],
        timeout_seconds: float,
    ) -> CommandResult:
        call = tuple(argv)
        self.calls.append(call)
        if call[-1] == "--version":
            return CommandResult(0, "Hermes Agent v0.19.1\n")
        if call[-2:] == ("config", "path"):
            return CommandResult(0, f"{self.config_path}\n")
        if call[-4:] == ("config", "get", "model", "--json"):
            return CommandResult(
                0,
                json.dumps({"provider": self.provider, "default": self.model}),
            )
        if call[-2:] == ("config", "check"):
            return CommandResult(0, "Config valid\n")
        if call[-3:] == ("mcp", "test", "t4l"):
            return CommandResult(0 if self.mcp_ok else 1)
        if len(call) >= 4 and call[1:3] == ("pairing", "approve"):
            return CommandResult(0, "Approved\n")
        return CommandResult(1, stderr="unexpected fake command")


class VersionOnlyRunner:
    def run(
        self,
        argv: Sequence[str],
        *,
        env: Mapping[str, str],
        timeout_seconds: float,
    ) -> CommandResult:
        return CommandResult(0, "OpenClaw 1.0\n")


class FakeConfirmationClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, VerifiedOwnerIdentity]] = []

    def confirm(
        self,
        *,
        code: str,
        owner: VerifiedOwnerIdentity,
        request_id: str | None = None,
    ) -> PairingConfirmation:
        del request_id
        self.calls.append((code, owner))
        return PairingConfirmation(True, 200, "confirmed", "confirmed")


class FakeOpenClawRunner:
    def __init__(
        self,
        config_path: Path,
        *,
        mcp_ok: bool = True,
        gateway_ok: bool = True,
        runtime_agent_ok: bool = True,
        expose_install_path: bool = True,
        version: str = "2026.7.1-2",
    ) -> None:
        self.config_path = config_path
        self.install_path = config_path.parent / "extensions" / "t4l-connect"
        self.installed = False
        self.enabled = False
        self.mcp_ok = mcp_ok
        self.gateway_ok = gateway_ok
        self.runtime_agent_ok = runtime_agent_ok
        self.expose_install_path = expose_install_path
        self.version = version
        self.skill_dirs: list[str] = []
        self.agent_entries: dict[str, dict[str, object]] = {
            "agent-02": {
                "model": "customer-provider/customer-model",
                "thinkingDefault": "high",
                "reasoningDefault": "on",
            }
        }
        self.listed_agent_ids = {"agent-02"}
        self.mcp_config: dict[str, object] | None = None
        self.plugin_config: dict[str, object] = {
            "installRoot": "/srv/t4l/agent-02",
            "serviceMode": "systemd",
        }
        self.calls: list[tuple[str, ...]] = []
        self.call_envs: list[dict[str, str]] = []

    def run(
        self,
        argv: Sequence[str],
        *,
        env: Mapping[str, str],
        timeout_seconds: float,
    ) -> CommandResult:
        del timeout_seconds
        call = tuple(argv)
        self.calls.append(call)
        self.call_envs.append(dict(env))
        command = call[3:]
        if command == ("--version",):
            return CommandResult(0, f"OpenClaw {self.version}\n")
        if command == ("config", "file"):
            return CommandResult(
                0,
                "Configuration warning\n$OPENCLAW_HOME/state/openclaw.json\n",
            )
        if command == ("config", "get", "agents.defaults.model", "--json"):
            return CommandResult(0, '{"primary":"customer-provider/customer-model"}')
        if command == ("agents", "list", "--json"):
            return CommandResult(
                0,
                json.dumps(
                    {
                        "agents": [
                            {
                                "id": agent_id,
                                **self.agent_entries.get(agent_id, {}),
                            }
                            for agent_id in sorted(self.listed_agent_ids)
                        ]
                    }
                ),
            )
        if command == ("config", "get", "agents.entries", "--json"):
            return CommandResult(0, json.dumps(self.agent_entries))
        if command == ("config", "get", "agents.list", "--json"):
            return CommandResult(1, stderr="Config path not found")
        if command[:2] == ("config", "set") and command[2].startswith(
            "agents.entries."
        ):
            agent_id = command[2].removeprefix("agents.entries.")
            self.agent_entries[agent_id] = json.loads(command[3])
            return CommandResult(0)
        if command[:2] == ("config", "unset") and command[2].startswith(
            "agents.entries."
        ):
            agent_id = command[2].removeprefix("agents.entries.")
            self.agent_entries.pop(agent_id, None)
            return CommandResult(0)
        if command[:3] == ("plugins", "inspect", "t4l-connect"):
            if not self.installed:
                return CommandResult(1)
            payload: dict[str, object] = {
                "plugin": {
                    "id": "t4l-connect",
                    "packageName": "@t4l-trainer/openclaw-t4l-connect",
                    "version": "0.3.0",
                    "source": str(self.install_path / "dist" / "index.js"),
                },
                "install": {
                    "source": "path",
                    "version": "0.3.0",
                },
                "commands": ["t4l"],
            }
            if self.expose_install_path:
                install = payload["install"]
                assert isinstance(install, dict)
                install["installPath"] = str(self.install_path)
            if "--runtime" in command and not self.enabled:
                return CommandResult(1)
            return CommandResult(0, json.dumps(payload))
        if command[:2] == ("plugins", "install"):
            source = Path(command[2])
            self.install_path = (
                Path(env["OPENCLAW_STATE_DIR"]) / "extensions" / "t4l-connect"
            )
            self.install_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(source, self.install_path, dirs_exist_ok=True)
            self.installed = True
            return CommandResult(0, '{"installed":true}')
        if command == ("plugins", "enable", "t4l-connect"):
            self.enabled = True
            return CommandResult(0)
        if command == ("plugins", "uninstall", "t4l-connect", "--force"):
            self.installed = False
            self.enabled = False
            return CommandResult(0)
        if command[:3] == ("config", "set", "skills.load.extraDirs"):
            self.skill_dirs = json.loads(command[3])
            return CommandResult(0)
        if command == ("config", "get", "skills.load.extraDirs", "--json"):
            return CommandResult(0, json.dumps(self.skill_dirs))
        if command[:3] == ("mcp", "set", "t4l"):
            self.mcp_config = json.loads(command[3])
            return CommandResult(0)
        if command == ("config", "get", "mcp.servers.t4l", "--json"):
            if self.mcp_config is None:
                return CommandResult(1, stderr="Config path not found")
            configured = json.loads(json.dumps(self.mcp_config))
            headers = configured.get("headers")
            if isinstance(headers, dict):
                authorization = headers.get("Authorization")
                if isinstance(authorization, str):
                    match = re.fullmatch(
                        r"Bearer \$\{([A-Z_][A-Z0-9_]*)\}", authorization
                    )
                    if match is not None:
                        headers["Authorization"] = (
                            f"Bearer {env.get(match.group(1), '')}"
                        )
            return CommandResult(0, json.dumps(configured))
        if command == ("mcp", "show", "t4l", "--json"):
            if self.mcp_config is None:
                return CommandResult(1, stderr="MCP server 't4l' not found")
            rendered = json.loads(json.dumps(self.mcp_config))
            headers = rendered.get("headers")
            if isinstance(headers, dict):
                headers["Authorization"] = "Bearer real-secret-that-must-not-be-read"
            return CommandResult(0, json.dumps(rendered))
        if command == ("mcp", "unset", "t4l"):
            self.mcp_config = None
            return CommandResult(0, '{"removed":true}')
        if command == ("mcp", "doctor", "t4l", "--probe", "--json"):
            return CommandResult(
                0 if self.mcp_ok else 1, json.dumps({"ok": self.mcp_ok})
            )
        if command[:3] == ("config", "set", "plugins.entries.t4l-connect.config"):
            self.plugin_config = json.loads(command[3])
            return CommandResult(0)
        if command == (
            "config",
            "get",
            "plugins.entries.t4l-connect.config",
            "--json",
        ):
            return CommandResult(0, json.dumps(self.plugin_config))
        if command == ("config", "validate", "--json"):
            return CommandResult(
                0,
                json.dumps(
                    {"valid": True, "path": str(self.config_path), "warnings": []}
                ),
            )
        if command == ("gateway", "restart", "--json"):
            return CommandResult(0, '{"ok":true}')
        if command == ("gateway", "status", "--deep", "--require-rpc", "--json"):
            return CommandResult(0 if self.gateway_ok else 1, '{"ok":true}')
        if command and command[0] == "agent":
            if not self.runtime_agent_ok:
                return CommandResult(1, stderr="model auth failed")
            return CommandResult(
                0,
                json.dumps(
                    {
                        "payloads": [{"text": "T4L_READY"}],
                        "meta": {
                            "agentMeta": {
                                "provider": "customer-provider",
                                "model": "customer-model",
                            }
                        },
                    }
                ),
            )
        return CommandResult(1, stderr=f"unexpected: {command}")


def _target(tmp_path: Path) -> RuntimeTarget:
    home = tmp_path / "agent-01" / "home"
    state = home / ".hermes"
    state.mkdir(parents=True)
    (state / "config.yaml").write_text(
        yaml.safe_dump(
            {
                "model": {
                    "provider": "customer-provider",
                    "default": "customer-model",
                },
                "skills": {"external_dirs": ["/kept/skills"]},
                "mcp_servers": {"kept": {"url": "http://127.0.0.1:9000/mcp"}},
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return RuntimeTarget(
        runtime=RuntimeKind.HERMES,
        agent_id="agent-01",
        profile="agent-01",
        home_dir=home,
        state_dir=state,
        executable="hermes",
    )


def _bundle(tmp_path: Path) -> Path:
    root = tmp_path / "instructions"
    files = {
        "docs/setup_instruction.md": "get_planning_context accepted state",
        "docs/coaching_setup.md": (
            "AgentDescriptor phone controls accepted state review-only proposal"
        ),
        "skills/t4l-onboard-athlete/SKILL.md": (
            "write_athlete_setup_draft athlete_setup_draft.v1 "
            "contextRevision not accepted state"
        ),
        "skills/t4l-write-results/SKILL.md": (
            "https://www.youtube.com/shorts/<videoId> `superset` `circuit` "
            "Never fabricate"
        ),
    }
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def test_instruction_bundle_verifies_setup_intro_video_and_group_contract(
    tmp_path: Path,
) -> None:
    verified = verify_instruction_bundle(_bundle(tmp_path))
    assert verified.ok
    assert verified.digest is not None
    assert verified.checks == {
        "coachIntro": True,
        "exerciseVideoLinks": True,
        "supersets": True,
        "circuits": True,
    }


def test_hermes_probe_reports_model_metadata_without_enforcing_it(
    tmp_path: Path,
) -> None:
    target = _target(tmp_path)
    runner = FakeHermesRunner(target.runtime_state_dir / "config.yaml")
    result = HermesRuntimeAdapter(runner=runner).probe(target)

    assert result.status is AdapterStatus.READY
    assert result.provider == "customer-provider"
    assert result.model == "customer-model"
    assert not result.identity_verified


def test_hermes_probe_accepts_any_configured_model_metadata(tmp_path: Path) -> None:
    target = _target(tmp_path)
    runner = FakeHermesRunner(
        target.runtime_state_dir / "config.yaml",
        model="another-model",
    )

    result = HermesRuntimeAdapter(runner=runner).probe(target)

    assert result.status is AdapterStatus.READY
    assert result.model == "another-model"


def test_hermes_bootstrap_rolls_back_without_native_coach_execution(
    tmp_path: Path,
) -> None:
    target = _target(tmp_path)
    config_path = target.runtime_state_dir / "config.yaml"
    original = config_path.read_bytes()
    result = HermesRuntimeAdapter(runner=FakeHermesRunner(config_path)).bootstrap(
        BootstrapSpec(
            target=target,
            t4l_server_url="http://127.0.0.1:8787/mcp",
            instruction_bundle_dir=_bundle(tmp_path),
        )
    )

    assert result.status is AdapterStatus.FAILED
    assert result.checks["restored"] is True
    assert config_path.read_bytes() == original
    assert not (target.runtime_state_dir / "t4l-bootstrap.json").exists()


def test_verified_hermes_owner_calls_local_connector_not_hermes_pairing(
    tmp_path: Path,
) -> None:
    target = _target(tmp_path)
    config_path = target.runtime_state_dir / "config.yaml"
    runner = FakeHermesRunner(config_path)
    confirmation = FakeConfirmationClient()
    adapter = HermesRuntimeAdapter(
        runner=runner,
        confirmation_client=confirmation,
    )
    (target.runtime_state_dir / "t4l-bootstrap.json").write_text(
        json.dumps(
            {
                "runtime": "hermes",
                "agentId": "agent-01",
                "profile": "agent-01",
            }
        ),
        encoding="utf-8",
    )

    rejected = adapter.consume_owner_connect(
        target,
        code="ABCD-1234",
        owner=None,
    )
    owner = VerifiedOwnerIdentity(
        runtime="hermes",
        agent_id="agent-01",
        channel="slack",
        account_id="workspace-01",
        sender_id="owner-id",
        owner_verified=True,
    )
    connected = adapter.consume_owner_connect(
        target,
        code="ABCD-1234",
        owner=owner,
    )

    assert rejected.status is AdapterStatus.REJECTED
    assert connected.status is AdapterStatus.CONNECTED
    assert confirmation.calls == [("ABCD-1234", owner)]
    assert not any("pairing" in call for call in runner.calls)


def test_openclaw_prepares_pinned_owner_command_before_pairing(tmp_path: Path) -> None:
    home = (tmp_path / "agent-02" / "home").resolve()
    state = (tmp_path / "agent-02" / "state").resolve()
    state.mkdir(parents=True)
    config_path = (tmp_path / "custom-config" / "coach.json").resolve()
    config_path.parent.mkdir(parents=True)
    config_path.write_text("{}\n", encoding="utf-8")
    target = RuntimeTarget(
        runtime=RuntimeKind.OPENCLAW,
        agent_id="agent-02",
        profile="agent-02",
        home_dir=home,
        state_dir=state,
        config_path=config_path,
        executable="openclaw",
    )

    runner = FakeOpenClawRunner(config_path)
    adapter = OpenClawRuntimeAdapter(runner=runner)
    result = adapter.prepare_pairing_command(
        BootstrapSpec(
            target=target,
            t4l_server_url="http://127.0.0.1:8787/mcp",
            instruction_bundle_dir=_bundle(tmp_path),
            connector_base_url="http://127.0.0.1:8787",
            openclaw_plugin_dir=(
                Path(__file__).parents[1] / "openclaw_plugins" / "t4l-connect"
            ).resolve(),
        )
    )

    assert result.status is AdapterStatus.CONFIGURED
    assert result.checks == {"pairingCommand": True, "gateway": True}
    assert result.probe.native_owner_connect
    install_calls = [call for call in runner.calls if "install" in call]
    assert len(install_calls) == 1
    assert "openclaw_plugins/t4l-connect" in install_calls[0][-2]


def test_openclaw_probe_uses_structured_validated_config_path(tmp_path: Path) -> None:
    home = (tmp_path / "agent-02" / "home").resolve()
    state = (tmp_path / "agent-02" / "state").resolve()
    state.mkdir(parents=True)
    config_path = (tmp_path / "custom-config" / "coach.json").resolve()
    config_path.parent.mkdir(parents=True)
    config_path.write_text("{}\n", encoding="utf-8")
    target = RuntimeTarget(
        runtime=RuntimeKind.OPENCLAW,
        agent_id="agent-02",
        profile="agent-02",
        home_dir=home,
        state_dir=state,
        config_path=config_path,
        executable="openclaw",
    )
    runner = FakeOpenClawRunner(config_path)

    result = OpenClawRuntimeAdapter(runner=runner).probe(target)

    assert result.ok
    assert result.config_path == str(config_path)
    assert not any(call[3:] == ("config", "file") for call in runner.calls)
    assert any(call[3:] == ("config", "validate", "--json") for call in runner.calls)


def test_openclaw_pairing_rejects_unpinned_command_semantics(tmp_path: Path) -> None:
    home = (tmp_path / "agent-02" / "home").resolve()
    state = (tmp_path / "agent-02" / "state").resolve()
    state.mkdir(parents=True)
    config_path = state / "openclaw.json"
    config_path.write_text("{}\n", encoding="utf-8")
    target = RuntimeTarget(
        runtime=RuntimeKind.OPENCLAW,
        agent_id="agent-02",
        profile="agent-02",
        home_dir=home,
        state_dir=state,
        executable="openclaw",
    )
    runner = FakeOpenClawRunner(config_path, version="2026.7.1-1")

    result = OpenClawRuntimeAdapter(runner=runner).prepare_pairing_command(
        BootstrapSpec(
            target=target,
            t4l_server_url="http://127.0.0.1:8787/mcp",
            instruction_bundle_dir=_bundle(tmp_path),
            connector_base_url="http://127.0.0.1:8787",
            openclaw_plugin_dir=(
                Path(__file__).parents[1] / "openclaw_plugins" / "t4l-connect"
            ).resolve(),
        )
    )

    assert result.status is AdapterStatus.FAILED
    assert "compatible 2026.x API range" in result.details[0]
    assert not runner.installed


def test_openclaw_bootstrap_requires_every_live_readiness_check(
    tmp_path: Path,
) -> None:
    home = (tmp_path / "agent-02" / "home").resolve()
    state = (tmp_path / "agent-02" / "state").resolve()
    state.mkdir(parents=True)
    config_path = (tmp_path / "readiness-config" / "coach.json").resolve()
    config_path.parent.mkdir(parents=True)
    config_path.write_text("{}\n", encoding="utf-8")
    target = RuntimeTarget(
        runtime=RuntimeKind.OPENCLAW,
        agent_id="agent-02",
        profile="agent-02",
        home_dir=home,
        state_dir=state,
        config_path=config_path,
        executable="openclaw",
    )
    runner = FakeOpenClawRunner(config_path)
    adapter = OpenClawRuntimeAdapter(runner=runner)
    spec = BootstrapSpec(
        target=target,
        t4l_server_url="http://127.0.0.1:8787/mcp",
        instruction_bundle_dir=_bundle(tmp_path),
        connector_base_url="http://127.0.0.1:8787",
        openclaw_plugin_dir=(
            Path(__file__).parents[1] / "openclaw_plugins" / "t4l-connect"
        ).resolve(),
    )

    result = adapter.bootstrap(spec)

    assert result.status is AdapterStatus.CONFIGURED
    assert all(result.checks.values())
    assert result.checks["runtimeAgent"] is True
    assert result.checks["pluginIntegrity"] is True
    assert result.checks["mcp"] is True
    assert result.checks["tokenPolicy"] is True
    assert runner.agent_entries == {
        "agent-02": {
            "model": "customer-provider/customer-model",
            "thinkingDefault": "high",
            "reasoningDefault": "on",
            "contextInjection": "never",
            "skills": [],
            "tools": {
                "profile": "minimal",
                "alsoAllow": ["web_search"],
            },
            "heartbeat": {"every": "0m"},
        }
    }
    agent_calls = [call for call in runner.calls if "agent" in call]
    assert len(agent_calls) == 1
    agent_index = runner.calls.index(agent_calls[0])
    assert runner.call_envs[agent_index]["OPENCLAW_CONFIG_PATH"] == str(config_path)
    assert "--deliver" not in agent_calls[0]
    assert "--thinking" not in agent_calls[0]
    assert "--provider" not in agent_calls[0]
    assert "--model" not in agent_calls[0]


def test_openclaw_lean_policy_restores_an_implicit_agent_entry(
    tmp_path: Path,
) -> None:
    home = (tmp_path / "agent-02" / "home").resolve()
    state = (tmp_path / "agent-02" / "state").resolve()
    state.mkdir(parents=True)
    config_path = state / "openclaw.json"
    config_path.write_text("{}\n", encoding="utf-8")
    target = RuntimeTarget(
        runtime=RuntimeKind.OPENCLAW,
        agent_id="agent-02",
        profile="agent-02",
        home_dir=home,
        state_dir=state,
        executable="openclaw",
    )
    runner = FakeOpenClawRunner(config_path)
    runner.agent_entries = {}
    adapter = OpenClawRuntimeAdapter(runner=runner)
    spec = BootstrapSpec(
        target=target,
        t4l_server_url="http://127.0.0.1:8787/mcp",
        instruction_bundle_dir=_bundle(tmp_path),
        connector_base_url="http://127.0.0.1:8787",
        openclaw_plugin_dir=(
            Path(__file__).parents[1] / "openclaw_plugins" / "t4l-connect"
        ).resolve(),
    )

    assert adapter.bootstrap(spec).ok
    assert runner.agent_entries["agent-02"]["contextInjection"] == "never"
    snapshot = adapter.snapshot(target)
    assert snapshot.ok and snapshot.rollback_id is not None

    removed = adapter.uninstall(spec, snapshot.rollback_id)

    assert removed.ok
    assert runner.agent_entries == {}


def test_openclaw_verifies_mcp_env_reference_without_reading_real_secret(
    tmp_path: Path,
) -> None:
    home = (tmp_path / "agent-02" / "home").resolve()
    state = (tmp_path / "agent-02" / "state").resolve()
    state.mkdir(parents=True)
    config_path = state / "openclaw.json"
    config_path.write_text("{}\n", encoding="utf-8")
    target = RuntimeTarget(
        runtime=RuntimeKind.OPENCLAW,
        agent_id="agent-02",
        profile="agent-02",
        home_dir=home,
        state_dir=state,
        executable="openclaw",
    )
    runner = FakeOpenClawRunner(config_path)
    adapter = OpenClawRuntimeAdapter(runner=runner)
    spec = BootstrapSpec(
        target=target,
        t4l_server_url="http://127.0.0.1:8787/mcp",
        instruction_bundle_dir=_bundle(tmp_path),
        connector_base_url="http://127.0.0.1:8787",
        openclaw_plugin_dir=(
            Path(__file__).parents[1] / "openclaw_plugins" / "t4l-connect"
        ).resolve(),
    )

    assert adapter.bootstrap(spec).ok
    config_calls = [
        (call, runner.call_envs[index])
        for index, call in enumerate(runner.calls)
        if call[3:] == ("config", "get", "mcp.servers.t4l", "--json")
    ]
    assert config_calls
    assert all(
        command_env["MCP_T4L_API_KEY"].startswith("t4l_verify_")
        for _, command_env in config_calls
    )
    assert not any(
        call[3:] == ("mcp", "show", "t4l", "--json") for call in runner.calls
    )

    assert runner.mcp_config is not None
    headers = runner.mcp_config["headers"]
    assert isinstance(headers, dict)
    headers["Authorization"] = "Bearer real-secret-that-must-not-be-accepted"
    result = adapter.verify(spec)

    assert result.status is AdapterStatus.FAILED
    assert result.checks["instructions"] is False


def test_openclaw_update_replaces_owned_skill_and_preserves_bootstrap_config(
    tmp_path: Path,
) -> None:
    home = (tmp_path / "agent-02" / "home").resolve()
    state = (tmp_path / "agent-02" / "state").resolve()
    state.mkdir(parents=True)
    config_path = state / "openclaw.json"
    config_path.write_text("{}\n", encoding="utf-8")
    target = RuntimeTarget(
        runtime=RuntimeKind.OPENCLAW,
        agent_id="agent-02",
        profile="agent-02",
        home_dir=home,
        state_dir=state,
        executable="openclaw",
    )
    runner = FakeOpenClawRunner(config_path)
    adapter = OpenClawRuntimeAdapter(runner=runner)
    plugin = (Path(__file__).parents[1] / "openclaw_plugins" / "t4l-connect").resolve()
    first = BootstrapSpec(
        target=target,
        t4l_server_url="http://127.0.0.1:8787/mcp",
        instruction_bundle_dir=_bundle(tmp_path / "release-one"),
        connector_base_url="http://127.0.0.1:8787",
        openclaw_plugin_dir=plugin,
    )
    second = BootstrapSpec(
        target=target,
        t4l_server_url="http://127.0.0.1:8787/mcp",
        instruction_bundle_dir=_bundle(tmp_path / "release-two"),
        connector_base_url="http://127.0.0.1:8787",
        openclaw_plugin_dir=plugin,
    )

    assert adapter.bootstrap(first).ok
    assert adapter.bootstrap(second).ok
    assert runner.skill_dirs == [
        str((second.instruction_bundle_dir / "skills").resolve())
    ]
    assert runner.plugin_config["installRoot"] == "/srv/t4l/agent-02"
    assert runner.plugin_config["serviceMode"] == "systemd"
    assert runner.plugin_config["connectorBaseUrl"] == "http://127.0.0.1:8787"
    assert "runtimeTokenEnv" not in runner.plugin_config

    snapshot = adapter.snapshot(target)
    assert snapshot.ok and snapshot.rollback_id is not None
    removed = adapter.uninstall(second, snapshot.rollback_id)

    assert removed.ok
    assert any(call[3:] == ("mcp", "unset", "t4l") for call in runner.calls)
    assert not any(call[3:6] == ("mcp", "remove", "t4l") for call in runner.calls)
    assert runner.skill_dirs == []
    assert runner.plugin_config == {
        "installRoot": "/srv/t4l/agent-02",
        "serviceMode": "systemd",
        "agentId": "agent-02",
    }
    assert runner.agent_entries == {
        "agent-02": {
            "model": "customer-provider/customer-model",
            "thinkingDefault": "high",
            "reasoningDefault": "on",
        }
    }


def test_openclaw_bootstrap_rolls_back_when_runtime_agent_fails(
    tmp_path: Path,
) -> None:
    home = (tmp_path / "agent-02" / "home").resolve()
    state = (tmp_path / "agent-02" / "state").resolve()
    state.mkdir(parents=True)
    config_path = state / "openclaw.json"
    config_path.write_text("{}\n", encoding="utf-8")
    target = RuntimeTarget(
        runtime=RuntimeKind.OPENCLAW,
        agent_id="agent-02",
        profile="agent-02",
        home_dir=home,
        state_dir=state,
        executable="openclaw",
    )
    runner = FakeOpenClawRunner(config_path, runtime_agent_ok=False)

    result = OpenClawRuntimeAdapter(runner=runner).bootstrap(
        BootstrapSpec(
            target=target,
            t4l_server_url="http://127.0.0.1:8787/mcp",
            instruction_bundle_dir=_bundle(tmp_path),
            connector_base_url="http://127.0.0.1:8787",
            openclaw_plugin_dir=(
                Path(__file__).parents[1] / "openclaw_plugins" / "t4l-connect"
            ).resolve(),
        )
    )

    assert result.status is AdapterStatus.FAILED
    assert result.checks["restored"] is True
    assert "configured agent turn" in result.details[0]


def test_openclaw_pairing_fails_closed_when_installed_plugin_is_tampered(
    tmp_path: Path,
) -> None:
    home = (tmp_path / "agent-02" / "home").resolve()
    state = (tmp_path / "agent-02" / "state").resolve()
    state.mkdir(parents=True)
    config_path = state / "openclaw.json"
    config_path.write_text("{}\n", encoding="utf-8")
    target = RuntimeTarget(
        runtime=RuntimeKind.OPENCLAW,
        agent_id="agent-02",
        profile="agent-02",
        home_dir=home,
        state_dir=state,
        executable="openclaw",
    )
    runner = FakeOpenClawRunner(config_path)
    adapter = OpenClawRuntimeAdapter(runner=runner)
    spec = BootstrapSpec(
        target=target,
        t4l_server_url="http://127.0.0.1:8787/mcp",
        instruction_bundle_dir=_bundle(tmp_path),
        connector_base_url="http://127.0.0.1:8787",
        openclaw_plugin_dir=(
            Path(__file__).parents[1] / "openclaw_plugins" / "t4l-connect"
        ).resolve(),
    )
    assert adapter.prepare_pairing_command(spec).ok
    (runner.install_path / "dist" / "index.js").write_text(
        "export default {};\n",
        encoding="utf-8",
    )

    result = adapter.prepare_pairing_command(spec)

    assert result.status is AdapterStatus.FAILED
    assert result.checks["pairingCommand"] is False
    assert "content digest does not match" in result.details[0]


def test_openclaw_pairing_rejects_tampered_packaged_plugin(tmp_path: Path) -> None:
    home = (tmp_path / "agent-02" / "home").resolve()
    state = (tmp_path / "agent-02" / "state").resolve()
    state.mkdir(parents=True)
    config_path = state / "openclaw.json"
    config_path.write_text("{}\n", encoding="utf-8")
    plugin = (tmp_path / "plugin").resolve()
    shutil.copytree(
        Path(__file__).parents[1] / "openclaw_plugins" / "t4l-connect",
        plugin,
    )
    (plugin / "dist" / "index.js").write_text(
        "export default {};\n",
        encoding="utf-8",
    )
    target = RuntimeTarget(
        runtime=RuntimeKind.OPENCLAW,
        agent_id="agent-02",
        profile="agent-02",
        home_dir=home,
        state_dir=state,
        executable="openclaw",
    )
    runner = FakeOpenClawRunner(config_path)

    result = OpenClawRuntimeAdapter(runner=runner).prepare_pairing_command(
        BootstrapSpec(
            target=target,
            t4l_server_url="http://127.0.0.1:8787/mcp",
            instruction_bundle_dir=_bundle(tmp_path),
            connector_base_url="http://127.0.0.1:8787",
            openclaw_plugin_dir=plugin,
        )
    )

    assert result.status is AdapterStatus.FAILED
    assert "package content digest does not match" in result.details[0]
    assert not runner.installed


def test_openclaw_pairing_fails_when_inspect_hides_install_path(
    tmp_path: Path,
) -> None:
    home = (tmp_path / "agent-02" / "home").resolve()
    state = (tmp_path / "agent-02" / "state").resolve()
    state.mkdir(parents=True)
    config_path = state / "openclaw.json"
    config_path.write_text("{}\n", encoding="utf-8")
    target = RuntimeTarget(
        runtime=RuntimeKind.OPENCLAW,
        agent_id="agent-02",
        profile="agent-02",
        home_dir=home,
        state_dir=state,
        executable="openclaw",
    )
    runner = FakeOpenClawRunner(config_path, expose_install_path=False)

    result = OpenClawRuntimeAdapter(runner=runner).prepare_pairing_command(
        BootstrapSpec(
            target=target,
            t4l_server_url="http://127.0.0.1:8787/mcp",
            instruction_bundle_dir=_bundle(tmp_path),
            connector_base_url="http://127.0.0.1:8787",
            openclaw_plugin_dir=(
                Path(__file__).parents[1] / "openclaw_plugins" / "t4l-connect"
            ).resolve(),
        )
    )

    assert result.status is AdapterStatus.FAILED
    assert "install.installPath" in result.details[0]
    assert not runner.installed
