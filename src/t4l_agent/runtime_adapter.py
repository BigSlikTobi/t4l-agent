from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import tempfile
import uuid
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse

import yaml

from .pairing import (
    ChannelConfirmationClient,
    HttpChannelConfirmationClient,
    VerifiedOwnerIdentity,
)
from .runtime_coach import OpenClawRuntimeCoach, RuntimeCoachError
from .runtime_command import CommandResult, CommandRunner, SubprocessCommandRunner


class RuntimeKind(StrEnum):
    HERMES = "hermes"
    OPENCLAW = "openclaw"


class AdapterStatus(StrEnum):
    READY = "ready"
    NOT_FOUND = "not_found"
    UNSUPPORTED = "unsupported"
    INVALID_TARGET = "invalid_target"
    IDENTITY_MISMATCH = "identity_mismatch"
    FAILED = "failed"
    SNAPSHOTTED = "snapshotted"
    CONFIGURED = "configured"
    VERIFIED = "verified"
    ROLLED_BACK = "rolled_back"
    CONNECTED = "connected"
    REJECTED = "rejected"


@dataclass(frozen=True)
class RuntimeTarget:
    runtime: RuntimeKind
    agent_id: str
    profile: str
    home_dir: Path
    executable: str
    state_dir: Path | None = None
    config_path: Path | None = None

    @property
    def runtime_state_dir(self) -> Path:
        if self.state_dir is not None:
            return self.state_dir
        directory = (
            ".hermes"
            if self.runtime is RuntimeKind.HERMES
            else (
                ".openclaw"
                if self.profile == "default"
                else f".openclaw-{self.profile}"
            )
        )
        return self.home_dir / directory

    @property
    def runtime_config_path(self) -> Path:
        return self.config_path or self.runtime_state_dir / "openclaw.json"


@dataclass(frozen=True)
class BootstrapSpec:
    target: RuntimeTarget
    t4l_server_url: str
    instruction_bundle_dir: Path
    t4l_token_env: str = "MCP_T4L_API_KEY"
    connector_base_url: str | None = None
    connector_runtime_token_env: str = "T4L_CONNECTOR_RUNTIME_TOKEN"
    openclaw_plugin_dir: Path | None = None

    @property
    def resolved_connector_base_url(self) -> str:
        if self.connector_base_url is not None:
            return self.connector_base_url.rstrip("/")
        parsed = urlparse(self.t4l_server_url)
        host = f"[{parsed.hostname}]" if parsed.hostname == "::1" else parsed.hostname
        port = f":{parsed.port}" if parsed.port is not None else ""
        return f"{parsed.scheme}://{host}{port}"

    @property
    def resolved_openclaw_plugin_dir(self) -> Path:
        if self.openclaw_plugin_dir is not None:
            return self.openclaw_plugin_dir
        packaged = Path(__file__).resolve().parent / "openclaw_plugins" / "t4l-connect"
        if packaged.is_dir():
            return packaged
        return Path(__file__).resolve().parents[2] / "openclaw_plugins" / "t4l-connect"


@dataclass(frozen=True)
class RuntimeProbe:
    runtime: RuntimeKind
    status: AdapterStatus
    supported: bool
    agent_id: str
    profile: str
    identity_verified: bool = False
    provider: str | None = None
    model: str | None = None
    version: str | None = None
    config_path: str | None = None
    native_owner_connect: bool = False
    message: str = ""
    details: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.status is AdapterStatus.READY

    def to_dict(self) -> dict[str, Any]:
        return {
            "runtime": self.runtime.value,
            "status": self.status.value,
            "supported": self.supported,
            "agentId": self.agent_id,
            "profile": self.profile,
            "identityVerified": self.identity_verified,
            "provider": self.provider,
            "model": self.model,
            "version": self.version,
            "configPath": self.config_path,
            "nativeOwnerConnect": self.native_owner_connect,
            "message": self.message,
            "details": list(self.details),
        }


@dataclass(frozen=True)
class RuntimeAccessResult:
    ok: bool
    message: str
    provider: str | None = None
    model: str | None = None
    reasoning: str | None = None


@dataclass(frozen=True)
class BootstrapResult:
    status: AdapterStatus
    message: str
    probe: RuntimeProbe
    rollback_id: str | None = None
    bundle_digest: str | None = None
    restart_required: bool = False
    checks: Mapping[str, bool] = field(default_factory=dict)
    details: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.status in {
            AdapterStatus.SNAPSHOTTED,
            AdapterStatus.CONFIGURED,
            AdapterStatus.VERIFIED,
            AdapterStatus.ROLLED_BACK,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "message": self.message,
            "probe": self.probe.to_dict(),
            "rollbackId": self.rollback_id,
            "bundleDigest": self.bundle_digest,
            "restartRequired": self.restart_required,
            "checks": dict(self.checks),
            "details": list(self.details),
        }


@dataclass(frozen=True)
class ConnectResult:
    status: AdapterStatus
    handled: bool
    message: str

    @property
    def ok(self) -> bool:
        return self.status is AdapterStatus.CONNECTED

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "handled": self.handled,
            "message": self.message,
        }


@dataclass(frozen=True)
class BundleVerification:
    ok: bool
    digest: str | None = None
    errors: tuple[str, ...] = ()
    checks: Mapping[str, bool] = field(default_factory=dict)


class RuntimeAdapter(ABC):
    @abstractmethod
    def probe(self, target: RuntimeTarget) -> RuntimeProbe: ...

    @abstractmethod
    def snapshot(self, target: RuntimeTarget) -> BootstrapResult: ...

    @abstractmethod
    def apply(self, spec: BootstrapSpec, rollback_id: str) -> BootstrapResult: ...

    @abstractmethod
    def verify(self, spec: BootstrapSpec) -> BootstrapResult: ...

    @abstractmethod
    def rollback(self, target: RuntimeTarget, rollback_id: str) -> BootstrapResult: ...

    def bootstrap(self, spec: BootstrapSpec) -> BootstrapResult:
        snapshot = self.snapshot(spec.target)
        if not snapshot.ok or snapshot.rollback_id is None:
            return snapshot
        return self.apply(spec, snapshot.rollback_id)

    def uninstall(self, spec: BootstrapSpec, rollback_id: str) -> BootstrapResult:
        return BootstrapResult(
            AdapterStatus.UNSUPPORTED,
            "Runtime uninstall is not supported by this adapter.",
            self.probe(spec.target),
            rollback_id=rollback_id,
        )

    @abstractmethod
    def consume_owner_connect(
        self,
        target: RuntimeTarget,
        *,
        code: str,
        owner: VerifiedOwnerIdentity | None,
        request_id: str | None = None,
    ) -> ConnectResult: ...


_IDENTITY_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_ENV_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")
_PAIRING_CODE_RE = re.compile(r"^[A-Za-z0-9-]{4,64}$")
_MANIFEST_NAME = "t4l-bootstrap.json"
_ROLLBACK_ROOT = "t4l-bootstrap/rollback"
_OPENCLAW_PLUGIN_ID = "t4l-connect"
_OPENCLAW_PLUGIN_PACKAGE = "@t4l/openclaw-t4l-connect"
_OPENCLAW_PLUGIN_VERSION = "0.2.0"
_OPENCLAW_PLUGIN_DIGEST = (
    "170515cc2f1f120b0500b1ffa742f57ec43ec1e0c564640ca29f3a9181223bf5"
)
_OPENCLAW_RUNTIME_MIN_VERSION = "2026.7.1-2"
_OPENCLAW_PLUGIN_DIGEST_FILES = (
    "package.json",
    "openclaw.plugin.json",
    "release-policy.json",
    "dist/index.js",
    "dist/bootstrap.js",
    "dist/installer.js",
    "bin/t4l-bootstrap.mjs",
    "bin/extract_instructions.py",
    "bin/verify-release-policy.mjs",
)

_BUNDLE_REQUIREMENTS: Mapping[str, tuple[str, ...]] = {
    "docs/setup_instruction.md": ("get_planning_context", "accepted state"),
    "docs/coaching_setup.md": (
        "AgentDescriptor",
        "phone controls accepted state",
        "review-only proposal",
    ),
    "skills/t4l-onboard-athlete/SKILL.md": (
        "write_athlete_setup_draft",
        "athlete_setup_draft.v1",
        "contextRevision",
        "not accepted state",
    ),
    "skills/t4l-write-results/SKILL.md": (
        "https://www.youtube.com/shorts/<videoId>",
        "`superset`",
        "`circuit`",
        "Never fabricate",
    ),
}

_BUNDLE_FEATURE_REQUIREMENTS: Mapping[str, tuple[tuple[str, str], ...]] = {
    "coachIntro": (
        ("docs/coaching_setup.md", "AgentDescriptor"),
        ("docs/coaching_setup.md", "phone controls accepted state"),
    ),
    "exerciseVideoLinks": (
        (
            "skills/t4l-write-results/SKILL.md",
            "https://www.youtube.com/shorts/<videoId>",
        ),
        ("skills/t4l-write-results/SKILL.md", "Never fabricate"),
    ),
    "supersets": (("skills/t4l-write-results/SKILL.md", "`superset`"),),
    "circuits": (("skills/t4l-write-results/SKILL.md", "`circuit`"),),
}


@dataclass
class HermesRuntimeAdapter(RuntimeAdapter):
    runner: CommandRunner = field(default_factory=SubprocessCommandRunner)
    confirmation_client: ChannelConfirmationClient | None = None
    command_timeout_seconds: float = 20.0

    def probe(self, target: RuntimeTarget) -> RuntimeProbe:
        error = _target_error(target, RuntimeKind.HERMES)
        if error is not None:
            return _probe_failure(target, AdapterStatus.INVALID_TARGET, error)
        env = self._env(target)
        version = self.runner.run(
            [target.executable, "--version"],
            env=env,
            timeout_seconds=self.command_timeout_seconds,
        )
        version_line = _first_nonempty_line(version.stdout)
        if version.returncode != 0:
            return _probe_failure(
                target,
                AdapterStatus.NOT_FOUND,
                "Hermes executable could not be verified.",
            )
        if "Hermes Agent" not in version_line:
            return _probe_failure(
                target,
                AdapterStatus.UNSUPPORTED,
                "The executable does not identify itself as Hermes Agent.",
                version=version_line or None,
                supported=False,
            )
        config_result = self.runner.run(
            [target.executable, "config", "path"],
            env=env,
            timeout_seconds=self.command_timeout_seconds,
        )
        raw_path = _first_nonempty_line(config_result.stdout)
        expected_path = target.runtime_state_dir / "config.yaml"
        if config_result.returncode != 0 or _resolved(Path(raw_path)) != _resolved(
            expected_path
        ):
            return _probe_failure(
                target,
                AdapterStatus.IDENTITY_MISMATCH,
                "Hermes resolved a config outside the requested isolated profile.",
                version=version_line,
                config_path=raw_path or None,
            )
        if expected_path.is_symlink() or not expected_path.is_file():
            return _probe_failure(
                target,
                AdapterStatus.FAILED,
                "Hermes config is missing or is an unsafe symbolic link.",
                version=version_line,
                config_path=str(expected_path),
            )
        model_result = self.runner.run(
            [target.executable, "config", "get", "model", "--json"],
            env=env,
            timeout_seconds=self.command_timeout_seconds,
        )
        provider, model = _hermes_model(model_result.stdout)
        if model_result.returncode != 0:
            provider, model = None, None
        marker_result = _identity_marker(target)
        if isinstance(marker_result, str):
            return _probe_failure(target, AdapterStatus.FAILED, marker_result)
        marker = marker_result
        if marker is not None and not _marker_matches(marker, target):
            return _probe_failure(
                target,
                AdapterStatus.IDENTITY_MISMATCH,
                "The runtime profile is already claimed by another T4L agent.",
            )
        verified = marker is not None
        return RuntimeProbe(
            target.runtime,
            AdapterStatus.READY,
            True,
            target.agent_id,
            target.profile,
            identity_verified=verified,
            provider=provider,
            model=model,
            version=version_line,
            config_path=str(expected_path),
            native_owner_connect=False,
            message=(
                "Hermes runtime identity is verified."
                if verified
                else "Hermes runtime profile is unclaimed."
            ),
            details=(
                "Hermes has no verified native pre-model command plugin; a "
                "trusted gateway adapter must call the owner-connect boundary.",
            ),
        )

    def snapshot(self, target: RuntimeTarget) -> BootstrapResult:
        probe = self.probe(target)
        if not probe.ok or probe.config_path is None:
            return BootstrapResult(probe.status, probe.message, probe)
        rollback_id = _new_rollback_id()
        try:
            _snapshot_files(
                target,
                rollback_id,
                Path(probe.config_path),
                "config.yaml",
                extra={"pluginExisted": False},
            )
        except (OSError, ValueError) as error:
            return BootstrapResult(
                AdapterStatus.FAILED,
                "Hermes snapshot failed.",
                probe,
                details=(_safe_error(error),),
            )
        return BootstrapResult(
            AdapterStatus.SNAPSHOTTED,
            "Hermes runtime snapshot created.",
            probe,
            rollback_id=rollback_id,
            checks={"snapshot": True},
        )

    def apply(self, spec: BootstrapSpec, rollback_id: str) -> BootstrapResult:
        probe = self.probe(spec.target)
        prepared = _prepare_apply(spec, probe, rollback_id)
        if prepared is not None:
            return prepared
        bundle = verify_instruction_bundle(spec.instruction_bundle_dir)
        config_path = Path(cast(str, probe.config_path))
        try:
            config = _read_yaml_mapping(config_path)
            _apply_hermes_t4l_config(config, spec)
            _write_yaml_atomic(config_path, config)
            verification_error = self._verify_config(spec, config_path)
            if verification_error is not None:
                raise RuntimeError(verification_error)
            _write_identity_marker(spec, bundle.digest)
            verified = self.verify(spec)
            if not verified.ok:
                raise RuntimeError("; ".join(verified.details) or verified.message)
            return BootstrapResult(
                AdapterStatus.CONFIGURED,
                "Hermes T4L configuration is verified.",
                verified.probe,
                rollback_id=rollback_id,
                bundle_digest=bundle.digest,
                restart_required=True,
                checks=verified.checks,
                details=("Restart the isolated Hermes gateway/chat service once.",),
            )
        except (OSError, RuntimeError, ValueError, yaml.YAMLError) as error:
            return self._failed_apply(spec.target, rollback_id, bundle.digest, error)

    def verify(self, spec: BootstrapSpec) -> BootstrapResult:
        probe = self.probe(spec.target)
        bundle = verify_instruction_bundle(spec.instruction_bundle_dir)
        error = _bootstrap_spec_error(spec)
        runtime_error = "Hermes native coach execution is not supported by this build."
        checks = {
            "identity": probe.ok and probe.identity_verified,
            "runtimeAgent": False,
            "instructions": bundle.ok,
            "mcp": False,
            "chat": False,
            "coachIntro": bundle.checks.get("coachIntro", False),
            "exerciseVideoLinks": bundle.checks.get("exerciseVideoLinks", False),
            "supersets": bundle.checks.get("supersets", False),
            "circuits": bundle.checks.get("circuits", False),
        }
        if error is not None or not checks["identity"] or probe.config_path is None:
            return BootstrapResult(
                AdapterStatus.FAILED,
                error or "Hermes identity is not bootstrapped.",
                probe,
                bundle_digest=bundle.digest,
                checks=checks,
                details=(*bundle.errors, runtime_error),
            )
        config_error = self._verify_config(spec, Path(probe.config_path))
        marker_error = _verify_marker(spec, bundle.digest)
        checks["mcp"] = config_error is None
        checks["chat"] = marker_error is None
        errors = tuple(
            item
            for item in (
                *bundle.errors,
                config_error,
                marker_error,
                runtime_error,
            )
            if item
        )
        return BootstrapResult(
            AdapterStatus.VERIFIED if all(checks.values()) else AdapterStatus.FAILED,
            "Hermes runtime verification completed."
            if not errors
            else "Hermes runtime verification failed.",
            probe,
            bundle_digest=bundle.digest,
            checks=checks,
            details=errors,
        )

    def rollback(self, target: RuntimeTarget, rollback_id: str) -> BootstrapResult:
        before = self.probe(target)
        error = _restore_files(target, rollback_id, "config.yaml")
        after = self.probe(target)
        if error is not None:
            return BootstrapResult(
                AdapterStatus.FAILED,
                "Runtime rollback failed.",
                after,
                rollback_id=rollback_id,
                details=(error,),
            )
        return BootstrapResult(
            AdapterStatus.ROLLED_BACK,
            "Runtime files were restored from the selected snapshot.",
            after,
            rollback_id=rollback_id,
            restart_required=True,
            checks={"restored": True, "previousProbeAvailable": before.supported},
        )

    def consume_owner_connect(
        self,
        target: RuntimeTarget,
        *,
        code: str,
        owner: VerifiedOwnerIdentity | None,
        request_id: str | None = None,
    ) -> ConnectResult:
        rejected = _owner_error(target, code, owner)
        if rejected is not None:
            return ConnectResult(AdapterStatus.REJECTED, True, rejected)
        probe = self.probe(target)
        if not probe.ok or not probe.identity_verified:
            return ConnectResult(
                probe.status,
                True,
                "Runtime identity must be verified before phone pairing.",
            )
        client = self.confirmation_client or _confirmation_client_from_marker(target)
        if client is None:
            return ConnectResult(
                AdapterStatus.UNSUPPORTED,
                True,
                "The connector confirmation client is not configured.",
            )
        confirmation = client.confirm(
            code=code, owner=cast(VerifiedOwnerIdentity, owner), request_id=request_id
        )
        status = AdapterStatus.CONNECTED if confirmation.ok else AdapterStatus.REJECTED
        return ConnectResult(status, True, confirmation.message)

    def _failed_apply(
        self,
        target: RuntimeTarget,
        rollback_id: str,
        digest: str | None,
        error: Exception,
    ) -> BootstrapResult:
        rollback = self.rollback(target, rollback_id)
        return BootstrapResult(
            AdapterStatus.FAILED,
            "Hermes bootstrap failed; previous files were restored."
            if rollback.ok
            else "Hermes bootstrap and rollback failed.",
            rollback.probe,
            rollback_id=rollback_id,
            bundle_digest=digest,
            checks={"restored": rollback.ok},
            details=(_safe_error(error), *rollback.details),
        )

    def _verify_config(self, spec: BootstrapSpec, config_path: Path) -> str | None:
        config = _read_yaml_mapping(config_path)
        skill_dir = str((spec.instruction_bundle_dir / "skills").resolve())
        skills = config.get("skills")
        dirs = skills.get("external_dirs") if isinstance(skills, dict) else None
        if not isinstance(dirs, list) or skill_dir not in dirs:
            return "Hermes did not retain the T4L external skill directory."
        servers = config.get("mcp_servers")
        t4l = servers.get("t4l") if isinstance(servers, dict) else None
        expected_header = f"Bearer ${{{spec.t4l_token_env}}}"
        if not isinstance(t4l, dict) or t4l.get("url") != spec.t4l_server_url:
            return "Hermes did not retain the T4L MCP URL."
        headers = t4l.get("headers")
        if (
            not isinstance(headers, dict)
            or headers.get("Authorization") != expected_header
        ):
            return "Hermes T4L MCP credential reference is wrong."
        env = self._env(spec.target)
        check = self.runner.run(
            [spec.target.executable, "config", "check"],
            env=env,
            timeout_seconds=self.command_timeout_seconds,
        )
        mcp = self.runner.run(
            [spec.target.executable, "mcp", "test", "t4l"],
            env=env,
            timeout_seconds=self.command_timeout_seconds,
        )
        if check.returncode != 0:
            return "Hermes rejected the updated configuration."
        if mcp.returncode != 0:
            return "Hermes could not verify the local T4L MCP connection."
        return None

    def _env(self, target: RuntimeTarget) -> dict[str, str]:
        return {
            "HOME": str(target.home_dir),
            "HERMES_HOME": str(target.runtime_state_dir),
        }


@dataclass
class OpenClawRuntimeAdapter(RuntimeAdapter):
    runner: CommandRunner = field(default_factory=SubprocessCommandRunner)
    command_timeout_seconds: float = 30.0

    def probe(self, target: RuntimeTarget) -> RuntimeProbe:
        error = _target_error(target, RuntimeKind.OPENCLAW)
        if error is not None:
            return _probe_failure(target, AdapterStatus.INVALID_TARGET, error)
        version = self._run(target, "--version")
        version_line = _first_nonempty_line(version.stdout)
        if version.returncode != 0:
            return _probe_failure(
                target,
                AdapterStatus.NOT_FOUND,
                "OpenClaw executable could not be verified.",
            )
        if "openclaw" not in version_line.casefold():
            return _probe_failure(
                target,
                AdapterStatus.UNSUPPORTED,
                "The executable does not identify itself as OpenClaw.",
                supported=False,
                version=version_line or None,
            )
        if not _openclaw_runtime_version_matches(version_line):
            return _probe_failure(
                target,
                AdapterStatus.UNSUPPORTED,
                "This build requires OpenClaw 2026.7.1-2 through the compatible "
                "2026.x API range.",
                supported=False,
                version=version_line or None,
            )
        expected_path = target.runtime_config_path
        if expected_path.is_symlink() or not expected_path.is_file():
            return _probe_failure(
                target,
                AdapterStatus.FAILED,
                "OpenClaw config is missing or is an unsafe symbolic link.",
                version=version_line,
                config_path=str(expected_path),
            )
        config_result = self._run(target, "config", "validate", "--json")
        try:
            config_status: object = json.loads(config_result.stdout)
        except json.JSONDecodeError:
            config_status = None
        reported_path = (
            config_status.get("path") if isinstance(config_status, dict) else None
        )
        config_matches = (
            config_result.returncode == 0
            and isinstance(config_status, dict)
            and config_status.get("valid") is True
            and isinstance(reported_path, str)
            and Path(reported_path).is_absolute()
            and _resolved(Path(reported_path)) == _resolved(expected_path)
        )
        if not config_matches:
            return _probe_failure(
                target,
                AdapterStatus.IDENTITY_MISMATCH,
                "OpenClaw did not validate the requested isolated config path.",
                version=version_line,
                config_path=str(expected_path),
            )
        model_result = self._run(
            target, "config", "get", "agents.defaults.model", "--json"
        )
        provider, model = _openclaw_model(model_result.stdout)
        if model_result.returncode != 0:
            provider, model = None, None
        agents = self._run(target, "agents", "list", "--json")
        if agents.returncode != 0 or target.agent_id not in _openclaw_agent_ids(
            agents.stdout
        ):
            return _probe_failure(
                target,
                AdapterStatus.IDENTITY_MISMATCH,
                "OpenClaw does not contain the requested isolated agent id.",
            )
        marker_result = _identity_marker(target)
        if isinstance(marker_result, str):
            return _probe_failure(target, AdapterStatus.FAILED, marker_result)
        marker = marker_result
        if marker is not None and not _marker_matches(marker, target):
            return _probe_failure(
                target,
                AdapterStatus.IDENTITY_MISMATCH,
                "The runtime profile is already claimed by another T4L agent.",
            )
        plugin_ready = self._plugin_ready(target)
        verified = marker is not None
        if verified and not plugin_ready:
            return _probe_failure(
                target,
                AdapterStatus.FAILED,
                "The T4L OpenClaw plugin is missing or did not register /t4l.",
            )
        return RuntimeProbe(
            target.runtime,
            AdapterStatus.READY,
            True,
            target.agent_id,
            target.profile,
            identity_verified=verified,
            provider=provider,
            model=model,
            version=version_line,
            config_path=str(expected_path),
            native_owner_connect=plugin_ready,
            message=(
                "OpenClaw runtime identity and owner command are verified."
                if verified
                else "OpenClaw agent profile is unclaimed."
            ),
        )

    def snapshot(self, target: RuntimeTarget) -> BootstrapResult:
        probe = self.probe(target)
        if not probe.ok or probe.config_path is None:
            return BootstrapResult(probe.status, probe.message, probe)
        rollback_id = _new_rollback_id()
        plugin_existed = self._plugin_installed(target)
        try:
            _snapshot_files(
                target,
                rollback_id,
                Path(probe.config_path),
                "openclaw.json",
                extra={"pluginExisted": plugin_existed},
            )
        except (OSError, ValueError) as error:
            return BootstrapResult(
                AdapterStatus.FAILED,
                "OpenClaw snapshot failed.",
                probe,
                details=(_safe_error(error),),
            )
        return BootstrapResult(
            AdapterStatus.SNAPSHOTTED,
            "OpenClaw runtime snapshot created.",
            probe,
            rollback_id=rollback_id,
            checks={"snapshot": True},
        )

    def prepare_pairing_command(self, spec: BootstrapSpec) -> BootstrapResult:
        """Install only the trusted pre-model owner command before phone pairing."""
        probe = self.probe(spec.target)
        spec_error = _bootstrap_spec_error(spec)
        plugin_error = _openclaw_plugin_error(spec.resolved_openclaw_plugin_dir)
        errors = tuple(item for item in (spec_error, plugin_error) if item)
        if not probe.ok or errors:
            return BootstrapResult(
                AdapterStatus.INVALID_TARGET if spec_error else AdapterStatus.FAILED,
                "OpenClaw pairing-command preflight failed.",
                probe,
                checks={"pairingCommand": False},
                details=(*errors, *((probe.message,) if not probe.ok else ())),
            )
        snapshot = self.snapshot(spec.target)
        if not snapshot.ok or snapshot.rollback_id is None:
            return snapshot
        rollback_id = snapshot.rollback_id
        try:
            if self._plugin_installed(spec.target):
                plugin_integrity_error = self._plugin_integrity_error(spec)
                if plugin_integrity_error is not None:
                    raise RuntimeError(
                        "An unverified plugin already owns the t4l-connect id: "
                        + plugin_integrity_error
                    )
            else:
                installed = self._run(
                    spec.target,
                    "plugins",
                    "install",
                    str(spec.resolved_openclaw_plugin_dir.resolve()),
                    "--force",
                )
                if installed.returncode != 0:
                    raise RuntimeError(
                        "OpenClaw rejected the pinned local T4L plugin package."
                    )
            self._configure_pairing_command(spec)
            restarted = self._run(spec.target, "gateway", "restart", "--json")
            if restarted.returncode != 0 or not self._gateway_ready(spec.target):
                raise RuntimeError(
                    "OpenClaw Gateway did not start after pairing setup."
                )
            plugin_integrity_error = self._plugin_integrity_error(spec)
            if plugin_integrity_error is not None or not self._plugin_ready(
                spec.target
            ):
                raise RuntimeError(
                    plugin_integrity_error
                    or "OpenClaw did not register the pinned /t4l command."
                )
            return BootstrapResult(
                AdapterStatus.CONFIGURED,
                "OpenClaw /t4l pairing command is ready before phone pairing.",
                self.probe(spec.target),
                rollback_id=rollback_id,
                checks={"pairingCommand": True, "gateway": True},
            )
        except (OSError, RuntimeError, ValueError) as error:
            rollback = self.rollback(spec.target, rollback_id)
            return BootstrapResult(
                AdapterStatus.FAILED,
                "Pairing-command setup failed; previous state was restored."
                if rollback.ok
                else "Pairing-command setup and rollback failed.",
                rollback.probe,
                rollback_id=rollback_id,
                checks={"pairingCommand": False, "restored": rollback.ok},
                details=(_safe_error(error), *rollback.details),
            )

    def verify_preinstalled_pairing_command(
        self, spec: BootstrapSpec
    ) -> BootstrapResult:
        """Verify an owner-installed bootstrap plugin without changing OpenClaw."""
        probe = self.probe(spec.target)
        spec_error = _bootstrap_spec_error(spec)
        packaged_error = _openclaw_plugin_error(spec.resolved_openclaw_plugin_dir)
        integrity_error = (
            self._plugin_integrity_error(spec)
            if probe.ok and not packaged_error
            else None
        )
        errors = tuple(
            item
            for item in (
                spec_error,
                packaged_error,
                integrity_error,
                None if probe.ok else probe.message,
            )
            if item
        )
        ready = probe.ok and not errors and self._plugin_ready(spec.target)
        if not ready:
            return BootstrapResult(
                AdapterStatus.FAILED,
                "The owner-installed OpenClaw bootstrap plugin is not the "
                "pinned package.",
                probe,
                checks={"pairingCommand": False, "pluginIntegrity": False},
                details=errors,
            )
        return BootstrapResult(
            AdapterStatus.VERIFIED,
            "The owner-installed OpenClaw bootstrap plugin is verified.",
            probe,
            checks={"pairingCommand": True, "pluginIntegrity": True},
        )

    def apply(self, spec: BootstrapSpec, rollback_id: str) -> BootstrapResult:
        probe = self.probe(spec.target)
        prepared = _prepare_apply(
            spec, probe, rollback_id, require_openclaw_plugin=True
        )
        if prepared is not None:
            return prepared
        bundle = verify_instruction_bundle(spec.instruction_bundle_dir)
        plugin_error = _openclaw_plugin_error(spec.resolved_openclaw_plugin_dir)
        if plugin_error is not None:
            return BootstrapResult(
                AdapterStatus.FAILED,
                plugin_error,
                probe,
                rollback_id=rollback_id,
                bundle_digest=bundle.digest,
            )
        metadata = _snapshot_metadata(spec.target, rollback_id)
        plugin_existed = metadata is not None and metadata.get("pluginExisted") is True
        try:
            if not plugin_existed:
                installed = self._run(
                    spec.target,
                    "plugins",
                    "install",
                    str(spec.resolved_openclaw_plugin_dir.resolve()),
                    "--force",
                )
                if installed.returncode != 0:
                    raise RuntimeError(
                        "OpenClaw rejected the pinned local T4L plugin package."
                    )
            else:
                plugin_integrity_error = self._plugin_integrity_error(spec)
                if plugin_integrity_error is not None or not self._plugin_ready(
                    spec.target
                ):
                    raise RuntimeError(
                        plugin_integrity_error
                        or (
                            "A pre-existing t4l-connect plugin is not the required "
                            "command plugin."
                        )
                    )
            self._configure(spec)
            _write_identity_marker(spec, bundle.digest)
            restarted = self._run(spec.target, "gateway", "restart", "--json")
            if restarted.returncode != 0:
                raise RuntimeError("OpenClaw Gateway restart failed.")
            verified = self.verify(spec)
            if not verified.ok:
                raise RuntimeError("; ".join(verified.details) or verified.message)
            return BootstrapResult(
                AdapterStatus.CONFIGURED,
                "OpenClaw T4L configuration and /t4l command are verified.",
                verified.probe,
                rollback_id=rollback_id,
                bundle_digest=bundle.digest,
                checks=verified.checks,
            )
        except (OSError, RuntimeError, ValueError) as error:
            rollback = self.rollback(spec.target, rollback_id)
            return BootstrapResult(
                AdapterStatus.FAILED,
                "OpenClaw bootstrap failed; previous state was restored."
                if rollback.ok
                else "OpenClaw bootstrap and rollback failed.",
                rollback.probe,
                rollback_id=rollback_id,
                bundle_digest=bundle.digest,
                checks={"restored": rollback.ok},
                details=(_safe_error(error), *rollback.details),
            )

    def verify(self, spec: BootstrapSpec) -> BootstrapResult:
        probe = self.probe(spec.target)
        bundle = verify_instruction_bundle(spec.instruction_bundle_dir)
        spec_error = _bootstrap_spec_error(spec)
        config_ok = self._config_matches(spec)
        plugin_ok = self._plugin_ready(spec.target)
        plugin_integrity_error = self._plugin_integrity_error(spec)
        mcp_ok = self._mcp_ready(spec.target)
        gateway_ok = self._gateway_ready(spec.target)
        runtime_access = (
            self._runtime_agent_access(spec.target)
            if gateway_ok
            else RuntimeAccessResult(
                False,
                "OpenClaw runtime agent probe was skipped because Gateway is down.",
            )
        )
        marker_error = _verify_marker(spec, bundle.digest)
        checks = {
            "identity": probe.ok and probe.identity_verified,
            "runtimeAgent": runtime_access.ok,
            "instructions": bundle.ok and config_ok,
            "mcp": mcp_ok,
            "pluginIntegrity": plugin_integrity_error is None,
            "gateway": gateway_ok,
            "chat": plugin_ok
            and plugin_integrity_error is None
            and gateway_ok
            and runtime_access.ok
            and marker_error is None,
            "coachIntro": bundle.checks.get("coachIntro", False),
            "exerciseVideoLinks": bundle.checks.get("exerciseVideoLinks", False),
            "supersets": bundle.checks.get("supersets", False),
            "circuits": bundle.checks.get("circuits", False),
        }
        errors = tuple(
            item
            for item in (
                *bundle.errors,
                spec_error,
                plugin_integrity_error,
                marker_error,
                None if runtime_access.ok else runtime_access.message,
            )
            if item
        )
        ok = all(checks.values()) and not errors
        return BootstrapResult(
            AdapterStatus.VERIFIED if ok else AdapterStatus.FAILED,
            "OpenClaw runtime verification completed."
            if ok
            else "OpenClaw runtime verification failed.",
            probe,
            bundle_digest=bundle.digest,
            checks=checks,
            details=errors,
        )

    def rollback(self, target: RuntimeTarget, rollback_id: str) -> BootstrapResult:
        metadata = _snapshot_metadata(target, rollback_id)
        before = self.probe(target)
        if metadata is None:
            return BootstrapResult(
                AdapterStatus.FAILED,
                "OpenClaw rollback snapshot is missing.",
                before,
                rollback_id=rollback_id,
            )
        details: list[str] = []
        if metadata.get("pluginExisted") is not True and self._plugin_installed(target):
            removed = self._run(
                target, "plugins", "uninstall", _OPENCLAW_PLUGIN_ID, "--force"
            )
            if removed.returncode != 0:
                details.append(
                    "OpenClaw could not remove the plugin installed by this bootstrap."
                )
        error = _restore_files(target, rollback_id, "openclaw.json")
        if error is not None:
            details.append(error)
        if not details:
            validated = self._run(target, "config", "validate", "--json")
            restarted = self._run(target, "gateway", "restart", "--json")
            if validated.returncode != 0:
                details.append("Restored OpenClaw config did not validate.")
            if restarted.returncode != 0:
                details.append("OpenClaw Gateway did not restart after rollback.")
        after = self.probe(target)
        return BootstrapResult(
            AdapterStatus.ROLLED_BACK if not details else AdapterStatus.FAILED,
            "OpenClaw state was restored."
            if not details
            else "OpenClaw rollback failed.",
            after,
            rollback_id=rollback_id,
            checks={"restored": not details},
            details=tuple(details),
        )

    def uninstall(self, spec: BootstrapSpec, rollback_id: str) -> BootstrapResult:
        probe = self.probe(spec.target)
        if _snapshot_metadata(spec.target, rollback_id) is None:
            return BootstrapResult(
                AdapterStatus.FAILED,
                "OpenClaw uninstall requires a matching rollback snapshot.",
                probe,
                rollback_id=rollback_id,
            )
        try:
            marker = _identity_marker(spec.target)
            skills = self._run(
                spec.target, "config", "get", "skills.load.extraDirs", "--json"
            )
            t4l_skills = str((spec.instruction_bundle_dir / "skills").resolve())
            old_t4l_skills = _marker_skill_dir(marker, spec.target)
            kept = [
                item
                for item in _json_string_list(skills.stdout)
                if item not in {t4l_skills, old_t4l_skills}
            ]
            plugin_config = self._plugin_config(spec.target)
            plugin_config["agentId"] = spec.target.agent_id
            plugin_config.pop("connectorBaseUrl", None)
            plugin_config.pop("runtimeTokenEnv", None)
            commands = (
                (
                    "config",
                    "set",
                    "skills.load.extraDirs",
                    json.dumps(kept),
                    "--strict-json",
                ),
                (
                    "config",
                    "set",
                    "plugins.entries.t4l-connect.config",
                    json.dumps(plugin_config, separators=(",", ":")),
                    "--strict-json",
                ),
                ("config", "validate", "--json"),
                ("gateway", "restart", "--json"),
            )
            removed = self._run(spec.target, "mcp", "unset", "t4l")
            absence_markers = (
                "not found",
                "does not exist",
                "no mcp server",
                "unknown server",
            )
            removed_detail = f"{removed.stdout}\n{removed.stderr}".casefold()
            if removed.returncode != 0 and not any(
                marker in removed_detail for marker in absence_markers
            ):
                raise RuntimeError("OpenClaw could not unset the T4L MCP entry.")
            remaining = self._run(spec.target, "mcp", "show", "t4l", "--json")
            absent_detail = f"{remaining.stdout}\n{remaining.stderr}".casefold()
            confirmed_absent = remaining.returncode != 0 and any(
                marker in absent_detail for marker in absence_markers
            )
            if remaining.returncode == 0 or not confirmed_absent:
                raise RuntimeError(
                    "OpenClaw T4L MCP entry still exists or cannot be verified."
                )
            for command in commands:
                result = self._run(spec.target, *command)
                if result.returncode != 0:
                    raise RuntimeError(
                        "OpenClaw uninstall command failed: " + " ".join(command[:3])
                    )
            marker_path = spec.target.runtime_state_dir / _MANIFEST_NAME
            if marker_path.exists():
                if marker_path.is_symlink() or not marker_path.is_file():
                    raise RuntimeError("T4L runtime marker is unsafe.")
                marker_path.unlink()
            return BootstrapResult(
                AdapterStatus.CONFIGURED,
                "OpenClaw T4L MCP and instruction integration was removed.",
                self.probe(spec.target),
                rollback_id=rollback_id,
                restart_required=True,
                checks={"mcpRemoved": True, "instructionsRemoved": True},
            )
        except (OSError, RuntimeError, ValueError) as error:
            rollback = self.rollback(spec.target, rollback_id)
            return BootstrapResult(
                AdapterStatus.FAILED,
                "OpenClaw uninstall failed; previous state was restored."
                if rollback.ok
                else "OpenClaw uninstall and rollback failed.",
                rollback.probe,
                rollback_id=rollback_id,
                checks={"restored": rollback.ok},
                details=(_safe_error(error), *rollback.details),
            )

    def consume_owner_connect(
        self,
        target: RuntimeTarget,
        *,
        code: str,
        owner: VerifiedOwnerIdentity | None,
        request_id: str | None = None,
    ) -> ConnectResult:
        del code, owner, request_id
        probe = self.probe(target)
        if probe.native_owner_connect:
            return ConnectResult(
                AdapterStatus.UNSUPPORTED,
                True,
                "The native OpenClaw /t4l plugin owns this command before the model.",
            )
        return ConnectResult(
            AdapterStatus.UNSUPPORTED,
            True,
            "OpenClaw /t4l command plugin is not installed or verified.",
        )

    def _configure(self, spec: BootstrapSpec) -> None:
        skill_result = self._run(
            spec.target, "config", "get", "skills.load.extraDirs", "--json"
        )
        existing = (
            _json_string_list(skill_result.stdout)
            if skill_result.returncode == 0
            else []
        )
        skill_dir = str((spec.instruction_bundle_dir / "skills").resolve())
        old_skill_dir = _marker_skill_dir(_identity_marker(spec.target), spec.target)
        dirs = [item for item in existing if item not in {skill_dir, old_skill_dir}]
        dirs.append(skill_dir)
        plugin_config = self._plugin_config(spec.target)
        plugin_config.update(
            {
                "agentId": spec.target.agent_id,
                "connectorBaseUrl": spec.resolved_connector_base_url,
            }
        )
        plugin_config.pop("runtimeTokenEnv", None)
        commands = (
            (
                "config",
                "set",
                "skills.load.extraDirs",
                json.dumps(dirs),
                "--strict-json",
            ),
            (
                "mcp",
                "set",
                "t4l",
                json.dumps(
                    {
                        "url": spec.t4l_server_url,
                        "transport": "streamable-http",
                        "headers": {
                            "Authorization": f"Bearer ${{{spec.t4l_token_env}}}"
                        },
                    },
                    separators=(",", ":"),
                ),
            ),
            (
                "config",
                "set",
                "plugins.entries.t4l-connect.config",
                json.dumps(plugin_config, separators=(",", ":")),
                "--strict-json",
            ),
            ("plugins", "enable", _OPENCLAW_PLUGIN_ID),
            ("config", "validate", "--json"),
        )
        for command in commands:
            result = self._run(spec.target, *command)
            if result.returncode != 0:
                raise RuntimeError(
                    f"OpenClaw configuration command failed: {' '.join(command[:3])}"
                )
        if not self._plugin_ready(spec.target):
            raise RuntimeError("OpenClaw runtime inspection did not register /t4l.")
        if not self._mcp_ready(spec.target):
            raise RuntimeError("OpenClaw could not probe the local T4L MCP server.")

    def _configure_pairing_command(self, spec: BootstrapSpec) -> None:
        plugin_config = self._plugin_config(spec.target)
        plugin_config.update(
            {
                "agentId": spec.target.agent_id,
                "connectorBaseUrl": spec.resolved_connector_base_url,
            }
        )
        plugin_config.pop("runtimeTokenEnv", None)
        commands = (
            (
                "config",
                "set",
                "plugins.entries.t4l-connect.config",
                json.dumps(plugin_config, separators=(",", ":")),
                "--strict-json",
            ),
            ("plugins", "enable", _OPENCLAW_PLUGIN_ID),
            ("config", "validate", "--json"),
        )
        for command in commands:
            result = self._run(spec.target, *command)
            if result.returncode != 0:
                raise RuntimeError(
                    "OpenClaw pairing configuration command failed: "
                    + " ".join(command[:3])
                )

    def _config_matches(self, spec: BootstrapSpec) -> bool:
        skills = self._run(
            spec.target, "config", "get", "skills.load.extraDirs", "--json"
        )
        skill_dir = str((spec.instruction_bundle_dir / "skills").resolve())
        if skills.returncode != 0 or skill_dir not in _json_string_list(skills.stdout):
            return False
        try:
            plugin_config = self._plugin_config(spec.target)
        except RuntimeError:
            return False
        if (
            plugin_config.get("agentId") != spec.target.agent_id
            or plugin_config.get("connectorBaseUrl") != spec.resolved_connector_base_url
            or "runtimeTokenEnv" in plugin_config
        ):
            return False
        # OpenClaw resolves ${ENV_NAME} in both `mcp show` and `config get`.
        # Inspect with a one-use sentinel instead of exposing the real MCP secret
        # in captured command output. An exact sentinel match proves the stored
        # configuration references the expected environment variable.
        sentinel = "t4l_verify_" + secrets.token_urlsafe(32)
        mcp = self._run(
            spec.target,
            "config",
            "get",
            "mcp.servers.t4l",
            "--json",
            env_overrides={spec.t4l_token_env: sentinel},
        )
        if mcp.returncode != 0:
            return False
        try:
            configured: object = json.loads(mcp.stdout)
        except json.JSONDecodeError:
            return False
        return configured == {
            "url": spec.t4l_server_url,
            "transport": "streamable-http",
            "headers": {"Authorization": f"Bearer {sentinel}"},
        }

    def _plugin_config(self, target: RuntimeTarget) -> dict[str, Any]:
        result = self._run(
            target,
            "config",
            "get",
            "plugins.entries.t4l-connect.config",
            "--json",
        )
        if result.returncode != 0 or not result.stdout.strip():
            return {}
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise RuntimeError(
                "OpenClaw t4l-connect plugin config is invalid JSON."
            ) from error
        if not isinstance(value, dict):
            raise RuntimeError("OpenClaw t4l-connect plugin config must be an object.")
        return {str(key): item for key, item in value.items()}

    def _plugin_installed(self, target: RuntimeTarget) -> bool:
        return (
            self._run(
                target, "plugins", "inspect", _OPENCLAW_PLUGIN_ID, "--json"
            ).returncode
            == 0
        )

    def _plugin_integrity_error(self, spec: BootstrapSpec) -> str | None:
        target = spec.target
        result = self._run(target, "plugins", "inspect", _OPENCLAW_PLUGIN_ID, "--json")
        if result.returncode != 0:
            return "OpenClaw could not inspect the installed t4l-connect plugin."
        try:
            decoded = json.loads(result.stdout)
        except json.JSONDecodeError:
            return "OpenClaw plugin inspection did not return valid JSON."
        if not isinstance(decoded, dict):
            return "OpenClaw plugin inspection did not return an object."
        plugin = decoded.get("plugin")
        install = decoded.get("install")
        if not isinstance(plugin, dict) or not isinstance(install, dict):
            return (
                "OpenClaw inspect did not expose plugin and install metadata; "
                "installed plugin content cannot be verified."
            )
        if (
            plugin.get("id") != _OPENCLAW_PLUGIN_ID
            or plugin.get("packageName") != _OPENCLAW_PLUGIN_PACKAGE
            or plugin.get("version") != _OPENCLAW_PLUGIN_VERSION
        ):
            return "OpenClaw plugin identity or version is not the pinned package."
        raw_install_path = install.get("installPath")
        if not isinstance(raw_install_path, str) or not raw_install_path.strip():
            return (
                "OpenClaw inspect did not expose install.installPath; installed "
                "plugin content cannot be verified."
            )
        install_path = Path(raw_install_path)
        if not install_path.is_absolute() or install_path.is_symlink():
            return "OpenClaw plugin install path is unsafe."
        try:
            installed_root = install_path.resolve(strict=True)
            state_root = target.runtime_state_dir.resolve(strict=True)
        except OSError:
            return "OpenClaw plugin install path does not exist."
        if not installed_root.is_dir() or not installed_root.is_relative_to(state_root):
            return "OpenClaw plugin install path escapes the isolated profile."
        raw_source = plugin.get("source")
        if not isinstance(raw_source, str):
            return "OpenClaw inspect did not expose the loaded plugin source path."
        try:
            loaded_source = Path(raw_source).resolve(strict=True)
        except OSError:
            return "OpenClaw loaded plugin source path does not exist."
        expected_source = (installed_root / "dist" / "index.js").resolve(strict=False)
        if loaded_source != expected_source:
            return "OpenClaw loaded a different t4l-connect source artifact."
        expected_digest, expected_error = _openclaw_plugin_digest(
            spec.resolved_openclaw_plugin_dir
        )
        installed_digest, installed_error = _openclaw_plugin_digest(installed_root)
        if expected_error is not None:
            return expected_error
        if installed_error is not None:
            return installed_error
        if expected_digest != _OPENCLAW_PLUGIN_DIGEST:
            return "Packaged t4l-connect plugin content digest is not pinned."
        if installed_digest != _OPENCLAW_PLUGIN_DIGEST:
            return "Installed t4l-connect plugin content digest does not match."
        return None

    def _plugin_ready(self, target: RuntimeTarget) -> bool:
        result = self._run(
            target, "plugins", "inspect", _OPENCLAW_PLUGIN_ID, "--runtime", "--json"
        )
        if result.returncode != 0:
            return False
        try:
            decoded = json.loads(result.stdout)
        except json.JSONDecodeError:
            return False
        return isinstance(decoded, dict) and "t4l" in _runtime_command_names(decoded)

    def _mcp_ready(self, target: RuntimeTarget) -> bool:
        result = self._run(target, "mcp", "doctor", "t4l", "--probe", "--json")
        if result.returncode != 0:
            return False
        try:
            decoded = json.loads(result.stdout)
        except json.JSONDecodeError:
            return False
        return isinstance(decoded, dict) and decoded.get("ok") is True

    def _gateway_ready(self, target: RuntimeTarget) -> bool:
        return (
            self._run(
                target, "gateway", "status", "--deep", "--require-rpc", "--json"
            ).returncode
            == 0
        )

    def _runtime_agent_access(self, target: RuntimeTarget) -> RuntimeAccessResult:
        coach = OpenClawRuntimeCoach(
            executable=target.executable,
            profile=target.profile,
            agent_id=target.agent_id,
            home_dir=target.home_dir,
            state_dir=target.runtime_state_dir,
            config_path=target.runtime_config_path,
            runner=self.runner,
            timeout_seconds=min(self.command_timeout_seconds, 20.0),
        )
        try:
            result = coach.readiness()
        except RuntimeCoachError as error:
            return RuntimeAccessResult(False, str(error))
        if result.text.strip() != "T4L_READY":
            return RuntimeAccessResult(
                False,
                "OpenClaw configured agent did not complete the readiness turn.",
                result.provider,
                result.model,
                result.reasoning,
            )
        return RuntimeAccessResult(
            True,
            "OpenClaw executed the configured agent without channel delivery.",
            result.provider,
            result.model,
            result.reasoning,
        )

    def _run(
        self,
        target: RuntimeTarget,
        *args: str,
        env_overrides: Mapping[str, str] | None = None,
    ) -> CommandResult:
        command_env = self._env(target)
        if env_overrides is not None:
            command_env.update(env_overrides)
        return self.runner.run(
            [target.executable, "--profile", target.profile, *args],
            env=command_env,
            timeout_seconds=self.command_timeout_seconds,
        )

    def _env(self, target: RuntimeTarget) -> dict[str, str]:
        return {
            "HOME": str(target.home_dir),
            "OPENCLAW_HOME": str(target.home_dir),
            "OPENCLAW_PROFILE": target.profile,
            "OPENCLAW_STATE_DIR": str(target.runtime_state_dir),
            "OPENCLAW_CONFIG_PATH": str(target.runtime_config_path),
        }


def adapter_for(
    runtime: RuntimeKind, *, runner: CommandRunner | None = None
) -> RuntimeAdapter:
    if runtime is RuntimeKind.HERMES:
        return HermesRuntimeAdapter(runner=runner or SubprocessCommandRunner())
    return OpenClawRuntimeAdapter(runner=runner or SubprocessCommandRunner())


def verify_instruction_bundle(bundle_dir: Path) -> BundleVerification:
    try:
        root = bundle_dir.expanduser().resolve(strict=True)
    except OSError:
        return BundleVerification(False, errors=("Instruction bundle is missing.",))
    if not root.is_dir():
        return BundleVerification(
            False, errors=("Instruction bundle is not a directory.",)
        )
    digest = hashlib.sha256()
    errors: list[str] = []
    contents: dict[str, str] = {}
    for relative_path, required_text in _BUNDLE_REQUIREMENTS.items():
        path = root / relative_path
        try:
            resolved = path.resolve(strict=True)
        except OSError:
            errors.append(f"Missing instruction file: {relative_path}")
            continue
        if (
            not resolved.is_relative_to(root)
            or not resolved.is_file()
            or path.is_symlink()
        ):
            errors.append(f"Unsafe instruction file: {relative_path}")
            continue
        content = resolved.read_text(encoding="utf-8")
        contents[relative_path] = content
        for token in required_text:
            if token not in content:
                errors.append(f"{relative_path} is missing policy marker: {token}")
        encoded_path = relative_path.encode()
        encoded_content = content.encode()
        digest.update(len(encoded_path).to_bytes(4, "big"))
        digest.update(encoded_path)
        digest.update(len(encoded_content).to_bytes(8, "big"))
        digest.update(encoded_content)
    checks = {
        name: all(
            token in contents.get(relative_path, "") for relative_path, token in rules
        )
        for name, rules in _BUNDLE_FEATURE_REQUIREMENTS.items()
    }
    return BundleVerification(
        not errors and all(checks.values()),
        digest.hexdigest() if not errors and all(checks.values()) else None,
        tuple(errors),
        checks,
    )


def _prepare_apply(
    spec: BootstrapSpec,
    probe: RuntimeProbe,
    rollback_id: str,
    *,
    require_openclaw_plugin: bool = False,
) -> BootstrapResult | None:
    bundle = verify_instruction_bundle(spec.instruction_bundle_dir)
    spec_error = _bootstrap_spec_error(spec)
    metadata = _snapshot_metadata(spec.target, rollback_id)
    details = list(bundle.errors)
    if spec_error is not None:
        details.append(spec_error)
    if require_openclaw_plugin and not spec.resolved_openclaw_plugin_dir.is_absolute():
        details.append("OpenClaw plugin directory must be absolute.")
    if not probe.ok:
        details.append(probe.message)
    if metadata is None:
        details.append("Rollback snapshot is missing or does not match this agent.")
    if details:
        return BootstrapResult(
            AdapterStatus.INVALID_TARGET
            if spec_error is not None
            else AdapterStatus.FAILED,
            "Runtime apply preflight failed.",
            probe,
            rollback_id=rollback_id,
            bundle_digest=bundle.digest,
            details=tuple(details),
        )
    return None


def _target_error(target: RuntimeTarget, expected: RuntimeKind) -> str | None:
    if target.runtime is not expected:
        return f"Adapter expects runtime {expected.value}."
    if not _IDENTITY_RE.fullmatch(target.agent_id) or not _IDENTITY_RE.fullmatch(
        target.profile
    ):
        return "Agent ID and profile must be lowercase and filesystem-safe."
    if (
        not target.home_dir.is_absolute()
        or not target.runtime_state_dir.is_absolute()
        or not target.runtime_config_path.is_absolute()
    ):
        return "Runtime home, state, and config paths must be absolute."
    executable = target.executable.strip()
    if not executable or any(ord(character) < 32 for character in executable):
        return "Runtime executable is invalid."
    if os.path.sep in executable and (
        not os.path.isabs(executable) or os.path.normpath(executable) != executable
    ):
        return "Runtime executable must be a bare command or canonical absolute path."
    return None


def _bootstrap_spec_error(spec: BootstrapSpec) -> str | None:
    parsed = urlparse(spec.t4l_server_url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in {
        "127.0.0.1",
        "::1",
        "localhost",
    }:
        return "T4L MCP server URL must be loopback HTTP or HTTPS."
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        return (
            "T4L MCP server URL must not contain credentials, a query, or a fragment."
        )
    if parsed.path.rstrip("/") != "/mcp":
        return "T4L server URL must name the local /mcp endpoint."
    connector = urlparse(spec.resolved_connector_base_url)
    if connector.hostname not in {
        "127.0.0.1",
        "::1",
        "localhost",
    } or connector.path.rstrip("/"):
        return "Connector base URL must be loopback and contain no path."
    if not _ENV_NAME_RE.fullmatch(spec.t4l_token_env) or not _ENV_NAME_RE.fullmatch(
        spec.connector_runtime_token_env
    ):
        return "T4L credential environment variable name is invalid."
    if spec.connector_runtime_token_env != "T4L_CONNECTOR_RUNTIME_TOKEN":
        return "The connector runtime credential uses the fixed host environment name."
    return None


def _apply_hermes_t4l_config(config: dict[str, Any], spec: BootstrapSpec) -> None:
    skills_raw = config.get("skills")
    skills = dict(skills_raw) if isinstance(skills_raw, dict) else {}
    dirs_raw = skills.get("external_dirs")
    dirs = [str(item) for item in dirs_raw] if isinstance(dirs_raw, list) else []
    skill_dir = str((spec.instruction_bundle_dir / "skills").resolve())
    skills["external_dirs"] = [item for item in dirs if item != skill_dir] + [skill_dir]
    config["skills"] = skills
    servers_raw = config.get("mcp_servers")
    servers = dict(servers_raw) if isinstance(servers_raw, dict) else {}
    servers["t4l"] = {
        "url": spec.t4l_server_url,
        "headers": {"Authorization": f"Bearer ${{{spec.t4l_token_env}}}"},
        "enabled": True,
    }
    config["mcp_servers"] = servers


def _write_identity_marker(spec: BootstrapSpec, bundle_digest: str | None) -> None:
    _write_json_atomic(
        spec.target.runtime_state_dir / _MANIFEST_NAME,
        {
            "schema": "t4l.runtime-bootstrap.v1",
            "runtime": spec.target.runtime.value,
            "agentId": spec.target.agent_id,
            "profile": spec.target.profile,
            "instructionBundle": str(spec.instruction_bundle_dir.resolve()),
            "bundleDigest": bundle_digest,
            "t4lServerUrl": spec.t4l_server_url,
            "t4lTokenEnv": spec.t4l_token_env,
            "connectorBaseUrl": spec.resolved_connector_base_url,
            "connectorRuntimeTokenEnv": spec.connector_runtime_token_env,
        },
    )


def _verify_marker(spec: BootstrapSpec, bundle_digest: str | None) -> str | None:
    marker = _identity_marker(spec.target)
    if isinstance(marker, str) or marker is None:
        return marker or "T4L runtime identity marker is missing."
    expected = {
        "runtime": spec.target.runtime.value,
        "agentId": spec.target.agent_id,
        "profile": spec.target.profile,
        "bundleDigest": bundle_digest,
        "t4lServerUrl": spec.t4l_server_url,
        "t4lTokenEnv": spec.t4l_token_env,
        "connectorBaseUrl": spec.resolved_connector_base_url,
        "connectorRuntimeTokenEnv": spec.connector_runtime_token_env,
    }
    return (
        None
        if all(marker.get(key) == value for key, value in expected.items())
        else "T4L runtime marker does not match the requested setup."
    )


def _snapshot_files(
    target: RuntimeTarget,
    rollback_id: str,
    config_path: Path,
    config_name: str,
    *,
    extra: Mapping[str, Any],
) -> None:
    snapshot_dir = target.runtime_state_dir / _ROLLBACK_ROOT / rollback_id
    if snapshot_dir.exists() or not config_path.is_file() or config_path.is_symlink():
        raise ValueError("Cannot create a safe rollback snapshot.")
    snapshot_dir.mkdir(parents=True, mode=0o700)
    shutil.copy2(config_path, snapshot_dir / config_name)
    marker_path = target.runtime_state_dir / _MANIFEST_NAME
    marker_existed = marker_path.is_file()
    if marker_existed:
        shutil.copy2(marker_path, snapshot_dir / _MANIFEST_NAME)
    _write_json_atomic(
        snapshot_dir / "snapshot.json",
        {
            "schema": "t4l.runtime-rollback.v1",
            "runtime": target.runtime.value,
            "agentId": target.agent_id,
            "profile": target.profile,
            "configPath": str(config_path),
            "configName": config_name,
            "markerExisted": marker_existed,
            **dict(extra),
        },
    )


def _snapshot_metadata(
    target: RuntimeTarget, rollback_id: str
) -> dict[str, Any] | None:
    if not re.fullmatch(r"[0-9a-f]{32}", rollback_id):
        return None
    try:
        metadata = _read_json_object(
            target.runtime_state_dir / _ROLLBACK_ROOT / rollback_id / "snapshot.json"
        )
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    return (
        metadata if metadata is not None and _marker_matches(metadata, target) else None
    )


def _restore_files(
    target: RuntimeTarget, rollback_id: str, expected_name: str
) -> str | None:
    metadata = _snapshot_metadata(target, rollback_id)
    if metadata is None or metadata.get("configName") != expected_name:
        return "Rollback snapshot identity or config type does not match."
    config_path = Path(str(metadata.get("configPath") or ""))
    expected_path = (
        target.runtime_config_path
        if target.runtime is RuntimeKind.OPENCLAW and expected_name == "openclaw.json"
        else target.runtime_state_dir / expected_name
    )
    if _resolved(config_path) != _resolved(expected_path):
        return "Rollback snapshot points outside the isolated runtime profile."
    snapshot_dir = target.runtime_state_dir / _ROLLBACK_ROOT / rollback_id
    try:
        _copy_atomic(snapshot_dir / expected_name, config_path)
        marker_path = target.runtime_state_dir / _MANIFEST_NAME
        if metadata.get("markerExisted") is True:
            _copy_atomic(snapshot_dir / _MANIFEST_NAME, marker_path)
        elif marker_path.exists():
            marker_path.unlink()
    except (OSError, ValueError) as error:
        return _safe_error(error)
    return None


def _identity_marker(target: RuntimeTarget) -> dict[str, Any] | None | str:
    try:
        return _read_json_object(target.runtime_state_dir / _MANIFEST_NAME)
    except (OSError, ValueError, json.JSONDecodeError):
        return "The T4L runtime identity marker is unreadable."


def _marker_skill_dir(
    marker: Mapping[str, Any] | str | None, target: RuntimeTarget
) -> str | None:
    if not isinstance(marker, Mapping) or not _marker_matches(marker, target):
        return None
    raw = marker.get("instructionBundle")
    if not isinstance(raw, str) or not raw or any(ord(char) < 32 for char in raw):
        return None
    bundle = Path(raw)
    if not bundle.is_absolute() or bundle != Path(os.path.normpath(bundle)):
        return None
    return str((bundle / "skills").resolve())


def _confirmation_client_from_marker(
    target: RuntimeTarget,
) -> ChannelConfirmationClient | None:
    marker = _identity_marker(target)
    if not isinstance(marker, dict):
        return None
    base = marker.get("connectorBaseUrl")
    env_name = marker.get("connectorRuntimeTokenEnv")
    if not isinstance(base, str) or not isinstance(env_name, str):
        return None
    return HttpChannelConfirmationClient(base, env_name)


def _owner_error(
    target: RuntimeTarget, code: str, owner: VerifiedOwnerIdentity | None
) -> str | None:
    if owner is None or not owner.owner_verified:
        return "Only a gateway-verified owner can connect this agent."
    if owner.runtime != target.runtime.value or owner.agent_id != target.agent_id:
        return "Verified owner identity belongs to a different runtime agent."
    if not _PAIRING_CODE_RE.fullmatch(code):
        return "The pairing code format is invalid."
    return None


def _openclaw_plugin_error(path: Path) -> str | None:
    try:
        root = path.resolve(strict=True)
        package = _read_json_object(root / "package.json")
        manifest = _read_json_object(root / "openclaw.plugin.json")
    except (OSError, ValueError, json.JSONDecodeError):
        return "Pinned OpenClaw t4l-connect plugin package is missing or invalid."
    if package is None or manifest is None or manifest.get("id") != _OPENCLAW_PLUGIN_ID:
        return "OpenClaw plugin manifest does not identify t4l-connect."
    entry = root / "dist" / "index.js"
    if not entry.is_file() or entry.is_symlink():
        return "OpenClaw plugin has no safe built JavaScript entry."
    digest, digest_error = _openclaw_plugin_digest(root)
    if digest_error is not None:
        return digest_error
    if digest != _OPENCLAW_PLUGIN_DIGEST:
        return "Pinned OpenClaw t4l-connect package content digest does not match."
    return None


def _openclaw_runtime_version_matches(version_line: str) -> bool:
    match = re.search(r"(?<!\d)(\d{4})\.(\d+)\.(\d+)(?:-(\d+))?", version_line)
    minimum = re.fullmatch(
        r"(\d{4})\.(\d+)\.(\d+)-(\d+)", _OPENCLAW_RUNTIME_MIN_VERSION
    )
    if match is None or minimum is None:
        return False
    actual_base = tuple(int(value) for value in match.groups()[:3])
    minimum_base = tuple(int(value) for value in minimum.groups()[:3])
    if actual_base[0] >= 2027:
        return False
    if actual_base != minimum_base:
        return actual_base > minimum_base
    actual_revision = match.group(4)
    return actual_revision is None or int(actual_revision) >= int(minimum.group(4))


def _openclaw_plugin_digest(root_path: Path) -> tuple[str | None, str | None]:
    if root_path.is_symlink():
        return None, "OpenClaw plugin package root is a symbolic link."
    try:
        root = root_path.resolve(strict=True)
    except OSError:
        return None, "OpenClaw plugin package root is missing."
    if not root.is_dir():
        return None, "OpenClaw plugin package root is not a directory."
    digest = hashlib.sha256()
    for relative in _OPENCLAW_PLUGIN_DIGEST_FILES:
        path = root / relative
        if path.is_symlink() or not path.is_file():
            return None, f"OpenClaw plugin digest file is missing or unsafe: {relative}"
        encoded_path = relative.encode()
        content = path.read_bytes()
        digest.update(len(encoded_path).to_bytes(4, "big"))
        digest.update(encoded_path)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest(), None


def _runtime_command_names(document: Mapping[str, Any]) -> set[str]:
    names: set[str] = set()

    def collect(value: object) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key in {"commands", "cliCommands"} and isinstance(child, list):
                    for item in child:
                        if isinstance(item, str):
                            names.add(item)
                        elif isinstance(item, dict):
                            name = item.get("name")
                            if isinstance(name, str):
                                names.add(name)
                else:
                    collect(child)
        elif isinstance(value, list):
            for item in value:
                collect(item)

    collect(document)
    return names


def _openclaw_model(text: str) -> tuple[str | None, str | None]:
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None, None
    value: object = parsed.get("primary") if isinstance(parsed, dict) else parsed
    if not isinstance(value, str) or "/" not in value:
        return None, None
    provider, model = value.split("/", 1)
    return provider.strip() or None, model.strip() or None


def _openclaw_agent_ids(text: str) -> set[str]:
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return set()
    values: object = parsed.get("agents") if isinstance(parsed, dict) else parsed
    if not isinstance(values, list):
        return set()
    return {
        str(item["id"])
        for item in values
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }


def _json_string_list(text: str) -> list[str]:
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return []
    return (
        [item for item in parsed if isinstance(item, str)]
        if isinstance(parsed, list)
        else []
    )


def _hermes_model(text: str) -> tuple[str | None, str | None]:
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None, None
    if not isinstance(parsed, dict):
        return None, parsed if isinstance(parsed, str) else None
    provider = parsed.get("provider")
    model = parsed.get("default")
    return (
        provider.strip() if isinstance(provider, str) and provider.strip() else None,
        model.strip() if isinstance(model, str) and model.strip() else None,
    )


def _read_yaml_mapping(path: Path) -> dict[str, Any]:
    if path.is_symlink():
        raise ValueError("Refusing to edit a symbolic-link config.")
    parsed = yaml.safe_load(path.read_text(encoding="utf-8"))
    if parsed is None:
        return {}
    if not isinstance(parsed, dict):
        raise ValueError("Hermes config root must be a mapping.")
    return cast(dict[str, Any], parsed)


def _write_yaml_atomic(path: Path, value: Mapping[str, Any]) -> None:
    _write_text_atomic(
        path, yaml.safe_dump(dict(value), allow_unicode=True, sort_keys=False)
    )


def _read_json_object(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Unsafe JSON state file: {path.name}")
    parsed = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError(f"JSON state file is not an object: {path.name}")
    return cast(dict[str, Any], parsed)


def _write_json_atomic(path: Path, value: Mapping[str, Any]) -> None:
    _write_text_atomic(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def _write_text_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o600
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(mode)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _copy_atomic(source: Path, target: Path) -> None:
    if not source.is_file() or source.is_symlink():
        raise ValueError("Rollback source is missing or unsafe.")
    _write_text_atomic(target, source.read_text(encoding="utf-8"))


def _marker_matches(marker: Mapping[str, Any], target: RuntimeTarget) -> bool:
    return (
        marker.get("runtime") == target.runtime.value
        and marker.get("agentId") == target.agent_id
        and marker.get("profile") == target.profile
    )


def _probe_failure(
    target: RuntimeTarget,
    status: AdapterStatus,
    message: str,
    *,
    supported: bool = True,
    version: str | None = None,
    config_path: str | None = None,
) -> RuntimeProbe:
    return RuntimeProbe(
        target.runtime,
        status,
        supported,
        target.agent_id,
        target.profile,
        version=version,
        config_path=config_path,
        message=message,
    )


def _resolved(path: Path) -> Path:
    return path.expanduser().resolve(strict=False)


def _first_nonempty_line(text: str) -> str:
    return next((line.strip() for line in text.splitlines() if line.strip()), "")


def _new_rollback_id() -> str:
    return uuid.uuid4().hex


def _safe_error(error: Exception) -> str:
    return str(error).replace("\n", " ")[:500] or error.__class__.__name__
