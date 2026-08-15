from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, TextIO, cast

from .runtime_adapter import (
    AdapterStatus,
    BootstrapResult,
    BootstrapSpec,
    RuntimeKind,
    RuntimeProbe,
    RuntimeTarget,
    adapter_for,
)

_FORBIDDEN_SECRET_KEYS = frozenset(
    {
        "adminkey",
        "apikey",
        "connectorruntimetoken",
        "modelapikey",
        "providerapikey",
        "providerkey",
        "t4lapikey",
        "token",
    }
)
_SUCCESS = frozenset(
    {
        AdapterStatus.READY,
        AdapterStatus.SNAPSHOTTED,
        AdapterStatus.CONFIGURED,
        AdapterStatus.VERIFIED,
        AdapterStatus.ROLLED_BACK,
    }
)


def run_runtime_adapter_cli(
    *,
    input_stream: TextIO = sys.stdin,
    output_stream: TextIO = sys.stdout,
) -> int:
    try:
        envelope = _read_request(input_stream)
        result = execute_runtime_envelope(envelope)
    except (ValueError, json.JSONDecodeError) as error:
        result = _error_result(str(error))
    json.dump(result, output_stream, ensure_ascii=False, sort_keys=True)
    output_stream.write("\n")
    return 0 if result.get("ok") is True else 1


def run_runtime_cli(
    action: str,
    *,
    input_stream: TextIO = sys.stdin,
    output_stream: TextIO = sys.stdout,
) -> int:
    """Compatibility wrapper for the original ``runtime <action>`` command."""

    try:
        request = _read_request(input_stream)
        if "agent" not in request:
            request = {"action": action, "agent": request, "spec": request}
        else:
            request["action"] = action
        result = execute_runtime_envelope(request)
    except (ValueError, json.JSONDecodeError) as error:
        result = _error_result(str(error))
    json.dump(result, output_stream, ensure_ascii=False, sort_keys=True)
    output_stream.write("\n")
    return 0 if result.get("ok") is True else 1


def execute_runtime_envelope(document: Mapping[str, Any]) -> dict[str, Any]:
    secret_path = _find_secret_field(document)
    if secret_path is not None:
        raise ValueError(
            "Runtime requests accept credential environment-variable names only; "
            f"secret field is forbidden: {secret_path}"
        )
    action = _required_string(document, "action").lower()
    agent = _required_mapping(document, "agent")
    target = _target_from_json(agent)
    adapter = adapter_for(target.runtime)
    if action == "probe":
        return _normalize_probe(adapter.probe(target))
    if action == "snapshot":
        return _normalize_result(adapter.snapshot(target))
    if action in {"apply", "bootstrap", "install", "update", "verify", "uninstall"}:
        spec_doc = _required_mapping(document, "spec")
        spec = _spec_from_json(target, spec_doc)
        installed_release: dict[str, str] | None = None
        release_doc = document.get("release")
        if release_doc is not None:
            if not isinstance(release_doc, dict):
                raise ValueError("Runtime release must be an object.")
            installed_release = _verify_installed_release(spec, release_doc)
        elif action in {"install", "update"}:
            # A host without a pinned release may still run the legacy bundled
            # setup. A claimed signed release is never inferred from the phone.
            installed_release = None
        if action == "verify":
            result = _normalize_result(adapter.verify(spec))
            if installed_release is not None:
                result["installedRelease"] = installed_release
            return result
        if action == "bootstrap":
            return _normalize_result(adapter.bootstrap(spec))
        rollback_id = _required_string(document, "rollbackId")
        if action == "uninstall":
            return _normalize_result(adapter.uninstall(spec, rollback_id))
        result = _normalize_result(adapter.apply(spec, rollback_id))
        if installed_release is not None:
            result["installedRelease"] = installed_release
        return result
    if action == "prepare-pairing":
        if target.runtime is not RuntimeKind.OPENCLAW:
            raise ValueError(
                "Secure pre-pairing command installation is supported only "
                "for OpenClaw."
            )
        spec = _spec_from_json(target, _required_mapping(document, "spec"))
        if not hasattr(adapter, "prepare_pairing_command"):
            raise ValueError("Runtime adapter has no pre-pairing command hook.")
        prepare = cast(Any, adapter).prepare_pairing_command
        return _normalize_result(cast(BootstrapResult, prepare(spec)))
    if action == "rollback":
        return _normalize_result(
            adapter.rollback(target, _required_string(document, "rollbackId"))
        )
    raise ValueError(f"Unsupported runtime-adapter action: {action}")


def _normalize_probe(probe: RuntimeProbe) -> dict[str, Any]:
    payload = probe.to_dict()
    payload.update(
        {
            "ok": probe.status in _SUCCESS,
            "code": probe.status.value,
            "checks": {
                "runtime": probe.supported,
                "identity": probe.identity_verified,
                "runtimeMetadata": (
                    probe.provider is not None or probe.model is not None
                ),
            },
        }
    )
    return payload


def _normalize_result(result: BootstrapResult) -> dict[str, Any]:
    payload = result.to_dict()
    payload.update(
        {
            "ok": result.status in _SUCCESS,
            "code": result.status.value,
        }
    )
    return payload


def _error_result(message: str) -> dict[str, Any]:
    return {
        "ok": False,
        "code": AdapterStatus.INVALID_TARGET.value,
        "status": AdapterStatus.INVALID_TARGET.value,
        "message": message,
        "checks": {},
    }


def _read_request(stream: TextIO) -> dict[str, Any]:
    parsed = json.load(stream)
    if not isinstance(parsed, dict):
        raise ValueError("Runtime request must be a JSON object.")
    return cast(dict[str, Any], parsed)


def _target_from_json(document: Mapping[str, Any]) -> RuntimeTarget:
    runtime_text = _required_string(document, "runtime").lower()
    try:
        runtime = RuntimeKind(runtime_text)
    except ValueError as error:
        raise ValueError(f"Unsupported runtime: {runtime_text}") from error
    state_dir_text = _optional_string(document, "stateDir", "")
    config_path_text = _optional_string(document, "configPath", "")
    return RuntimeTarget(
        runtime=runtime,
        agent_id=_required_string(document, "agentId"),
        profile=_required_string(document, "profile"),
        home_dir=Path(_required_string(document, "homeDir")),
        executable=_optional_string(document, "executable", runtime.value),
        state_dir=Path(state_dir_text) if state_dir_text else None,
        config_path=Path(config_path_text) if config_path_text else None,
    )


def _spec_from_json(
    target: RuntimeTarget,
    document: Mapping[str, Any],
) -> BootstrapSpec:
    plugin_dir = _optional_string(document, "openclawPluginDir", "")
    connector_url = _optional_string(document, "connectorBaseUrl", "")
    return BootstrapSpec(
        target=target,
        t4l_server_url=_required_string(document, "t4lServerUrl"),
        instruction_bundle_dir=Path(_required_string(document, "instructionBundleDir")),
        t4l_token_env=_optional_string(
            document,
            "t4lTokenEnv",
            "MCP_T4L_API_KEY",
        ),
        connector_base_url=connector_url or None,
        connector_runtime_token_env=_optional_string(
            document,
            "connectorRuntimeTokenEnv",
            "T4L_CONNECTOR_RUNTIME_TOKEN",
        ),
        openclaw_plugin_dir=Path(plugin_dir) if plugin_dir else None,
    )


def _required_mapping(
    document: Mapping[str, Any],
    key: str,
) -> Mapping[str, Any]:
    value = document.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"Runtime request requires object: {key}")
    return cast(Mapping[str, Any], value)


def _required_string(document: Mapping[str, Any], key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Runtime request requires non-empty string: {key}")
    return value.strip()


def _optional_string(
    document: Mapping[str, Any],
    key: str,
    default: str,
) -> str:
    value = document.get(key)
    if value is None:
        return default
    if not isinstance(value, str):
        raise ValueError(f"Runtime request field must be a string: {key}")
    return value.strip()


def _find_secret_field(value: object, path: str = "") -> str | None:
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            child_path = f"{path}.{key_text}" if path else key_text
            if key_text.casefold() in _FORBIDDEN_SECRET_KEYS:
                return child_path
            found = _find_secret_field(child, child_path)
            if found is not None:
                return found
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found = _find_secret_field(child, f"{path}[{index}]")
            if found is not None:
                return found
    return None


def _verify_installed_release(
    spec: BootstrapSpec,
    release: Mapping[str, Any],
) -> dict[str, str]:
    expected_keys = {
        "releaseId",
        "version",
        "manifestUrl",
        "manifestSha256",
        "signingKeyId",
        "signatureRequired",
    }
    if set(release) != expected_keys or release.get("signatureRequired") is not True:
        raise ValueError("Runtime release envelope is incomplete or has extra fields.")
    expected = {
        "releaseId": _required_string(release, "releaseId"),
        "version": _required_string(release, "version"),
        "manifestUrl": _required_string(release, "manifestUrl"),
        "manifestSha256": _required_string(release, "manifestSha256"),
        "signingKeyId": _required_string(release, "signingKeyId"),
    }
    state_path = spec.instruction_bundle_dir.parent / "release.json"
    if state_path.is_symlink():
        raise ValueError("Installed release state must not be a symbolic link.")
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("Installed signed release state is unavailable.") from error
    if not isinstance(state, dict) or state.get("schema") != "t4l_installed_release.v1":
        raise ValueError("Installed signed release state is invalid.")
    if any(state.get(key) != value for key, value in expected.items()):
        raise ValueError(
            "Runtime release does not match the host-verified installation."
        )
    return {
        "releaseId": expected["releaseId"],
        "version": expected["version"],
        "manifestSha256": expected["manifestSha256"],
        "signingKeyId": expected["signingKeyId"],
    }
