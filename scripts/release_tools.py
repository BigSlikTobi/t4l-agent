#!/usr/bin/env python3
"""Build the acyclic, signed T4L OpenClaw release inputs."""

from __future__ import annotations

import argparse
import base64
import contextlib
import gzip
import hashlib
import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Any, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

PLUGIN_DIGEST_FILES = (
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
REQUIRED_ARTIFACTS = {
    "t4l-agent-wheel": "python-wheel",
    "t4l-server-wheel": "python-wheel",
    "t4l-python-wheelhouse": "python-wheelhouse-tar",
    "t4l-instructions": "instruction-bundle-tar",
}
RELEASE_TARGETS = (
    "linux-x64-cp311",
    "linux-x64-cp312",
    "linux-x64-cp313",
    "darwin-arm64-cp311",
    "darwin-arm64-cp312",
    "darwin-arm64-cp313",
)
REQUIRED_SMOKE_CHECKS = {
    "offlineInstall",
    "pythonImports",
    "instructions",
    "pluginLifecycle",
}
PLUGIN_SMOKE_CHECKS = {"install", "load", "ownerCommand", "uninstall"}
MAX_ARTIFACT_SIZE = 250 * 1024 * 1024
INSTRUCTION_MARKERS = {
    "docs/setup_instruction.md": ("get_planning_context", "accepted state"),
    "docs/coaching_setup.md": (
        "AgentDescriptor",
        "phone controls accepted state",
        "review-only proposal",
    ),
    "skills/t4l-onboard-athlete/SKILL.md": (
        "write_athlete_setup_draft",
        "athlete_setup_draft.v1",
    ),
    "skills/t4l-write-results/SKILL.md": (
        "youtube.com/shorts",
        "superset",
        "circuit",
    ),
}


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _decode_b64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def plugin_digest(root: Path) -> str:
    if root.is_symlink():
        raise ValueError("plugin root is a symbolic link")
    root = root.resolve(strict=True)
    digest = hashlib.sha256()
    for relative in PLUGIN_DIGEST_FILES:
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"unsafe or missing plugin file: {relative}")
        encoded = relative.encode()
        content = path.read_bytes()
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def stage_plugin(source: Path, destination: Path, policy: dict[str, Any]) -> str:
    if source.is_symlink() or destination.is_symlink():
        raise ValueError("plugin source or destination is a symbolic link")
    if destination.exists():
        raise ValueError("staging destination already exists")
    required = {
        "schema",
        "releaseId",
        "version",
        "manifestUrl",
        "signingKeyId",
        "signingPublicKey",
    }
    if set(policy) != required or policy.get("schema") != "t4l_release_policy.v1":
        raise ValueError("release policy has unexpected fields")
    if not str(policy["manifestUrl"]).startswith("https://"):
        raise ValueError("manifest URL must use HTTPS")
    public_key = _decode_b64url(str(policy["signingPublicKey"]))
    if len(public_key) != 32 or "REPLACE_" in json.dumps(policy):
        raise ValueError("release signing key is invalid or still a placeholder")
    destination.mkdir(parents=True, mode=0o700)
    for name in ("bin", "dist"):
        shutil.copytree(source / name, destination / name)
    for name in ("package.json", "openclaw.plugin.json"):
        shutil.copy2(source / name, destination / name)
    (destination / "release-policy.json").write_text(
        json.dumps(policy, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    digest = plugin_digest(destination)
    (destination / "plugin-digest.txt").write_text(digest + "\n", encoding="ascii")
    return digest


def stamp_runtime_adapter(path: Path, digest: str) -> None:
    if not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise ValueError("plugin digest is invalid")
    source = path.read_text(encoding="utf-8")
    updated, count = re.subn(
        r'(_OPENCLAW_PLUGIN_DIGEST = \(\n\s+")[a-f0-9]{64}("\n\))',
        rf"\g<1>{digest}\g<2>",
        source,
        count=1,
    )
    if count != 1:
        raise ValueError("could not locate the pinned runtime plugin digest")
    path.write_text(updated, encoding="utf-8")


def pack_plugin(staged: Path, output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        ["npm", "pack", str(staged), "--pack-destination", str(output), "--json"],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    filename = str(json.loads(result.stdout)[0]["filename"])
    archive = output / filename
    with tarfile.open(archive, "r:gz") as package:
        expected = {f"package/{relative}" for relative in PLUGIN_DIGEST_FILES}
        actual = {member.name for member in package.getmembers() if member.isfile()}
        if actual != expected:
            raise ValueError("packed npm plugin file allowlist does not match")
        policy = package.extractfile("package/release-policy.json")
        if policy is None or b"REPLACE_" in policy.read():
            raise ValueError("packed npm plugin contains a placeholder policy")
        digest = hashlib.sha256()
        for relative in PLUGIN_DIGEST_FILES:
            member = package.extractfile(f"package/{relative}")
            if member is None:
                raise ValueError(f"packed npm plugin is missing {relative}")
            content = member.read()
            encoded = relative.encode()
            digest.update(len(encoded).to_bytes(4, "big"))
            digest.update(encoded)
            digest.update(len(content).to_bytes(8, "big"))
            digest.update(content)
        if digest.hexdigest() != plugin_digest(staged):
            raise ValueError("packed npm plugin content digest changed during packing")
    return archive


def validate_wheelhouse_archive(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise ValueError("wheelhouse archive is missing or unsafe")
    with tarfile.open(path, "r:*") as archive:
        members = archive.getmembers()
        if any(
            not member.isfile()
            or member.name != Path(member.name).name
            or member.name.startswith(".")
            for member in members
        ):
            raise ValueError("wheelhouse archive must contain only root-level files")
        names = [member.name for member in members]
        if len(names) != len(set(names)) or "wheelhouse-lock.json" not in names:
            raise ValueError("wheelhouse archive entries are duplicated or unlocked")
        lock_file = archive.extractfile("wheelhouse-lock.json")
        if lock_file is None:
            raise ValueError("wheelhouse lock is missing")
        lock_value = json.loads(lock_file.read())
        if not isinstance(lock_value, dict):
            raise ValueError("wheelhouse lock must be an object")
        lock = cast(dict[str, Any], lock_value)
        files = lock.get("files")
        if (
            lock.get("schema") != "t4l_wheelhouse_lock.v1"
            or tuple(lock.get("targets", ())) != RELEASE_TARGETS
            or not isinstance(files, list)
        ):
            raise ValueError("wheelhouse lock identity or target matrix is invalid")
        expected_names = {"wheelhouse-lock.json"}
        wheel_names: set[str] = set()
        for item in files:
            if not isinstance(item, dict):
                raise ValueError("wheelhouse lock file entry is invalid")
            name = str(item.get("filename", ""))
            if (
                Path(name).name != name
                or not name.endswith(".whl")
                or name in wheel_names
            ):
                raise ValueError("wheelhouse lock wheel filename is invalid")
            member = archive.extractfile(name)
            if member is None:
                raise ValueError(f"wheelhouse archive is missing {name}")
            content = member.read()
            if hashlib.sha256(content).hexdigest() != item.get("sha256") or len(
                content
            ) != item.get("size"):
                raise ValueError(f"wheelhouse wheel digest mismatch: {name}")
            expected_names.add(name)
            wheel_names.add(name)
        if set(names) != expected_names:
            raise ValueError("wheelhouse archive and lock file set differ")
        _validate_wheel_matrix(wheel_names)
        return lock


def _validate_wheel_matrix(names: set[str]) -> None:
    normalized = {name.casefold().replace("-", "_") for name in names}
    if len(normalized) != 15:
        raise ValueError(
            "wheelhouse must contain the exact 15 pinned dependency wheels"
        )
    expected_counts = {
        "pyyaml_6.0.3_": 6,
        "cffi_2.1.1_": 6,
        "cryptography_46.0.7_": 2,
        "pycparser_3.0_": 1,
    }
    for prefix, count in expected_counts.items():
        if sum(name.startswith(prefix) for name in normalized) != count:
            raise ValueError(f"wheelhouse pin count is wrong for {prefix.rstrip('_')}")
    if not any(
        name.startswith("pycparser_3.0_py3_none_any.whl") for name in normalized
    ):
        raise ValueError("wheelhouse is missing pinned pycparser 3.0")
    targets = {
        "linux-x64": ("manylinux_2_17_x86_64", "manylinux2014_x86_64"),
        "darwin-arm64": ("macosx_11_0_arm64",),
    }
    for _target, tags in targets.items():
        for version in ("311", "312", "313"):
            for distribution, package_version in (
                ("pyyaml", "6.0.3"),
                ("cffi", "2.1.1"),
            ):
                if not any(
                    name.startswith(
                        f"{distribution}_{package_version}_cp{version}_cp{version}_"
                    )
                    and any(tag in name for tag in tags)
                    for name in normalized
                ):
                    target_tag = tags[0]
                    raise ValueError(
                        "wheelhouse lacks "
                        f"{distribution} {package_version} cp{version} for {target_tag}"
                    )
        crypto_tags = (
            ("macosx_10_9_universal2",) if tags == ("macosx_11_0_arm64",) else tags
        )
        if not any(
            name.startswith("cryptography_46.0.7_cp311_abi3_")
            and any(tag in name for tag in crypto_tags)
            for name in normalized
        ):
            raise ValueError(f"wheelhouse lacks cryptography 46.0.7 for {tags[0]}")


def validate_project_wheel(
    path: Path,
    *,
    distribution: str,
    version: str,
    required_dependencies: tuple[str, ...],
    expected_plugin_digest: str | None = None,
) -> None:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"{distribution} wheel is missing or unsafe")
    normalized = distribution.replace("-", "_")
    if path.name != f"{normalized}-{version}-py3-none-any.whl":
        raise ValueError(f"{distribution} wheel filename or tag is not pinned")
    with zipfile.ZipFile(path) as wheel:
        metadata_names = [
            name for name in wheel.namelist() if name.endswith(".dist-info/METADATA")
        ]
        wheel_names = [
            name for name in wheel.namelist() if name.endswith(".dist-info/WHEEL")
        ]
        if len(metadata_names) != 1 or len(wheel_names) != 1:
            raise ValueError(f"{distribution} wheel metadata is ambiguous")
        metadata = wheel.read(metadata_names[0]).decode("utf-8")
        wheel_metadata = wheel.read(wheel_names[0]).decode("utf-8")
        if expected_plugin_digest is not None:
            adapter_names = [
                name
                for name in wheel.namelist()
                if name == "t4l_agent/runtime_adapter.py"
            ]
            if len(adapter_names) != 1:
                raise ValueError("t4l-agent wheel has no pinned runtime adapter")
            adapter = wheel.read(adapter_names[0]).decode("utf-8")
            if expected_plugin_digest not in adapter:
                raise ValueError("t4l-agent wheel plugin digest does not match staging")
    lowered = metadata.casefold()
    if (
        f"name: {distribution}".casefold() not in lowered
        or f"version: {version}".casefold() not in lowered
        or "requires-python: >=3.11" not in lowered
        or "tag: py3-none-any" not in wheel_metadata.casefold()
        or any(
            f"requires-dist: {dependency}" not in lowered
            for dependency in required_dependencies
        )
    ):
        raise ValueError(
            f"{distribution} wheel metadata does not match the release contract"
        )


def sign_manifest(
    build: dict[str, Any],
    policy: dict[str, Any],
    private_key: Ed25519PrivateKey,
) -> dict[str, Any]:
    if build.get("schema") != "t4l_release_build_input.v1":
        raise ValueError("release build input schema is invalid")
    if build.get("releaseId") != policy.get("releaseId") or build.get(
        "version"
    ) != policy.get("version"):
        raise ValueError("release identity does not match staged policy")
    public_raw = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    if _b64url(public_raw) != policy.get("signingPublicKey"):
        raise ValueError("private key does not match staged public key")
    artifacts = []
    seen: set[str] = set()
    for item in build.get("artifacts", []):
        name = str(item.get("name", ""))
        kind = str(item.get("kind", ""))
        path = Path(str(item.get("path", ""))).resolve(strict=True)
        url = str(item.get("url", ""))
        if name in seen or REQUIRED_ARTIFACTS.get(name) != kind:
            raise ValueError(f"invalid release artifact: {name}")
        if not url.startswith("https://") or not path.is_file() or path.is_symlink():
            raise ValueError(f"unsafe release artifact: {name}")
        content = path.read_bytes()
        artifacts.append(
            {
                "name": name,
                "kind": kind,
                "filename": path.name,
                "url": url,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
        )
        seen.add(name)
    if seen != set(REQUIRED_ARTIFACTS):
        raise ValueError("release build is missing required artifacts")
    unsigned = {
        "schema": "t4l_release_manifest.v1",
        "releaseId": build["releaseId"],
        "version": build["version"],
        "minOpenClawVersion": build.get("minOpenClawVersion", "2026.7.1-2"),
        "sourceRepositories": build.get("sourceRepositories", []),
        "artifacts": artifacts,
    }
    signature = private_key.sign(canonical_json(unsigned))
    private_key.public_key().verify(signature, canonical_json(unsigned))
    return {
        **unsigned,
        "signature": {
            "algorithm": "Ed25519",
            "keyId": policy["signingKeyId"],
            "value": _b64url(signature),
        },
    }


def artifact_digest(build: dict[str, Any], name: str) -> str:
    return hashlib.sha256(artifact_path(build, name).read_bytes()).hexdigest()


def artifact_path(build: dict[str, Any], name: str) -> Path:
    matches = [item for item in build.get("artifacts", []) if item.get("name") == name]
    if len(matches) != 1:
        raise ValueError(f"release build must contain one {name} artifact")
    raw_path = Path(str(matches[0].get("path", "")))
    if raw_path.is_symlink():
        raise ValueError(f"release artifact is unsafe: {name}")
    path = raw_path.resolve(strict=True)
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"release artifact is unsafe: {name}")
    return path


def verify_release_receipts(
    directory: Path,
    *,
    release_id: str,
    wheelhouse_sha256: str,
    instructions_sha256: str,
    agent_wheel_sha256: str,
    server_wheel_sha256: str,
    expected_plugin_digest: str,
) -> None:
    if not directory.is_dir() or directory.is_symlink():
        raise ValueError("release verification receipt directory is missing")
    for target in RELEASE_TARGETS:
        path = directory / f"{target}.json"
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"release verification receipt is missing: {target}")
        receipt = json.loads(path.read_text(encoding="utf-8"))
        if (
            receipt.get("schema") != "t4l_release_verification.v1"
            or receipt.get("target") != target
            or receipt.get("releaseId") != release_id
            or receipt.get("wheelhouseSha256") != wheelhouse_sha256
            or receipt.get("instructionsSha256") != instructions_sha256
            or receipt.get("agentWheelSha256") != agent_wheel_sha256
            or receipt.get("serverWheelSha256") != server_wheel_sha256
            or receipt.get("pluginDigest") != expected_plugin_digest
            or receipt.get("networkDisabled") is not True
            or set(receipt.get("checks", [])) != REQUIRED_SMOKE_CHECKS
        ):
            raise ValueError(f"release verification receipt is invalid: {target}")


def pack_deterministic_tree(source: Path, output: Path) -> None:
    if source.is_symlink() or output.is_symlink():
        raise ValueError("archive source or output is a symbolic link")
    root = source.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("archive source is missing or unsafe")
    files = sorted(path for path in root.rglob("*") if path.is_file())
    if not files or any(path.is_symlink() for path in files):
        raise ValueError("archive source has no files or contains symbolic links")
    output.parent.mkdir(parents=True, exist_ok=True)
    with (
        output.open("wb") as raw,
        gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed,
        tarfile.open(
            fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
        ) as archive,
    ):
        for path in files:
            relative = path.relative_to(root).as_posix()
            info = tarfile.TarInfo(relative)
            content = path.read_bytes()
            info.size = len(content)
            info.mode = 0o644
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            archive.addfile(info, fileobj=io.BytesIO(content))


def pack_instruction_bundle(source: Path, output: Path) -> None:
    if source.is_symlink() or output.is_symlink():
        raise ValueError("instruction source or output is a symbolic link")
    root = source.resolve(strict=True)
    files: list[Path] = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("instruction source contains a symbolic link")
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        allowed = relative.as_posix() == "README.md" or (
            relative.parts
            and relative.parts[0] in {"agents", "contracts", "docs", "skills"}
        )
        if (
            not allowed
            or "__pycache__" in relative.parts
            or relative.suffix in {".pyc", ".pyo"}
        ):
            continue
        files.append(path)
    if not (root / "contracts" / "coaching-contract.v1.schema.json").is_file():
        raise ValueError("instruction bundle coaching contract is missing")
    for relative_name, markers in INSTRUCTION_MARKERS.items():
        path = root / relative_name
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"instruction bundle is missing {relative_name}")
        content = path.read_text(encoding="utf-8")
        if any(marker.casefold() not in content.casefold() for marker in markers):
            raise ValueError(
                f"instruction bundle markers are missing from {relative_name}"
            )
    with tempfile.TemporaryDirectory(prefix="t4l-instructions-") as temporary:
        staging = Path(temporary)
        for path in files:
            relative = path.relative_to(root)
            destination = staging / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, destination)
        pack_deterministic_tree(staging, output)


def build_wheelhouse(source: Path, output: Path) -> dict[str, Any]:
    if source.is_symlink() or output.is_symlink():
        raise ValueError("wheelhouse source or output is a symbolic link")
    root = source.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("wheelhouse source is missing or unsafe")
    wheels = sorted(root.glob("*.whl"))
    if any(path.is_symlink() for path in wheels):
        raise ValueError("wheelhouse contains a symbolic link")
    _validate_wheel_matrix({path.name for path in wheels})
    lock = {
        "schema": "t4l_wheelhouse_lock.v1",
        "targets": list(RELEASE_TARGETS),
        "files": [
            {
                "filename": path.name,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "size": path.stat().st_size,
            }
            for path in wheels
        ],
    }
    with tempfile.TemporaryDirectory(prefix="t4l-wheelhouse-") as temporary:
        staging = Path(temporary)
        for path in wheels:
            shutil.copy2(path, staging / path.name)
        (staging / "wheelhouse-lock.json").write_text(
            json.dumps(lock, separators=(",", ":"), sort_keys=True) + "\n",
            encoding="utf-8",
        )
        pack_deterministic_tree(staging, output)
    validate_wheelhouse_archive(output)
    return lock


def native_release_target(
    *,
    system_name: str | None = None,
    machine: str | None = None,
    python_version: tuple[int, int] | None = None,
    libc: tuple[str, str] | None = None,
) -> str:
    system_value = system_name or platform.system()
    machine_value = (machine or platform.machine()).casefold()
    version_value = python_version or (sys.version_info.major, sys.version_info.minor)
    if version_value not in {(3, 11), (3, 12), (3, 13)}:
        raise ValueError("release verification requires CPython 3.11, 3.12, or 3.13")
    python_tag = f"cp{version_value[0]}{version_value[1]}"
    if system_value == "Linux" and machine_value in {"x86_64", "amd64"}:
        libc_name, libc_version = libc or platform.libc_ver()
        if libc_name.casefold() not in {"glibc", "gnu libc"} or _number_tuple(
            libc_version
        ) < (2, 17):
            raise ValueError("Linux release verification requires glibc 2.17 or newer")
        return f"linux-x64-{python_tag}"
    if system_value == "Darwin" and machine_value in {"arm64", "aarch64"}:
        return f"darwin-arm64-{python_tag}"
    raise ValueError("this OS and CPU are outside the declared v1 release matrix")


def _number_tuple(value: str) -> tuple[int, ...]:
    match = re.fullmatch(r"(\d+(?:\.\d+)*)", value.strip())
    if match is None:
        return ()
    return tuple(int(part) for part in match.group(1).split("."))


def validate_instruction_archive(path: Path) -> None:
    if (
        not path.is_file()
        or path.is_symlink()
        or path.stat().st_size > MAX_ARTIFACT_SIZE
    ):
        raise ValueError("instruction archive is missing, unsafe, or too large")
    with tarfile.open(path, "r:*") as archive:
        members = archive.getmembers()
        if not members or sum(member.size for member in members) > MAX_ARTIFACT_SIZE:
            raise ValueError(
                "instruction archive is empty or expands past the size limit"
            )
        names: set[str] = set()
        for member in members:
            pure = Path(member.name)
            if (
                not member.isfile()
                or pure.is_absolute()
                or any(part in {"", ".", ".."} for part in pure.parts)
                or member.name in names
            ):
                raise ValueError("instruction archive has an unsafe member")
            allowed = member.name == "README.md" or pure.parts[0] in {
                "agents",
                "contracts",
                "docs",
                "skills",
            }
            if (
                not allowed
                or "__pycache__" in pure.parts
                or pure.suffix
                in {
                    ".pyc",
                    ".pyo",
                }
            ):
                raise ValueError("instruction archive contains an unexpected file")
            names.add(member.name)
        required_contract = "contracts/coaching-contract.v1.schema.json"
        if required_contract not in names:
            raise ValueError("instruction archive coaching contract is missing")
        for relative, markers in INSTRUCTION_MARKERS.items():
            if relative not in names:
                raise ValueError(f"instruction archive is missing {relative}")
            extracted = archive.extractfile(relative)
            if extracted is None:
                raise ValueError(f"instruction archive cannot read {relative}")
            content = extracted.read().decode("utf-8")
            if any(marker.casefold() not in content.casefold() for marker in markers):
                raise ValueError(
                    f"instruction archive markers are missing from {relative}"
                )


def _extract_wheelhouse(path: Path, destination: Path) -> None:
    validate_wheelhouse_archive(path)
    destination.mkdir(mode=0o700)
    with tarfile.open(path, "r:*") as archive:
        for member in archive.getmembers():
            target = destination / member.name
            source = archive.extractfile(member)
            if source is None:
                raise ValueError(f"wheelhouse cannot read {member.name}")
            descriptor = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            with os.fdopen(descriptor, "wb") as output:
                shutil.copyfileobj(source, output)


def _run_checked(
    command: list[str],
    *,
    environment: dict[str, str],
    timeout: int,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        timeout=timeout,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()[-1000:]
        raise ValueError(f"release verification command failed: {detail}")
    return result


def _verify_plugin_smoke(
    command: tuple[str, ...],
    *,
    staged_plugin: Path,
    expected_plugin_digest: str,
    environment: dict[str, str],
) -> None:
    if not command:
        raise ValueError(
            "an actual OpenClaw plugin lifecycle smoke command is required"
        )
    executable = Path(command[0])
    if (
        not executable.is_absolute()
        or executable.is_symlink()
        or not executable.is_file()
        or any(any(ord(character) < 32 for character in item) for item in command)
    ):
        raise ValueError("plugin lifecycle smoke command is unsafe")
    smoke_environment = {
        **environment,
        "T4L_STAGED_PLUGIN": str(staged_plugin),
        "T4L_PLUGIN_DIGEST": expected_plugin_digest,
        "T4L_NETWORK_DISABLED_REQUIRED": "1",
    }
    result = _run_checked(
        list(command),
        environment=smoke_environment,
        timeout=300,
    )
    try:
        evidence = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ValueError("plugin lifecycle smoke output is not JSON") from error
    required = {
        "schema",
        "ok",
        "pluginDigest",
        "openClawVersion",
        "networkDisabled",
        "modelInvoked",
        "checks",
    }
    if (
        not isinstance(evidence, dict)
        or set(evidence) != required
        or evidence.get("schema") != "t4l_plugin_lifecycle_smoke.v1"
        or evidence.get("ok") is not True
        or evidence.get("pluginDigest") != expected_plugin_digest
        or evidence.get("networkDisabled") is not True
        or evidence.get("modelInvoked") is not False
        or set(evidence.get("checks", [])) != PLUGIN_SMOKE_CHECKS
        or not re.fullmatch(
            r"2026\.\d+\.\d+(?:-\d+)?",
            str(evidence.get("openClawVersion", "")),
        )
    ):
        raise ValueError("plugin lifecycle smoke evidence is invalid")


def produce_target_receipt(
    *,
    target: str,
    release_id: str,
    version: str,
    agent_wheel: Path,
    server_wheel: Path,
    wheelhouse: Path,
    instructions: Path,
    staged_plugin: Path,
    plugin_smoke_command: tuple[str, ...],
    output: Path,
) -> dict[str, Any]:
    if target != native_release_target() or target not in RELEASE_TARGETS:
        raise ValueError("declared target does not match this native runner")
    expected_plugin_digest = plugin_digest(staged_plugin)
    if any(
        not path.is_file()
        or path.is_symlink()
        or path.stat().st_size > MAX_ARTIFACT_SIZE
        for path in (agent_wheel, server_wheel, wheelhouse, instructions)
    ):
        raise ValueError(
            "release verification artifact is missing, unsafe, or too large"
        )
    validate_project_wheel(
        agent_wheel,
        distribution="t4l-agent",
        version=version,
        required_dependencies=("pyyaml", "t4l-server"),
        expected_plugin_digest=expected_plugin_digest,
    )
    validate_project_wheel(
        server_wheel,
        distribution="t4l-server",
        version="0.8.0",
        required_dependencies=("cryptography",),
    )
    validate_instruction_archive(instructions)
    clean_environment = {
        key: value
        for key, value in os.environ.items()
        if key.casefold()
        not in {
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "pip_index_url",
            "pip_extra_index_url",
        }
    }
    clean_environment.update(
        {
            "PIP_NO_INDEX": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_CONFIG_FILE": os.devnull,
        }
    )
    with tempfile.TemporaryDirectory(prefix=f"t4l-release-{target}-") as temporary:
        root = Path(temporary)
        links = root / "wheelhouse"
        _extract_wheelhouse(wheelhouse, links)
        shutil.copy2(agent_wheel, links / agent_wheel.name)
        shutil.copy2(server_wheel, links / server_wheel.name)
        virtual_environment = root / "venv"
        _run_checked(
            [sys.executable, "-m", "venv", str(virtual_environment)],
            environment=clean_environment,
            timeout=120,
        )
        python = virtual_environment / (
            "Scripts/python.exe" if os.name == "nt" else "bin/python"
        )
        _run_checked(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--no-index",
                "--disable-pip-version-check",
                "--no-cache-dir",
                "--find-links",
                str(links),
                f"t4l-agent=={version}",
                "t4l-server==0.8.0",
            ],
            environment=clean_environment,
            timeout=300,
        )
        _run_checked(
            [
                str(python),
                "-I",
                "-c",
                (
                    "from importlib.metadata import version; "
                    "import t4l_agent, t4l_server; "
                    f"assert version('t4l-agent') == '{version}'; "
                    "assert version('t4l-server') == '0.8.0'"
                ),
            ],
            environment=clean_environment,
            timeout=60,
        )
        _verify_plugin_smoke(
            plugin_smoke_command,
            staged_plugin=staged_plugin,
            expected_plugin_digest=expected_plugin_digest,
            environment=clean_environment,
        )
    receipt: dict[str, Any] = {
        "schema": "t4l_release_verification.v1",
        "target": target,
        "releaseId": release_id,
        "wheelhouseSha256": hashlib.sha256(wheelhouse.read_bytes()).hexdigest(),
        "instructionsSha256": hashlib.sha256(instructions.read_bytes()).hexdigest(),
        "agentWheelSha256": hashlib.sha256(agent_wheel.read_bytes()).hexdigest(),
        "serverWheelSha256": hashlib.sha256(server_wheel.read_bytes()).hexdigest(),
        "pluginDigest": expected_plugin_digest,
        "networkDisabled": True,
        "checks": sorted(REQUIRED_SMOKE_CHECKS),
    }
    if output.exists() or output.is_symlink():
        raise ValueError("target receipt output already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=output.parent,
        prefix=f".{output.name}.",
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(receipt, stream, separators=(",", ":"), sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, output)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary_name)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    stage = commands.add_parser("stage-plugin")
    stage.add_argument("--source", type=Path, required=True)
    stage.add_argument("--destination", type=Path, required=True)
    stage.add_argument("--policy", type=Path, required=True)
    stage.add_argument("--stamp-runtime-adapter", type=Path)
    stage.add_argument("--staging-root", type=Path)
    instructions = commands.add_parser("pack-instructions")
    instructions.add_argument("--source", type=Path, required=True)
    instructions.add_argument("--output", type=Path, required=True)
    wheelhouse = commands.add_parser("build-wheelhouse")
    wheelhouse.add_argument("--source", type=Path, required=True)
    wheelhouse.add_argument("--output", type=Path, required=True)
    verify_target = commands.add_parser("verify-target")
    verify_target.add_argument("--target", required=True)
    verify_target.add_argument("--release-id", required=True)
    verify_target.add_argument("--version", required=True)
    verify_target.add_argument("--agent-wheel", type=Path, required=True)
    verify_target.add_argument("--server-wheel", type=Path, required=True)
    verify_target.add_argument("--wheelhouse", type=Path, required=True)
    verify_target.add_argument("--instructions", type=Path, required=True)
    verify_target.add_argument("--staged-plugin", type=Path, required=True)
    verify_target.add_argument("--output", type=Path, required=True)
    verify_target.add_argument(
        "--plugin-smoke-command",
        nargs=argparse.REMAINDER,
        required=True,
    )
    sign = commands.add_parser("sign-manifest")
    sign.add_argument("--build-input", type=Path, required=True)
    sign.add_argument("--policy", type=Path, required=True)
    sign.add_argument("--output", type=Path, required=True)
    sign.add_argument("--private-key-env", default="T4L_RELEASE_PRIVATE_KEY")
    sign.add_argument("--verification-receipts", type=Path, required=True)
    sign.add_argument("--staged-plugin", type=Path, required=True)
    sign.add_argument("--pack-output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "stage-plugin":
        policy = json.loads(args.policy.read_text(encoding="utf-8"))
        digest = stage_plugin(args.source, args.destination, policy)
        if args.stamp_runtime_adapter:
            if args.staging_root is None or args.staging_root.is_symlink():
                raise ValueError(
                    "--staging-root is required for runtime digest stamping"
                )
            staging_root = args.staging_root.resolve(strict=True)
            repository_root = Path(__file__).resolve().parents[1]
            if staging_root == repository_root or repository_root.is_relative_to(
                staging_root
            ):
                raise ValueError("staging root must not be the source repository")
            stamp_path = args.stamp_runtime_adapter.resolve()
            destination = args.destination.resolve(strict=True)
            source_root = args.source.resolve(strict=True)
            if (
                not stamp_path.is_relative_to(staging_root)
                or not destination.is_relative_to(staging_root)
                or stamp_path.is_relative_to(source_root)
            ):
                raise ValueError(
                    "runtime digest and plugin must use the declared staging root"
                )
            stamp_runtime_adapter(args.stamp_runtime_adapter, digest)
        print(json.dumps({"pluginDigest": digest, "archive": None}))
        return 0
    if args.command == "pack-instructions":
        pack_instruction_bundle(args.source, args.output)
        print(
            json.dumps({"sha256": hashlib.sha256(args.output.read_bytes()).hexdigest()})
        )
        return 0
    if args.command == "build-wheelhouse":
        lock = build_wheelhouse(args.source, args.output)
        print(
            json.dumps(
                {
                    "sha256": hashlib.sha256(args.output.read_bytes()).hexdigest(),
                    "wheelCount": len(lock["files"]),
                }
            )
        )
        return 0
    if args.command == "verify-target":
        smoke_command = tuple(args.plugin_smoke_command)
        if smoke_command[:1] == ("--",):
            smoke_command = smoke_command[1:]
        receipt = produce_target_receipt(
            target=args.target,
            release_id=args.release_id,
            version=args.version,
            agent_wheel=args.agent_wheel,
            server_wheel=args.server_wheel,
            wheelhouse=args.wheelhouse,
            instructions=args.instructions,
            staged_plugin=args.staged_plugin,
            plugin_smoke_command=smoke_command,
            output=args.output,
        )
        print(json.dumps(receipt, separators=(",", ":"), sort_keys=True))
        return 0
    policy = json.loads(args.policy.read_text(encoding="utf-8"))
    raw_key = os.environ.get(args.private_key_env, "")
    if len(_decode_b64url(raw_key)) != 32:
        raise ValueError("release private key environment variable is invalid")
    private_key = Ed25519PrivateKey.from_private_bytes(_decode_b64url(raw_key))
    build = json.loads(args.build_input.read_text(encoding="utf-8"))
    digest = plugin_digest(args.staged_plugin)
    staged_policy = json.loads(
        (args.staged_plugin / "release-policy.json").read_text(encoding="utf-8")
    )
    if staged_policy != policy:
        raise ValueError("staged plugin release policy does not match signing policy")
    if build.get("minOpenClawVersion") != "2026.7.1-2":
        raise ValueError("release must pin the tested OpenClaw 2026.7.1-2 minimum")
    validate_project_wheel(
        artifact_path(build, "t4l-agent-wheel"),
        distribution="t4l-agent",
        version=str(build.get("version", "")),
        required_dependencies=("pyyaml", "t4l-server"),
        expected_plugin_digest=digest,
    )
    validate_project_wheel(
        artifact_path(build, "t4l-server-wheel"),
        distribution="t4l-server",
        version="0.8.0",
        required_dependencies=("cryptography",),
    )
    wheelhouse_items = [
        item
        for item in build.get("artifacts", [])
        if item.get("name") == "t4l-python-wheelhouse"
    ]
    if len(wheelhouse_items) != 1:
        raise ValueError("release build must contain one wheelhouse artifact")
    validate_wheelhouse_archive(artifact_path(build, "t4l-python-wheelhouse"))
    verify_release_receipts(
        args.verification_receipts,
        release_id=str(build.get("releaseId", "")),
        wheelhouse_sha256=artifact_digest(build, "t4l-python-wheelhouse"),
        instructions_sha256=artifact_digest(build, "t4l-instructions"),
        agent_wheel_sha256=artifact_digest(build, "t4l-agent-wheel"),
        server_wheel_sha256=artifact_digest(build, "t4l-server-wheel"),
        expected_plugin_digest=digest,
    )
    document = sign_manifest(build, policy, private_key)
    args.output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    archive = pack_plugin(args.staged_plugin, args.pack_output)
    print(
        json.dumps(
            {
                "manifestSha256": hashlib.sha256(args.output.read_bytes()).hexdigest(),
                "pluginDigest": digest,
                "archive": str(archive),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
