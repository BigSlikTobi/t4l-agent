from __future__ import annotations

import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from scripts.release_tools import (
    PLUGIN_DIGEST_FILES,
    RELEASE_TARGETS,
    _b64url,
    native_release_target,
    pack_instruction_bundle,
    pack_plugin,
    sign_manifest,
    stage_plugin,
    validate_instruction_archive,
    validate_wheelhouse_archive,
    verify_release_receipts,
)
from t4l_agent.runtime_adapter import _OPENCLAW_PLUGIN_DIGEST_FILES


def test_staged_npm_plugin_and_signed_manifest_have_no_hash_cycle(
    tmp_path: Path,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    policy = {
        "schema": "t4l_release_policy.v1",
        "releaseId": "t4l-agent-0.3.0",
        "version": "0.3.0",
        "manifestUrl": "https://release.example.test/t4l-release-0.3.0.json",
        "signingKeyId": "test-release-key",
        "signingPublicKey": _b64url(public_key),
    }
    source = Path(__file__).parents[1] / "openclaw_plugins" / "t4l-connect"
    staged = tmp_path / "plugin"
    digest = stage_plugin(source, staged, policy)
    assert len(digest) == 64
    assert tuple(PLUGIN_DIGEST_FILES) == _OPENCLAW_PLUGIN_DIGEST_FILES
    archive = pack_plugin(staged, tmp_path / "packages")
    assert archive.is_file()
    assert b"REPLACE_DURING_RELEASE_BUILD" not in archive.read_bytes()

    artifacts = []
    kinds = {
        "t4l-agent-wheel": "python-wheel",
        "t4l-server-wheel": "python-wheel",
        "t4l-python-wheelhouse": "python-wheelhouse-tar",
        "t4l-instructions": "instruction-bundle-tar",
    }
    for index, (name, kind) in enumerate(kinds.items()):
        path = tmp_path / f"artifact-{index}.bin"
        path.write_bytes(f"artifact-{index}".encode())
        artifacts.append(
            {
                "name": name,
                "kind": kind,
                "path": str(path),
                "url": f"https://release.example.test/{path.name}",
            }
        )
    manifest = sign_manifest(
        {
            "schema": "t4l_release_build_input.v1",
            "releaseId": policy["releaseId"],
            "version": policy["version"],
            "minOpenClawVersion": "2026.7.1-2",
            "artifacts": artifacts,
            "sourceRepositories": [],
        },
        policy,
        private_key,
    )
    assert manifest["signature"]["algorithm"] == "Ed25519"
    assert "manifestSha256" not in policy
    assert "REPLACE_" not in json.dumps(manifest)


def test_release_signing_gate_requires_the_complete_target_matrix(
    tmp_path: Path,
) -> None:
    receipts = tmp_path / "receipts"
    receipts.mkdir()
    values = {
        "release_id": "t4l-agent-0.3.0",
        "wheelhouse_sha256": "a" * 64,
        "instructions_sha256": "b" * 64,
        "agent_wheel_sha256": "d" * 64,
        "server_wheel_sha256": "e" * 64,
        "expected_plugin_digest": "c" * 64,
    }
    for target in RELEASE_TARGETS[:-1]:
        (receipts / f"{target}.json").write_text(
            json.dumps(
                {
                    "schema": "t4l_release_verification.v1",
                    "target": target,
                    "releaseId": values["release_id"],
                    "wheelhouseSha256": values["wheelhouse_sha256"],
                    "instructionsSha256": values["instructions_sha256"],
                    "agentWheelSha256": values["agent_wheel_sha256"],
                    "serverWheelSha256": values["server_wheel_sha256"],
                    "pluginDigest": values["expected_plugin_digest"],
                    "networkDisabled": True,
                    "checks": [
                        "offlineInstall",
                        "pythonImports",
                        "instructions",
                        "pluginLifecycle",
                    ],
                }
            ),
            encoding="utf-8",
        )
    try:
        verify_release_receipts(receipts, **values)
    except ValueError as error:
        assert RELEASE_TARGETS[-1] in str(error)
    else:
        raise AssertionError("incomplete release verification matrix was accepted")

    last = RELEASE_TARGETS[-1]
    template = json.loads((receipts / f"{RELEASE_TARGETS[0]}.json").read_text())
    template["target"] = last
    (receipts / f"{last}.json").write_text(json.dumps(template), encoding="utf-8")
    verify_release_receipts(receipts, **values)


def test_deterministic_instruction_archive_and_exact_wheelhouse_lock(
    tmp_path: Path,
) -> None:
    instructions = tmp_path / "instructions"
    files = {
        "contracts/coaching-contract.v1.schema.json": "{}\n",
        "docs/setup_instruction.md": "get_planning_context accepted state\n",
        "docs/coaching_setup.md": (
            "AgentDescriptor phone controls accepted state review-only proposal\n"
        ),
        "skills/t4l-onboard-athlete/SKILL.md": (
            "write_athlete_setup_draft athlete_setup_draft.v1\n"
        ),
        "skills/t4l-write-results/SKILL.md": ("youtube.com/shorts superset circuit\n"),
    }
    for relative, content in files.items():
        path = instructions / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    (instructions / "ignored.txt").write_text("not in the release\n", encoding="utf-8")
    first = tmp_path / "first.tar.gz"
    second = tmp_path / "second.tar.gz"
    pack_instruction_bundle(instructions, first)
    pack_instruction_bundle(instructions, second)
    assert first.read_bytes() == second.read_bytes()
    validate_instruction_archive(first)
    with tarfile.open(first, "r:gz") as archive:
        assert "ignored.txt" not in archive.getnames()

    wheel_names = []
    for version in ("311", "312", "313"):
        for prefix in ("PyYAML-6.0.3", "cffi-2.1.1"):
            wheel_names.extend(
                [
                    f"{prefix}-cp{version}-cp{version}-manylinux_2_17_x86_64.whl",
                    f"{prefix}-cp{version}-cp{version}-macosx_11_0_arm64.whl",
                ]
            )
    wheel_names.extend(
        [
            "cryptography-46.0.7-cp311-abi3-manylinux_2_17_x86_64.whl",
            "cryptography-46.0.7-cp311-abi3-macosx_10_9_universal2.whl",
            "pycparser-3.0-py3-none-any.whl",
            "pip-26.1.2-py3-none-any.whl",
        ]
    )
    contents = {name: name.encode() for name in wheel_names}
    lock = {
        "schema": "t4l_wheelhouse_lock.v1",
        "targets": list(RELEASE_TARGETS),
        "files": [
            {
                "filename": name,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
            for name, content in contents.items()
        ],
    }
    wheelhouse = tmp_path / "wheelhouse.tar.gz"
    with tarfile.open(wheelhouse, "w:gz") as archive:
        for name, archive_content in {
            **contents,
            "wheelhouse-lock.json": json.dumps(lock).encode(),
        }.items():
            info = tarfile.TarInfo(name)
            info.size = len(archive_content)
            archive.addfile(info, io.BytesIO(archive_content))
    assert validate_wheelhouse_archive(wheelhouse)["targets"] == list(RELEASE_TARGETS)


def test_native_release_target_is_exact_and_checks_linux_glibc() -> None:
    assert (
        native_release_target(
            system_name="Linux",
            machine="x86_64",
            python_version=(3, 11),
            libc=("glibc", "2.17"),
        )
        == "linux-x64-cp311"
    )
    assert (
        native_release_target(
            system_name="Darwin",
            machine="arm64",
            python_version=(3, 13),
        )
        == "darwin-arm64-cp313"
    )
    with pytest.raises(ValueError, match="glibc 2.17"):
        native_release_target(
            system_name="Linux",
            machine="x86_64",
            python_version=(3, 12),
            libc=("glibc", "2.16"),
        )
