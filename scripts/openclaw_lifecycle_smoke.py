#!/usr/bin/env python3
"""Run the release-gate lifecycle smoke against a real OpenClaw CLI."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path


def _required_path(name: str) -> Path:
    raw = os.environ.get(name, "")
    path = Path(raw)
    if not path.is_absolute() or path.is_symlink() or not path.exists():
        raise RuntimeError(f"{name} must be an existing absolute non-symlink path")
    return path.resolve(strict=True)


def _run(
    command: list[str],
    *,
    environment: dict[str, str],
    timeout: int = 120,
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
        detail = (result.stderr or result.stdout).strip()[-1200:]
        raise RuntimeError(f"OpenClaw lifecycle command failed: {detail}")
    return result


def main() -> int:
    plugin = _required_path("T4L_STAGED_PLUGIN")
    openclaw = _required_path("T4L_OPENCLAW_EXECUTABLE")
    node = _required_path("T4L_NODE_EXECUTABLE")
    digest = os.environ.get("T4L_PLUGIN_DIGEST", "")
    if len(digest) != 64 or os.environ.get("T4L_NETWORK_DISABLED_REQUIRED") != "1":
        raise RuntimeError("release smoke environment is incomplete")

    with tempfile.TemporaryDirectory(prefix="t4l-openclaw-release-smoke-") as raw:
        root = Path(raw)
        config_path = root / "openclaw.json"
        config_path.write_text("{}\n", encoding="utf-8")
        environment = {
            **os.environ,
            "PATH": f"{node.parent}{os.pathsep}/usr/bin{os.pathsep}/bin",
            "OPENCLAW_HOME": str(root / "home"),
            "OPENCLAW_STATE_DIR": str(root / "state"),
            "OPENCLAW_CONFIG_PATH": str(config_path),
        }
        base = [str(openclaw), "--profile", "t4l-release-smoke"]
        version_line = _run(
            [str(openclaw), "--version"], environment=environment
        ).stdout.strip()
        version = next(
            (part for part in version_line.split() if part.startswith("2026.")),
            "",
        )
        _run(
            [*base, "plugins", "install", str(plugin), "--force"],
            environment=environment,
            timeout=180,
        )
        inspection = json.loads(
            _run(
                [
                    *base,
                    "plugins",
                    "inspect",
                    "t4l-connect",
                    "--runtime",
                    "--json",
                ],
                environment=environment,
            ).stdout
        )
        installed = inspection.get("plugin", {})
        install_path = Path(str(inspection.get("install", {}).get("installPath", "")))
        if (
            installed.get("status") != "loaded"
            or installed.get("packageName") != "@t4l-trainer/openclaw-t4l-connect"
            or "t4l" not in inspection.get("commands", [])
            or not install_path.is_absolute()
        ):
            raise RuntimeError("OpenClaw did not load the pinned T4L plugin")

        owner_probe = r"""
import { pathToFileURL } from "node:url";
const pluginRoot = process.argv[1];
const module = await import(pathToFileURL(`${pluginRoot}/dist/index.js`).href);
let command;
let submitted;
process.env.T4L_CONNECTOR_RUNTIME_TOKEN = "release-smoke-token";
module.createT4LConnectPlugin(async (_url, init) => {
  submitted = JSON.parse(init.body);
  return { ok: true, async json() { return { status: "confirmed" }; } };
}).register({
  pluginConfig: {
    agentId: "main",
    installRoot: `${pluginRoot}/release-smoke-state`,
    connectorBaseUrl: "http://127.0.0.1:18787",
  },
  registerCommand(value) { command = value; },
});
const reply = await command.handler({
  agentId: "main",
  args: "connect TEST-1234",
  senderId: "release-owner",
  channel: "slack",
  accountId: "release-workspace",
  isAuthorizedSender: true,
  senderIsOwner: true,
  gatewayClientScopes: ["operator.pairing"],
});
if (!/confirmed/i.test(reply.text) || submitted.verifiedSenderId !== "release-owner") {
  throw new Error("owner command did not reach the verified pre-model handler");
}
"""
        _run(
            [str(node), "--input-type=module", "-e", owner_probe, str(install_path)],
            environment=environment,
        )
        _run(
            [*base, "plugins", "uninstall", "t4l-connect", "--force"],
            environment=environment,
        )
        remaining = _run(
            [*base, "plugins", "list", "--json"], environment=environment
        ).stdout
        if '"id":"t4l-connect"' in remaining.replace(" ", ""):
            raise RuntimeError("OpenClaw retained the T4L plugin after uninstall")

    print(
        json.dumps(
            {
                "schema": "t4l_plugin_lifecycle_smoke.v1",
                "ok": True,
                "pluginDigest": digest,
                "openClawVersion": version,
                "networkDisabled": True,
                "modelInvoked": False,
                "checks": ["install", "load", "ownerCommand", "uninstall"],
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
