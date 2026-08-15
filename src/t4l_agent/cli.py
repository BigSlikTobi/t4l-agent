from __future__ import annotations

import argparse
import json
import logging
import os
import secrets
import sys
from pathlib import Path

from t4l_server.connector import AgentDescriptor, CommandSetupAdapter, ReleaseDescriptor

from .config import LoopConfig, env
from .license_audit import print_license_audit
from .runtime_adapter import (
    BootstrapSpec,
    OpenClawRuntimeAdapter,
    RuntimeKind,
    RuntimeTarget,
)
from .runtime_cli import run_runtime_adapter_cli, run_runtime_cli
from .runtime_coach import OpenClawRuntimeCoach, RuntimeCoach, RuntimeCoachError
from .server_runner import EmbeddedT4LServer
from .t4l_client import T4LError, T4LMcpClient

_LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.command == "run":
        return _run(args)
    if args.command == "chat-loop":
        return _chat_loop(args)
    if args.command == "licenses":
        return print_license_audit()
    if args.command == "runtime":
        return run_runtime_cli(str(args.runtime_action))
    if args.command == "runtime-adapter":
        return run_runtime_adapter_cli()
    return 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="t4l-agent")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run = subparsers.add_parser(
        "run",
        help="Start the complete T4L agent: server plus in-app chat loop.",
    )
    run.add_argument(
        "--data-dir",
        type=Path,
        default=None,
        help="Isolated server data directory. Defaults below ~/T4LAgents/<agent-id>.",
    )
    run.add_argument(
        "--release-state-file",
        type=Path,
        default=None,
        help="Host-installed signed release descriptor. Never supplied by the phone.",
    )
    run.add_argument("--host", default="127.0.0.1", help="Server bind host.")
    run.add_argument(
        "--allow-public-bind",
        action="store_true",
        help="Acknowledge binding outside loopback behind an HTTPS reverse proxy.",
    )
    run.add_argument("--port", default=8787, type=int, help="Server bind port.")
    run.add_argument(
        "--api-key",
        default=None,
        help="T4L server API key. Defaults to T4L_SERVER_API_KEY or a new key.",
    )
    run.add_argument(
        "--server-only",
        action="store_true",
        help="Unsupported legacy flag; secure setup requires the active chat loop.",
    )
    _add_agent_args(run)
    _add_loop_args(run)
    _add_logging_args(run)

    chat_loop = subparsers.add_parser(
        "chat-loop",
        help="Run the T4L in-app chat loop against an existing server.",
    )
    chat_loop.add_argument(
        "--server-url",
        default="http://127.0.0.1:8787",
        help="Base URL of a running T4L server.",
    )
    chat_loop.add_argument(
        "--api-key",
        default=None,
        help="T4L server API key. Defaults to T4L_SERVER_API_KEY or T4L_API_KEY.",
    )
    _add_agent_args(chat_loop, include_setup=False)
    _add_loop_args(chat_loop)
    _add_logging_args(chat_loop)

    subparsers.add_parser("licenses", help="Audit the runtime package licenses.")

    runtime = subparsers.add_parser(
        "runtime",
        help="Probe or bootstrap an isolated Hermes/OpenClaw runtime from JSON stdin.",
    )
    runtime.add_argument(
        "runtime_action",
        choices=(
            "probe",
            "prepare-pairing",
            "snapshot",
            "apply",
            "install",
            "update",
            "bootstrap",
            "verify",
            "rollback",
            "uninstall",
        ),
        help="Runtime adapter action. The request is read from JSON stdin.",
    )
    subparsers.add_parser(
        "runtime-adapter",
        help="Run one canonical runtime-adapter action envelope from JSON stdin.",
    )
    return parser


def _add_loop_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--poll-seconds",
        default=None,
        type=float,
        help="Seconds between chat polls.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Answer the current pending backlog once, then exit.",
    )
    parser.add_argument(
        "--recent-chat-limit",
        default=20,
        type=int,
        help="Recent chat turns to include in planning context.",
    )
    parser.add_argument(
        "--instruction-bundle-dir",
        type=Path,
        default=None,
        help="Installed T4L instruction bundle used by every coach turn.",
    )


def _add_agent_args(
    parser: argparse.ArgumentParser, *, include_setup: bool = True
) -> None:
    parser.add_argument("--agent-id", default="agent-01", help="Isolated agent id.")
    parser.add_argument(
        "--agent-name", default="T4L Coach", help="Verified coach display name."
    )
    parser.add_argument(
        "--agent-runtime",
        choices=("hermes", "openclaw"),
        default="openclaw",
        help="Messaging agent runtime.",
    )
    parser.add_argument(
        "--agent-profile", default=None, help="Isolated runtime profile."
    )
    parser.add_argument("--agent-home-dir", type=Path, default=None)
    parser.add_argument("--agent-state-dir", type=Path, default=None)
    parser.add_argument("--agent-config-path", type=Path, default=None)
    parser.add_argument("--runtime-executable", default=None)
    parser.add_argument(
        "--runtime-timeout-seconds",
        default=120.0,
        type=float,
        help="Timeout for one non-delivering coach turn through the runtime.",
    )
    if not include_setup:
        return
    parser.add_argument(
        "--runtime-adapter-command",
        default="t4l-agent",
        help="Executable providing the JSON runtime-adapter command.",
    )
    parser.add_argument(
        "--bootstrap-plugin-preinstalled",
        action="store_true",
        help=(
            "Signed host-installer mode: verify the owner-installed bootstrap "
            "package and defer MCP/instruction setup until phone pairing. Requires "
            "--release-state-file and --openclaw-plugin-dir; omit for manual runs."
        ),
    )
    parser.add_argument(
        "--openclaw-plugin-dir",
        type=Path,
        default=None,
        help=(
            "Absolute install.installPath from `openclaw plugins inspect "
            "t4l-connect --json`; required for a wheel/pipx manual install."
        ),
    )
    parser.add_argument(
        "--connector-owner-id",
        action="append",
        default=None,
        help=(
            "Canonical owner identity allowed to confirm pairing: "
            "channel:account:sender. Repeat for multiple owners."
        ),
    )


def _add_logging_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=_LOG_LEVELS,
        help="Logging verbosity.",
    )


def _run(args: argparse.Namespace) -> int:
    _configure_logging(args.log_level)
    if args.server_only:
        print(
            "--server-only is unsupported. Secure pairing and setup require the "
            "active in-app coach loop.",
            file=sys.stderr,
        )
        return 2
    if args.bootstrap_plugin_preinstalled and args.release_state_file is None:
        print(
            "--bootstrap-plugin-preinstalled is reserved for the signed host "
            "installer and requires --release-state-file. Omit it for a manual "
            "connector run.",
            file=sys.stderr,
        )
        return 2
    raw_plugin_dir = args.openclaw_plugin_dir
    if args.bootstrap_plugin_preinstalled and raw_plugin_dir is None:
        print(
            "--bootstrap-plugin-preinstalled requires the absolute "
            "--openclaw-plugin-dir reported by OpenClaw plugin inspection.",
            file=sys.stderr,
        )
        return 2
    openclaw_plugin_dir: Path | None = None
    if raw_plugin_dir is not None:
        expanded_plugin_dir = raw_plugin_dir.expanduser()
        if not expanded_plugin_dir.is_absolute():
            print("--openclaw-plugin-dir must be absolute.", file=sys.stderr)
            return 2
        if expanded_plugin_dir.is_symlink() or not expanded_plugin_dir.is_dir():
            print(
                "--openclaw-plugin-dir must be an existing, non-symlink directory.",
                file=sys.stderr,
            )
            return 2
        openclaw_plugin_dir = expanded_plugin_dir.resolve(strict=True)
    if not _is_loopback_bind(str(args.host)) and not args.allow_public_bind:
        print(
            "Public binding requires --allow-public-bind and an HTTPS reverse proxy.",
            file=sys.stderr,
        )
        return 2
    connector_runtime_token = env("T4L_CONNECTOR_RUNTIME_TOKEN")
    if not connector_runtime_token:
        print(
            "T4L_CONNECTOR_RUNTIME_TOKEN is required for secure phone pairing.",
            file=sys.stderr,
        )
        return 2
    owner_ids = frozenset(
        value.strip() for value in (args.connector_owner_id or []) if value.strip()
    )
    if not owner_ids:
        print("At least one --connector-owner-id is required.", file=sys.stderr)
        return 2
    if any(not _is_canonical_owner_identity(value) for value in owner_ids):
        print(
            "Every --connector-owner-id must use channel:account:sender.",
            file=sys.stderr,
        )
        return 2
    token = (
        args.api_key
        or env("T4L_SERVER_API_KEY")
        or env("T4L_API_KEY")
        or env("MCP_T4L_API_KEY")
        or secrets.token_urlsafe(24)
    )
    os.environ["MCP_T4L_API_KEY"] = token
    agent_id = str(args.agent_id).strip()
    profile = str(args.agent_profile or agent_id).strip()
    root = Path("~/T4LAgents").expanduser() / agent_id
    data_dir = (args.data_dir or root / "server-data").expanduser().resolve()
    home_dir = (args.agent_home_dir or root / "home").expanduser().resolve()
    state_dir = (
        args.agent_state_dir.expanduser().resolve()
        if args.agent_state_dir is not None
        else None
    )
    config_path = (
        args.agent_config_path.expanduser().resolve()
        if args.agent_config_path is not None
        else None
    )
    instruction_bundle = (
        (args.instruction_bundle_dir or root / "instructions").expanduser().resolve()
    )
    if not instruction_bundle.is_dir():
        print(
            f"Instruction bundle is missing: {instruction_bundle}",
            file=sys.stderr,
        )
        return 2
    if str(args.agent_runtime) != RuntimeKind.OPENCLAW.value:
        print(
            "Hermes has no verified pre-model /t4l owner hook. Secure phone "
            "pairing is unavailable; use OpenClaw or add a trusted gateway adapter.",
            file=sys.stderr,
        )
        return 2
    runtime_target = RuntimeTarget(
        runtime=RuntimeKind.OPENCLAW,
        agent_id=agent_id,
        profile=profile,
        home_dir=home_dir,
        state_dir=state_dir,
        config_path=config_path,
        executable=str(args.runtime_executable or args.agent_runtime),
    )
    runtime_spec = BootstrapSpec(
        target=runtime_target,
        t4l_server_url=f"http://127.0.0.1:{int(args.port)}/mcp",
        instruction_bundle_dir=instruction_bundle,
        connector_base_url=f"http://127.0.0.1:{int(args.port)}",
        openclaw_plugin_dir=openclaw_plugin_dir,
    )
    runtime_adapter = OpenClawRuntimeAdapter()
    if args.bootstrap_plugin_preinstalled:
        preinstalled = runtime_adapter.verify_preinstalled_pairing_command(runtime_spec)
        runtime_probe = preinstalled.probe
        if not preinstalled.ok:
            print(
                "The owner-installed OpenClaw bootstrap package could not be "
                "verified: " + "; ".join(preinstalled.details),
                file=sys.stderr,
            )
            return 2
    else:
        pairing_setup = runtime_adapter.prepare_pairing_command(runtime_spec)
        if not pairing_setup.ok or not pairing_setup.checks.get(
            "pairingCommand", False
        ):
            print(
                f"Secure OpenClaw pairing setup failed: {pairing_setup.message}",
                file=sys.stderr,
            )
            return 2
        runtime_probe = pairing_setup.probe
    descriptor = AgentDescriptor(
        agent_id=agent_id,
        display_name=str(args.agent_name),
        runtime=str(args.agent_runtime),
        provider=runtime_probe.provider,
        model=runtime_probe.model,
        reasoning=None,
    )
    try:
        release = _release_descriptor(args.release_state_file)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Installed release descriptor is invalid: {error}", file=sys.stderr)
        return 2
    setup_adapter = CommandSetupAdapter(
        executable=str(args.runtime_adapter_command),
        descriptor=descriptor,
        profile=profile,
        home_dir=str(home_dir),
        state_dir=str(state_dir) if state_dir is not None else None,
        config_path=str(config_path) if config_path is not None else None,
        runtime_executable=str(args.runtime_executable or args.agent_runtime),
        instruction_bundle_dir=str(instruction_bundle),
        connector_base_url=f"http://127.0.0.1:{int(args.port)}",
        owner_ids=owner_ids,
        openclaw_plugin_dir=(
            str(openclaw_plugin_dir) if openclaw_plugin_dir is not None else None
        ),
    )
    with EmbeddedT4LServer(
        data_dir=data_dir,
        host=str(args.host),
        port=int(args.port),
        api_key=token,
        agent_id=descriptor.agent_id,
        agent_name=descriptor.display_name,
        agent_runtime=descriptor.runtime,
        agent_provider=descriptor.provider,
        agent_model=descriptor.model,
        agent_reasoning=descriptor.reasoning,
        connector_runtime_token=connector_runtime_token,
        connector_setup_adapter=setup_adapter,
        connector_release=release,
    ) as running:
        _print_startup(
            running.server_url,
            running.mcp_url,
            running.data_dir,
            descriptor,
            profile,
        )
        client = T4LMcpClient(running.server_url, running.api_key)
        model = _runtime_coach(runtime_target, float(args.runtime_timeout_seconds))
        return _run_loop_from_args(
            args,
            client,
            model,
            instruction_bundle_dir=instruction_bundle,
        )


def _chat_loop(args: argparse.Namespace) -> int:
    _configure_logging(args.log_level)
    token = args.api_key or env("T4L_SERVER_API_KEY") or env("T4L_API_KEY")
    if not token:
        print(
            "Chat loop requires --api-key (or T4L_SERVER_API_KEY/T4L_API_KEY).",
            file=sys.stderr,
        )
        return 2
    bundle_value = args.instruction_bundle_dir or env("T4L_INSTRUCTION_BUNDLE_DIR")
    if not bundle_value:
        print("Chat loop requires --instruction-bundle-dir.", file=sys.stderr)
        return 2
    instruction_bundle = Path(bundle_value).expanduser().resolve()
    if not instruction_bundle.is_dir():
        print(
            f"Instruction bundle is missing: {instruction_bundle}",
            file=sys.stderr,
        )
        return 2
    if str(args.agent_runtime) != RuntimeKind.OPENCLAW.value:
        print(
            "This build has no verified Hermes coach-execution adapter.",
            file=sys.stderr,
        )
        return 2
    agent_id = str(args.agent_id).strip()
    profile = str(args.agent_profile or agent_id).strip()
    root = Path("~/T4LAgents").expanduser() / agent_id
    home_dir = (args.agent_home_dir or root / "home").expanduser().resolve()
    state_dir = (
        args.agent_state_dir.expanduser().resolve()
        if args.agent_state_dir is not None
        else None
    )
    config_path = (
        args.agent_config_path.expanduser().resolve()
        if args.agent_config_path is not None
        else None
    )
    target = RuntimeTarget(
        runtime=RuntimeKind.OPENCLAW,
        agent_id=agent_id,
        profile=profile,
        home_dir=home_dir,
        state_dir=state_dir,
        config_path=config_path,
        executable=str(args.runtime_executable or args.agent_runtime),
    )
    client = T4LMcpClient(str(args.server_url), token)
    model = _runtime_coach(target, float(args.runtime_timeout_seconds))
    return _run_loop_from_args(
        args,
        client,
        model,
        instruction_bundle_dir=instruction_bundle,
    )


def _run_loop_from_args(
    args: argparse.Namespace,
    client: T4LMcpClient,
    model: RuntimeCoach,
    *,
    instruction_bundle_dir: Path,
) -> int:
    from .chat_loop import run_chat_loop

    poll_seconds = args.poll_seconds
    if poll_seconds is None:
        poll_seconds = float(env("T4L_AGENT_POLL_SECONDS", "3"))
    config = LoopConfig(
        server_url=client.server_url,
        api_key="",
        poll_seconds=float(poll_seconds),
        once=bool(args.once),
        recent_chat_limit=max(1, int(args.recent_chat_limit)),
        instruction_bundle_dir=instruction_bundle_dir,
    )
    try:
        stats = run_chat_loop(client=client, model=model, config=config)
    except KeyboardInterrupt:
        return 0
    except (T4LError, RuntimeCoachError) as error:
        print(f"t4l-agent failed: {error}", file=sys.stderr)
        return 1
    if config.once:
        print(
            f"Checked {stats.checked} pending message(s), "
            f"answered {stats.answered}, wrote {stats.notes_written} note update(s), "
            f"{stats.setup_drafts_written} setup draft(s), and "
            f"{stats.training_plans_written} training plan(s)."
        )
    return 0


def _print_startup(
    server_url: str,
    mcp_url: str,
    data_dir: Path,
    descriptor: AgentDescriptor,
    profile: str,
) -> None:
    print("T4L Complete Agent")
    print(f"Data dir: {data_dir}")
    print(f"Server URL: {server_url}")
    print(f"MCP URL: {mcp_url}")
    print(f"Agent: {descriptor.display_name} ({descriptor.agent_id})")
    print(f"Runtime profile: {descriptor.runtime}/{profile}")
    if descriptor.provider or descriptor.model or descriptor.reasoning:
        identity = "/".join(
            value for value in (descriptor.provider, descriptor.model) if value
        )
        reasoning = f" ({descriptor.reasoning})" if descriptor.reasoning else ""
        print(f"Runtime model: {identity or 'reported'}{reasoning}")
    print("Pair the phone with the one-time code. No runtime credential is displayed.")


def _runtime_coach(
    target: RuntimeTarget, timeout_seconds: float
) -> OpenClawRuntimeCoach:
    return OpenClawRuntimeCoach(
        executable=target.executable,
        profile=target.profile,
        agent_id=target.agent_id,
        home_dir=target.home_dir,
        state_dir=target.runtime_state_dir,
        config_path=target.runtime_config_path,
        timeout_seconds=max(1.0, timeout_seconds),
    )


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


def _is_loopback_bind(host: str) -> bool:
    return host.strip().casefold() in {"127.0.0.1", "::1", "localhost"}


def _is_canonical_owner_identity(value: str) -> bool:
    parts = value.split(":")
    return len(parts) == 3 and all(part and part == part.strip() for part in parts)


def _release_descriptor(path: Path | None) -> ReleaseDescriptor | None:
    if path is None:
        return None
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise ValueError("release descriptor must not be a symbolic link")
    resolved = expanded.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError("release descriptor must be a regular file")
    document = json.loads(resolved.read_text(encoding="utf-8"))
    if (
        not isinstance(document, dict)
        or document.get("schema") != "t4l_installed_release.v1"
    ):
        raise ValueError("release descriptor schema is invalid")
    return ReleaseDescriptor(
        release_id=str(document.get("releaseId") or ""),
        version=str(document.get("version") or ""),
        manifest_url=str(document.get("manifestUrl") or ""),
        manifest_sha256=str(document.get("manifestSha256") or ""),
        signing_key_id=str(document.get("signingKeyId") or ""),
    )
