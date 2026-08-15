from __future__ import annotations

import os
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


class CommandRunner(Protocol):
    def run(
        self,
        argv: Sequence[str],
        *,
        env: Mapping[str, str],
        timeout_seconds: float,
    ) -> CommandResult: ...


class SubprocessCommandRunner:
    """Run a native runtime command without a shell or prompt automation."""

    def run(
        self,
        argv: Sequence[str],
        *,
        env: Mapping[str, str],
        timeout_seconds: float,
    ) -> CommandResult:
        child_env = dict(os.environ)
        child_env.update(env)
        try:
            completed = subprocess.run(
                list(argv),
                check=False,
                capture_output=True,
                text=True,
                env=child_env,
                timeout=timeout_seconds,
            )
        except FileNotFoundError:
            return CommandResult(127, stderr="runtime executable not found")
        except subprocess.TimeoutExpired:
            return CommandResult(124, stderr="runtime command timed out")
        return CommandResult(completed.returncode, completed.stdout, completed.stderr)
