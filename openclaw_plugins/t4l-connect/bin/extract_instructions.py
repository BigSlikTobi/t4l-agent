#!/usr/bin/env python3
"""Safely extract the pinned T4L instruction tarball.

This helper uses only the Python standard library. The Node bootstrap invokes
it with fixed argv and never passes it phone-controlled paths.
"""

from __future__ import annotations

import os
import sys
import tarfile
from pathlib import Path

MAX_FILES = 2_000
MAX_TOTAL_BYTES = 64 * 1024 * 1024


def _safe_member(root: Path, member: tarfile.TarInfo) -> Path:
    if member.name.startswith(("/", "\\")):
        raise ValueError("instruction archive contains an absolute path")
    if member.issym() or member.islnk() or member.isdev() or member.isfifo():
        raise ValueError("instruction archive contains an unsupported entry")
    target = (root / member.name).resolve(strict=False)
    if not target.is_relative_to(root):
        raise ValueError("instruction archive escapes its destination")
    return target


def extract(archive: Path, destination: Path) -> None:
    root = destination.resolve(strict=True)
    count = 0
    size = 0
    with tarfile.open(archive, mode="r:gz") as bundle:
        members = bundle.getmembers()
        for member in members:
            count += 1
            size += max(0, member.size)
            if count > MAX_FILES or size > MAX_TOTAL_BYTES:
                raise ValueError("instruction archive exceeds safety limits")
            _safe_member(root, member)
            if not (member.isdir() or member.isfile()):
                raise ValueError("instruction archive contains an unsupported entry")
        for member in members:
            target = _safe_member(root, member)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
                continue
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            source = bundle.extractfile(member)
            if source is None:
                raise ValueError("instruction archive member has no data")
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with source, os.fdopen(descriptor, "wb") as output:
                while chunk := source.read(1024 * 1024):
                    output.write(chunk)


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: extract_instructions.py ARCHIVE DESTINATION", file=sys.stderr)
        return 2
    archive = Path(sys.argv[1]).resolve(strict=True)
    destination = Path(sys.argv[2]).resolve(strict=True)
    extract(archive, destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
