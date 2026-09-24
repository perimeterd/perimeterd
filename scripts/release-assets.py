#!/usr/bin/env python3
"""Stage exactly the checksum-covered release artifacts, never build intermediates."""
import hashlib
from pathlib import Path
import re
import shutil
import sys


def stage(source, destination):
    destination.mkdir(parents=True, exist_ok=False)
    checksums = source / "checksums.txt"
    names = set()
    for line in checksums.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([a-f0-9]{64})  ([A-Za-z0-9_.+~-]+)", line)
        if not match:
            raise ValueError("invalid release checksum entry")
        checksum, name = match.groups()
        if name in names:
            raise ValueError("duplicate release asset")
        names.add(name)
        artifact = source / name
        if artifact.is_symlink() or not artifact.is_file():
            raise ValueError(f"missing or unsafe release artifact: {name}")
        with artifact.open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if actual != checksum:
            raise ValueError(f"release artifact checksum mismatch: {name}")
        shutil.copyfile(artifact, destination / name)
    if sum(name.endswith(".deb") for name in names) != 2 or sum(name.endswith(".rpm") for name in names) != 2:
        raise ValueError("release must contain two DEBs and two RPMs")
    if not any("source" in name and name.endswith(".tar.gz") for name in names):
        raise ValueError("release source archive missing")
    if sum(name.endswith(".sbom.json") for name in names) < 2:
        raise ValueError("architecture SBOMs missing")
    shutil.copyfile(checksums, destination / checksums.name)


if __name__ == "__main__":
    stage(Path(sys.argv[1]), Path(sys.argv[2]))
