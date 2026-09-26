#!/usr/bin/env python3
"""Stage exactly the checksum-covered release artifacts, never build intermediates."""
import hashlib
from pathlib import Path
import re
import shutil
import sys
import tempfile


def stage(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(destination)
    staging = Path(
        tempfile.mkdtemp(prefix=".release-assets-staging-", dir=destination.parent)
    )
    try:
        checksums = source / "checksums.txt"
        names = set()
        for line in checksums.read_text(encoding="utf-8").splitlines():
            match = re.fullmatch(
                r"([a-f0-9]{64})  ([A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?)",
                line,
            )
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
            shutil.copyfile(artifact, staging / name)
        if sum(name.endswith(".deb") for name in names) != 2 or sum(name.endswith(".rpm") for name in names) != 2:
            raise ValueError("release must contain two DEBs and two RPMs")
        source_archives = [
            name
            for name in names
            if name.startswith("perimeterd-source-") and name.endswith(".tar.gz")
        ]
        if not source_archives:
            raise ValueError("release source archive missing")
        required_artifacts = sorted(
            name for name in names if name.endswith((".deb", ".rpm"))
        ) + sorted(source_archives)
        missing_sboms = [
            f"{name}.spdx.sbom.json"
            for name in required_artifacts
            if f"{name}.spdx.sbom.json" not in names
        ]
        if missing_sboms:
            raise ValueError(f"missing required SBOMs: {', '.join(missing_sboms)}")
        shutil.copyfile(checksums, staging / checksums.name)
        if destination.exists() or destination.is_symlink():
            raise FileExistsError(destination)
        staging.rename(destination)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise

if __name__ == "__main__":
    stage(Path(sys.argv[1]), Path(sys.argv[2]))
