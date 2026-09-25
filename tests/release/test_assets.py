#!/usr/bin/env python3
"""Real filesystem regressions for the release asset staging boundary."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/release-assets.py"
spec = importlib.util.spec_from_file_location("release_assets", SCRIPT)
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)

REQUIRED_ARTIFACTS = (
    "perimeterd_1_amd64.deb",
    "perimeterd_1_arm64.deb",
    "perimeterd-1.x86_64.rpm",
    "perimeterd-1.aarch64.rpm",
    "perimeterd_1_source.tar.gz",
    "perimeterd_1_linux_amd64.sbom.json",
    "perimeterd_1_linux_arm64.sbom.json",
)


class ReleaseAssetStaging(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "dist"
        self.source.mkdir()
        self.destination = self.root / "release-assets"

    def create_fixture(self, omit=()):
        names = [name for name in REQUIRED_ARTIFACTS if name not in omit]
        for name in names:
            (self.source / name).write_bytes(f"synthetic artifact: {name}\n".encode())
        return names

    def write_manifest(self, names, extra_lines=()):
        lines = [
            f"{hashlib.sha256((self.source / name).read_bytes()).hexdigest()}  {name}"
            for name in names
        ]
        lines.extend(extra_lines)
        (self.source / "checksums.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    def assert_rejected_by(self, message):
        with self.assertRaisesRegex(ValueError, message):
            release.stage(self.source, self.destination)

    def test_stages_exact_manifest_assets_and_excludes_intermediates(self):
        names = self.create_fixture()
        self.write_manifest(names)
        (self.source / "metadata.json").write_text("build metadata", encoding="utf-8")
        (self.source / "perimeterd").write_bytes(b"unpackaged build binary")

        release.stage(self.source, self.destination)

        self.assertEqual(
            {path.name for path in self.destination.iterdir()},
            set(names) | {"checksums.txt"},
        )
        for name in names:
            self.assertEqual((self.destination / name).read_bytes(), (self.source / name).read_bytes())
        self.assertEqual(
            (self.destination / "checksums.txt").read_bytes(),
            (self.source / "checksums.txt").read_bytes(),
        )

    def test_modified_bytes_with_valid_manifest_reach_checksum_guard(self):
        names = self.create_fixture()
        self.write_manifest(names)
        (self.source / names[0]).write_bytes(b"modified after manifest creation")

        self.assert_rejected_by("release artifact checksum mismatch")

    def test_duplicate_checksum_name_reaches_duplicate_guard(self):
        names = self.create_fixture()
        self.write_manifest([*names, names[0]])

        self.assert_rejected_by("duplicate release asset")

    def test_unsafe_checksum_path_is_rejected_as_invalid_entry(self):
        names = self.create_fixture()
        self.write_manifest(names, [f"{'a' * 64}  ../escape.deb"])

        self.assert_rejected_by("invalid release checksum entry")

    def test_symlink_artifact_is_rejected(self):
        names = self.create_fixture()
        self.write_manifest(names)
        artifact = self.source / names[0]
        artifact.unlink()
        target = self.root / "outside-artifact"
        target.write_bytes(b"not a regular release artifact")
        artifact.symlink_to(target)

        self.assert_rejected_by("missing or unsafe release artifact")

    def test_absent_manifest_artifact_is_rejected(self):
        names = self.create_fixture()
        self.write_manifest(names)
        (self.source / names[0]).unlink()

        self.assert_rejected_by("missing or unsafe release artifact")

    def test_missing_deb_count_reaches_required_artifact_guard(self):
        names = self.create_fixture(omit=("perimeterd_1_amd64.deb",))
        self.write_manifest(names)

        self.assert_rejected_by("release must contain two DEBs and two RPMs")

    def test_missing_rpm_count_reaches_required_artifact_guard(self):
        names = self.create_fixture(omit=("perimeterd-1.x86_64.rpm",))
        self.write_manifest(names)

        self.assert_rejected_by("release must contain two DEBs and two RPMs")

    def test_missing_source_archive_reaches_source_guard(self):
        names = self.create_fixture(omit=("perimeterd_1_source.tar.gz",))
        self.write_manifest(names)

        self.assert_rejected_by("release source archive missing")

    def test_insufficient_sbom_coverage_reaches_sbom_guard(self):
        names = self.create_fixture(omit=("perimeterd_1_linux_arm64.sbom.json",))
        self.write_manifest(names)

        self.assert_rejected_by("architecture SBOMs missing")


if __name__ == "__main__":
    unittest.main()
