#!/usr/bin/env python3
"""Real archive-decoder regressions for the shared release payload extractor."""
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/release_sbom.py"
spec = importlib.util.spec_from_file_location("release_sbom", SCRIPT)
sbom = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sbom)


class PayloadExtraction(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.archive = self.root / "perimeterd_1.2.3_linux_amd64.tar.gz"
        self.destination = self.root / "extracted"

    def write_archive(self, entries):
        with tarfile.open(self.archive, "w:gz") as archive:
            for name, kind in entries:
                member = tarfile.TarInfo(name)
                if kind == "link":
                    member.type = tarfile.SYMTYPE
                    member.linkname = "../outside"
                    archive.addfile(member)
                else:
                    content = b"executable fixture"
                    member.size = len(content)
                    archive.addfile(member, io.BytesIO(content))

    def test_rejects_symlink_executable_without_writing_outside_temp(self):
        self.write_archive([("perimeterd", "link")])
        with self.assertRaisesRegex(sbom.SBOMError, "links/special files"):
            sbom.extract_binary(self.archive, "archive", self.destination)
        self.assertFalse(self.destination.exists())
        self.assertFalse((self.root / "outside").exists())

    def test_rejects_unsafe_member_even_if_valid_executable_is_present(self):
        self.write_archive([("../outside", "file"), ("perimeterd", "file")])
        with self.assertRaisesRegex(sbom.SBOMError, "unsafe archive member path"):
            sbom.extract_binary(self.archive, "archive", self.destination)
        self.assertFalse(self.destination.exists())
        self.assertFalse((self.root / "outside").exists())

    def test_rejects_ambiguous_executable(self):
        self.write_archive([("perimeterd", "file"), ("perimeterd", "file")])
        with self.assertRaisesRegex(sbom.SBOMError, "exactly one regular binary member"):
            sbom.extract_binary(self.archive, "archive", self.destination)
        self.assertFalse(self.destination.exists())


if __name__ == "__main__":
    unittest.main()
