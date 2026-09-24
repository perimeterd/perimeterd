#!/usr/bin/env python3
"""Real Git/GPG regressions for the release admission boundary."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/release-metadata.py"
spec = importlib.util.spec_from_file_location("release_metadata", SCRIPT)
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseAdmission(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        previous = Path.cwd()
        os.chdir(self.work.name)
        self.addCleanup(os.chdir, previous)
        self.git("init", "--initial-branch=main")
        self.git("config", "user.email", "release@example.invalid")
        self.git("config", "user.name", "Release test")
        self.git("commit", "--allow-empty", "-m", "main")
        self.commit = self.git("rev-parse", "HEAD")
        self.git("update-ref", "refs/remotes/origin/main", self.commit)

    def git(self, *args, env=None):
        return subprocess.check_output(["git", *args], text=True, stderr=subprocess.DEVNULL, env=env).strip()

    def admit(self, ref, keys=""):
        return release.metadata(ref, "42", self.git("rev-parse", "HEAD"), keys)

    def test_main_version_is_semver_and_ignores_unmerged_or_prerelease_tags(self):
        self.git("tag", "0.0.2")
        self.git("tag", "10.0.0-dev.1")
        self.git("checkout", "-b", "other")
        self.git("commit", "--allow-empty", "-m", "other")
        self.git("tag", "99.0.0")
        self.git("checkout", "main")
        result = self.admit("refs/heads/main")
        self.assertEqual(result["version"], f"0.0.3-dev.42.g{self.commit[:12]}")
        self.assertEqual(result["prerelease"], "true")
        self.assertEqual(result["commit"], self.commit)

    def test_first_prerelease_precedes_first_stable(self):
        self.assertEqual(self.admit("refs/heads/main")["version"], f"0.0.1-dev.42.g{self.commit[:12]}")

    def test_non_main_commit_is_rejected_even_with_stable_tag(self):
        self.git("checkout", "-b", "other")
        self.git("commit", "--allow-empty", "-m", "other")
        self.git("tag", "0.0.1")
        with self.assertRaises(subprocess.CalledProcessError):
            self.admit("refs/tags/0.0.1")

    def test_noncanonical_stable_versions_are_rejected(self):
        for tag in ["v0.0.1", "01.0.0", "1.0", "1.0.0-rc.1", "1.0.0+build"]:
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                self.admit("refs/tags/" + tag)

    def test_unsigned_tag_cannot_publish(self):
        self.git("tag", "0.0.1")
        with self.assertRaises(ValueError):
            self.admit("refs/tags/0.0.1")

    def test_signed_tag_requires_configured_signing_key(self):
        home = Path("gpg")
        home.mkdir(mode=0o700)
        env = dict(os.environ, GNUPGHOME=str(home.resolve()))
        subprocess.run(["gpg", "--batch", "--passphrase", "", "--quick-generate-key",
                        "Release test <release@example.invalid>", "ed25519", "sign", "0"],
                       env=env, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        keys = subprocess.check_output(["gpg", "--armor", "--export"], env=env, text=True)
        self.git("-c", "gpg.format=openpgp", "-c", "user.signingkey=release@example.invalid",
                 "tag", "-s", "0.0.1", "-m", "release", env=env)
        self.assertEqual(self.admit("refs/tags/0.0.1", keys)["prerelease"], "false")
        self.git("tag", "0.0.2")
        with self.assertRaises(subprocess.CalledProcessError):
            self.admit("refs/tags/0.0.2", keys)
        with self.assertRaises(ValueError):
            self.admit("refs/tags/0.0.1", "")


if __name__ == "__main__":
    unittest.main()
