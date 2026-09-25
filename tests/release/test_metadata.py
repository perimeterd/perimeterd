#!/usr/bin/env python3
"""Real Git/GPG regressions for the release admission boundary."""
import importlib.util
import io
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
import urllib.parse
import zipfile

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

    def release_env(self, attempt="1"):
        return {
            "GITHUB_REPOSITORY": "owner/repo",
            "GITHUB_RUN_ID": "123",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": self.commit,
            "GITHUB_RUN_NUMBER": "42",
            "GITHUB_RUN_ATTEMPT": attempt,
            "RELEASE_SIGNING_PUBLIC_KEYS": "",
        }

    def artifact_server(self, saved=None, status=None, extras=0, ambiguous=False, expired=False):
        content = None
        if saved is not None:
            archive = io.BytesIO()
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
                bundle.writestr("release-metadata.json", json.dumps(saved))
            content = archive.getvalue()
        items = [
            {"id": index + 10, "name": f"other-{index}", "expired": False}
            for index in range(extras)
        ]
        if saved is not None:
            item = {
                "id": 1,
                "name": "release-metadata-123",
                "expired": expired,
                "workflow_run": {"id": 123},
            }
            items.append(item)
            if ambiguous:
                items.append({**item, "id": 2})
        state = {"items": items, "content": content, "status": status}

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                if self.headers.get("Authorization") != "Bearer token":
                    self.send_error(401)
                    return
                if state["status"]:
                    self.send_error(state["status"])
                    return
                parsed = urllib.parse.urlsplit(self.path)
                if parsed.path == "/repos/owner/repo/actions/runs/123/artifacts":
                    page = int(urllib.parse.parse_qs(parsed.query).get("page", ["1"])[0])
                    start = (page - 1) * 100
                    values = state["items"][start:start + 100]
                    body = json.dumps({"total_count": len(state["items"]), "artifacts": values}).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                elif parsed.path == "/repos/owner/repo/actions/artifacts/1/zip" and state["content"]:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/zip")
                    self.send_header("Content-Length", str(len(state["content"])))
                    self.end_headers()
                    self.wfile.write(state["content"])
                else:
                    self.send_error(404)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def stop_server():
            server.shutdown()
            thread.join()
            server.server_close()

        self.addCleanup(stop_server)
        return {
            "GH_TOKEN": "token",
            "GITHUB_API_URL": f"http://127.0.0.1:{server.server_port}",
        }

    def persist_identity(self, env):
        path = Path(self.work.name) / "release-metadata.json"
        release.prepare(path, env)
        return path

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



    def test_rerun_reuses_the_durable_version_after_new_stable_tag(self):
        first_attempt = self.release_env()
        path = self.persist_identity(first_attempt)
        saved = json.loads(path.read_text(encoding="utf-8"))
        self.git("tag", "0.0.9", self.commit)
        retry = self.release_env("2")
        retry.update(self.artifact_server(saved, extras=101))
        release.prepare(path, retry)
        recovered = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(recovered["version"], saved["version"])
        self.assertEqual(recovered["commit"], self.commit)

    def test_rerun_fails_closed_when_metadata_is_missing(self):
        path = Path(self.work.name) / "recovered.json"
        env = self.release_env("2")
        env.update(self.artifact_server())
        with self.assertRaisesRegex(ValueError, "missing or expired"):
            release.prepare(path, env)
        self.assertFalse(path.exists())

    def test_rerun_rejects_metadata_bound_to_another_commit(self):
        saved = {
            **release.run_identity(self.release_env()),
            "GITHUB_SHA": "a" * 40,
            "schema": release.SCHEMA,
            "version": f"0.0.1-dev.42.g{self.commit[:12]}",
            "prerelease": True,
            "commit": self.commit,
        }
        path = Path(self.work.name) / "recovered.json"
        env = self.release_env("2")
        env.update(self.artifact_server(saved))
        with self.assertRaisesRegex(ValueError, "different GITHUB_SHA"):
            release.prepare(path, env)
        self.assertFalse(path.exists())

    def test_rerun_rejects_expired_ambiguous_and_malformed_metadata(self):
        first_attempt = self.release_env()
        path = self.persist_identity(first_attempt)
        saved = json.loads(path.read_text(encoding="utf-8"))
        path = Path(self.work.name) / "recovered.json"
        retry = self.release_env("2")
        retry.update(self.artifact_server(saved, expired=True))
        with self.assertRaisesRegex(ValueError, "has expired"):
            release.prepare(path, retry)

        retry = self.release_env("2")
        retry.update(self.artifact_server(saved, ambiguous=True))
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            release.prepare(path, retry)

        saved["schema"] = release.SCHEMA + 1
        retry = self.release_env("2")
        retry.update(self.artifact_server(saved))
        with self.assertRaisesRegex(ValueError, "unsupported schema"):
            release.prepare(path, retry)
        self.assertFalse(path.exists())

    def test_rerun_does_not_treat_api_authentication_failure_as_absence(self):
        path = Path(self.work.name) / "recovered.json"
        env = self.release_env("2")
        env.update(self.artifact_server(status=403))
        with self.assertRaisesRegex(ValueError, "HTTP 403"):
            release.prepare(path, env)
        self.assertFalse(path.exists())

    def test_candidate_tag_is_created_then_reused_without_rewriting(self):
        version = f"0.0.1-dev.42.g{self.commit[:12]}"
        release.ensure_candidate_tag(version, self.commit)
        self.assertEqual(self.git("rev-parse", f"refs/tags/{version}^{{commit}}"), self.commit)
        self.assertEqual(self.git("cat-file", "-t", f"refs/tags/{version}"), "commit")
        self.git("pack-refs", "--all")
        packed_before = Path(".git/packed-refs").read_bytes()
        release.ensure_candidate_tag(version, self.commit)
        self.assertEqual(Path(".git/packed-refs").read_bytes(), packed_before)
        self.assertFalse(Path(".git/refs/tags", version).exists())

    def test_candidate_tag_at_another_commit_fails_without_rewriting(self):
        version = f"0.0.1-dev.42.g{self.commit[:12]}"
        self.git("commit", "--allow-empty", "-m", "other target")
        wrong = self.git("rev-parse", "HEAD")
        self.git("tag", version, wrong)
        before = self.git("show-ref", "--verify", f"refs/tags/{version}")
        with self.assertRaisesRegex(ValueError, "not"):
            release.ensure_candidate_tag(version, self.commit)
        self.assertEqual(self.git("show-ref", "--verify", f"refs/tags/{version}"), before)

    def test_stable_version_cannot_be_synthesized_as_candidate_tag(self):
        with self.assertRaisesRegex(ValueError, "only admitted prerelease"):
            release.ensure_candidate_tag("0.0.1", self.commit)

if __name__ == "__main__":
    unittest.main()
