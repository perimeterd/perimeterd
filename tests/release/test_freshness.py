#!/usr/bin/env python3
"""Freshness-gate decisions against an isolated GitHub ref API."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.parse

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/release-freshness.py"
spec = importlib.util.spec_from_file_location("release_freshness", SCRIPT)
freshness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(freshness)

METADATA_SCRIPT = Path(__file__).resolve().parents[2] / "scripts/release-metadata.py"
metadata_spec = importlib.util.spec_from_file_location("release_metadata", METADATA_SCRIPT)
release_metadata = importlib.util.module_from_spec(metadata_spec)
metadata_spec.loader.exec_module(release_metadata)

PUBLISH_SCRIPT = Path(__file__).resolve().parent / "test_publish.py"
publish_spec = importlib.util.spec_from_file_location("test_publish", PUBLISH_SCRIPT)
test_publish = importlib.util.module_from_spec(publish_spec)
publish_spec.loader.exec_module(test_publish)


class MainRefAPI:
    def __init__(self, sha):
        self.sha = sha
        self.status = None
        self.body = None
        self.requests = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def send_body(self, status, body):
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                path = urllib.parse.urlsplit(self.path).path
                outer.requests.append({"path": path, "authorization": self.headers.get("Authorization")})
                if self.headers.get("Authorization") != "Bearer token":
                    self.send_error(401)
                    return
                if outer.status is not None:
                    self.send_error(outer.status)
                    return
                if path != "/repos/owner/repo/git/ref/heads/main":
                    self.send_error(404)
                    return
                body = outer.body
                if body is None:
                    body = json.dumps({
                        "ref": "refs/heads/main",
                        "object": {"sha": outer.sha, "type": "commit"},
                    }).encode("utf-8")
                self.send_body(200, body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server.server_port}"

    def close(self):
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()


class ReleaseFreshness(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.repo = Path(self.work.name) / "repo"
        self.repo.mkdir()
        self.git("init", "--initial-branch=main")
        self.git("config", "user.email", "release@example.invalid")
        self.git("config", "user.name", "Release test")
        self.git("commit", "--allow-empty", "-m", "admitted candidate")
        self.admitted = self.git("rev-parse", "HEAD")
        self.git("commit", "--allow-empty", "-m", "new main candidate")
        self.new_main = self.git("rev-parse", "HEAD")
        self.git("update-ref", "refs/remotes/origin/main", self.new_main)

        self.api = MainRefAPI(self.admitted)
        self.addCleanup(self.api.close)
        self.cli_counter = 0

    def git(self, *args, env=None):
        return subprocess.check_output(
            ["git", "-C", str(self.repo), *args],
            text=True,
            stderr=subprocess.DEVNULL,
            env=env,
        ).strip()

    def env(self, ref="refs/heads/main", commit=None, **extra):
        values = {
            "GITHUB_REF": ref,
            "GITHUB_SHA": commit or self.admitted,
            "GITHUB_REPOSITORY": "owner/repo",
            "GITHUB_API_URL": self.api.url,
            "GH_TOKEN": "token",
        }
        values.update(extra)
        return values

    def run_cli(self, checkpoint, commit=None, env=None):
        self.cli_counter += 1
        output = Path(self.work.name) / f"output-{self.cli_counter}"
        summary = Path(self.work.name) / f"summary-{self.cli_counter}"
        output.write_text("", encoding="utf-8")
        summary.write_text("", encoding="utf-8")
        process_env = os.environ.copy()
        for key in ("GITHUB_REF", "GITHUB_SHA", "GITHUB_REPOSITORY", "GITHUB_API_URL",
                    "GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY", "GH_TOKEN", "GITHUB_TOKEN"):
            process_env.pop(key, None)
        process_env.update(self.env(commit=commit))
        if env is not None:
            process_env.update(env)
        process_env["GITHUB_OUTPUT"] = str(output)
        process_env["GITHUB_STEP_SUMMARY"] = str(summary)
        result = subprocess.run(
            [sys.executable, str(SCRIPT), f"--{checkpoint}", commit or self.admitted],
            env=process_env,
            text=True,
            capture_output=True,
            timeout=10,
        )
        return result, output.read_text(encoding="utf-8"), summary.read_text(encoding="utf-8")

    def test_early_current_candidate_waits_exactly_once_and_keeps_admitted_sha(self):
        waits = []
        eligible, current = freshness.decide(
            "early", self.admitted, self.env(), sleeper=waits.append
        )

        self.assertTrue(eligible)
        self.assertEqual(current, self.admitted)
        self.assertEqual(waits, [60])
        self.assertEqual(len(self.api.requests), 1)
        self.assertEqual(self.api.requests[0]["path"], "/repos/owner/repo/git/ref/heads/main")

    def test_main_advance_during_quiet_window_is_a_successful_early_skip(self):
        waits = []

        def advance_during_wait(seconds):
            waits.append(seconds)
            self.api.sha = self.new_main

        eligible, current = freshness.decide(
            "early", self.admitted, self.env(), sleeper=advance_during_wait
        )

        self.assertFalse(eligible)
        self.assertEqual(current, self.new_main)
        self.assertEqual(waits, [60])
        self.assertEqual(self.env()["GITHUB_SHA"], self.admitted)

    def test_late_supersession_skips_without_waiting_or_polling(self):
        self.api.sha = self.new_main
        waits = []

        eligible, current = freshness.decide(
            "late", self.admitted, self.env(), sleeper=waits.append
        )

        self.assertFalse(eligible)
        self.assertEqual(current, self.new_main)
        self.assertEqual(waits, [])
        self.assertEqual(len(self.api.requests), 1)

    def test_failed_jobs_only_rerun_rechecks_main_after_earlier_eligibility(self):
        waits = []
        early_eligible, _ = freshness.decide(
            "early", self.admitted, self.env(), sleeper=waits.append
        )
        self.assertTrue(early_eligible)
        self.api.sha = self.new_main

        result, output, summary = self.run_cli("late")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output, "eligible=false\n")
        self.assertIn("Checkpoint: `late`", summary)
        self.assertEqual(waits, [60])
        self.assertEqual(len(self.api.requests), 2)

    def test_rerun_rechecks_saved_sha_without_admitting_new_main(self):
        waits = []
        first, first_current = freshness.decide(
            "early", self.admitted, self.env(), sleeper=waits.append
        )
        self.api.sha = self.new_main
        rerun, rerun_current = freshness.decide(
            "early", self.admitted, self.env(), sleeper=waits.append
        )

        self.assertTrue(first)
        self.assertEqual(first_current, self.admitted)
        self.assertFalse(rerun)
        self.assertEqual(rerun_current, self.new_main)
        self.assertEqual(waits, [60, 60])
        self.assertEqual(self.env()["GITHUB_SHA"], self.admitted)

    def test_branch_advance_after_final_admission_does_not_interrupt_publication(self):
        eligible, _ = freshness.decide("late", self.admitted, self.env())
        self.assertTrue(eligible)
        publisher = test_publish.ReleasePublication(
            "test_new_release_uploads_verified_assets_before_publishing_draft"
        )
        publisher.setUp()
        self.addCleanup(publisher.doCleanups)
        publisher.commit = self.admitted
        publisher.version = f"0.0.1-dev.42.g{self.admitted[:12]}"
        publisher.env.update(COMMIT=self.admitted, VERSION=publisher.version)
        publisher.write_bundle(publisher.assets / test_publish.publisher.PROVENANCE)

        self.api.sha = self.new_main
        publisher.publish()
        self.assertFalse(publisher.remote.release["draft"])
        self.assertEqual(publisher.remote.tags[publisher.version], self.admitted)
        self.assertEqual(len(self.api.requests), 1)

    def test_stable_signed_tag_on_older_main_commit_keeps_metadata_admission(self):
        gpg_home = Path(self.work.name) / "gpg"
        gpg_home.mkdir(mode=0o700)
        gpg_env = dict(os.environ, GNUPGHOME=str(gpg_home))
        subprocess.run(
            [
                "gpg", "--batch", "--passphrase", "", "--quick-generate-key",
                "Release test <release@example.invalid>", "ed25519", "sign", "0",
            ],
            env=gpg_env,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        public_keys = subprocess.check_output(
            ["gpg", "--armor", "--export"], env=gpg_env, text=True
        )
        self.git("checkout", "--detach", self.admitted)
        self.git(
            "-c", "gpg.format=openpgp",
            "-c", "user.signingkey=release@example.invalid",
            "tag", "-s", "1.2.3", "-m", "stable release",
            env=gpg_env,
        )
        previous = Path.cwd()
        os.chdir(self.repo)
        self.addCleanup(os.chdir, previous)

        admitted = release_metadata.metadata(
            "refs/tags/1.2.3", "42", self.admitted, public_keys
        )
        self.assertEqual(admitted["commit"], self.admitted)
        self.assertEqual(admitted["prerelease"], "false")

        self.api.sha = self.new_main
        waits = []
        eligible, current = freshness.decide(
            "early",
            admitted["commit"],
            self.env(ref="refs/tags/1.2.3", commit=admitted["commit"]),
            sleeper=waits.append,
        )
        self.assertTrue(eligible)
        self.assertIsNone(current)
        self.assertEqual(waits, [])
        self.assertEqual(self.api.requests, [])

        self.git("tag", "1.2.4", self.admitted)
        with self.assertRaises(subprocess.CalledProcessError):
            release_metadata.metadata(
                "refs/tags/1.2.4", "42", self.admitted, public_keys
            )

    def test_unsupported_refs_and_sha_mismatch_fail_before_wait_or_lookup(self):
        for ref in (
            "refs/heads/topic", "refs/pull/12/merge",
            "refs/tags/v1.2.3", "refs/tags/01.2.3",
        ):
            with self.subTest(ref=ref):
                waits = []
                with self.assertRaises(freshness.FreshnessError):
                    freshness.decide("early", self.admitted, self.env(ref=ref), sleeper=waits.append)
                self.assertEqual(waits, [])
        with self.assertRaisesRegex(freshness.FreshnessError, "does not match"):
            freshness.decide("late", self.admitted, self.env(commit=self.new_main))
        missing_sha = self.env()
        missing_sha.pop("GITHUB_SHA")
        with self.assertRaisesRegex(freshness.FreshnessError, "GITHUB_SHA"):
            freshness.decide("late", self.admitted, missing_sha)
        with self.assertRaisesRegex(freshness.FreshnessError, "full lowercase"):
            freshness.decide("late", "not-a-sha", self.env())
        self.assertEqual(self.api.requests, [])

    def test_missing_authentication_http_404_and_bad_responses_fail_closed(self):
        cases = (
            ("missing token", None, None, None),
            ("rejected token", "wrong-token", 401, None),
            ("missing ref", "token", 404, None),
            ("malformed JSON", "token", None, b"{"),
            ("missing ref field", "token", None,
             b'{"object":{"sha":"0000000000000000000000000000000000000000","type":"commit"}}'),
            ("missing SHA", "token", None, b'{"ref":"refs/heads/main","object":{"type":"commit"}}'),
            ("invalid SHA", "token", None,
             b'{"ref":"refs/heads/main","object":{"type":"commit","sha":"not-a-sha"}}'),
        )
        for index, (label, token, status, body) in enumerate(cases):
            with self.subTest(case=label):
                self.api.status = status
                self.api.body = body
                env = {"GH_TOKEN": token} if token else {"GH_TOKEN": ""}
                result, output, _summary = self.run_cli("late", env=env)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("eligible=", output)
                self.assertNotIn("eligible=", result.stdout)
                self.assertNotIn("token", result.stderr)
                if label == "missing token":
                    self.assertEqual(len(self.api.requests), index)
                self.api.status = None
                self.api.body = None

    def test_cli_emits_explicit_true_state_for_current_main(self):
        result, output, summary = self.run_cli("late")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "eligible=true\n")
        self.assertEqual(output, "eligible=true\n")
        self.assertEqual(summary, "")
        self.assertEqual(len(self.api.requests), 1)

    def test_cli_records_superseded_summary_and_explicit_false_state(self):
        self.api.sha = self.new_main

        result, output, summary = self.run_cli("late")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "eligible=false\n")
        self.assertEqual(output, "eligible=false\n")
        self.assertIn("Checkpoint: `late`", summary)
        self.assertIn(f"Admitted SHA: `{self.admitted}`", summary)
        self.assertIn(f"Current main SHA: `{self.new_main}`", summary)
        self.assertIn("main advanced after the admitted commit", summary)
        self.assertEqual(len(self.api.requests), 1)


if __name__ == "__main__":
    unittest.main()
