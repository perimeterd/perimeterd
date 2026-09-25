#!/usr/bin/env python3
"""Behavioral release recovery tests against an isolated GitHub API boundary."""
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
from pathlib import Path
import re
import tempfile
import threading
import unittest
import urllib.parse

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/release-publish.py"
spec = importlib.util.spec_from_file_location("release_publish", SCRIPT)
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)


class FakeGitHub:
    def __init__(self):
        self.repository = "owner/repo"
        self.release = None
        self.tags = {}
        self.assets = {}
        self.other_releases = []
        self.concurrent_tag_target = None
        self.mutations = []
        self.errors = {}
        self.upload_failure = None
        self.next_asset_id = 1
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def send_json(self, status, value):
                body = json.dumps(value).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.headers.get("Authorization") != "Bearer token":
                    self.send_error(401)
                    return
                parsed = urllib.parse.urlsplit(self.path)
                path = parsed.path
                if path in outer.errors:
                    self.send_error(outer.errors[path])
                    return
                prefix = "/repos/owner/repo"
                if path.startswith(prefix + "/git/ref/tags/"):
                    version = urllib.parse.unquote(path.removeprefix(prefix + "/git/ref/tags/"))
                    target = outer.tags.get(version)
                    if target is None:
                        self.send_error(404)
                    else:
                        self.send_json(200, {"object": {"sha": target, "type": "commit"}})
                elif path == prefix + "/releases":
                    page = int(urllib.parse.parse_qs(parsed.query).get("page", ["1"])[0])
                    releases = outer.other_releases + ([outer.release] if outer.release else [])
                    self.send_json(200, releases[(page - 1) * 100:page * 100])
                elif path.startswith(prefix + "/releases/tags/"):
                    version = urllib.parse.unquote(path.removeprefix(prefix + "/releases/tags/"))
                    if outer.release is None or outer.release["draft"] or outer.release["tag_name"] != version:
                        self.send_error(404)
                    else:
                        self.send_json(200, outer.release)
                elif re.fullmatch(prefix + r"/releases/\d+", path):
                    release_id = int(path.rsplit("/", 1)[1])
                    release = next((item for item in outer.other_releases + ([outer.release] if outer.release else [])
                                    if item["id"] == release_id), None)
                    if release is None:
                        self.send_error(404)
                    else:
                        self.send_json(200, release)
                elif re.fullmatch(prefix + r"/releases/\d+/assets", path):
                    self.send_json(200, [
                        {key: value for key, value in asset.items() if key != "data"}
                        for asset in outer.assets.values()
                    ])
                elif re.fullmatch(prefix + r"/releases/assets/\d+", path):
                    asset_id = int(path.rsplit("/", 1)[1])
                    asset = next((item for item in outer.assets.values() if item["id"] == asset_id), None)
                    if asset is None:
                        self.send_error(404)
                    else:
                        body = asset["data"]
                        self.send_response(200)
                        self.send_header("Content-Type", "application/octet-stream")
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                else:
                    self.send_error(404)

            def do_POST(self):
                if self.headers.get("Authorization") != "Bearer token":
                    self.send_error(401)
                    return
                parsed = urllib.parse.urlsplit(self.path)
                if parsed.path in outer.errors:
                    self.send_error(outer.errors[parsed.path])
                    return
                prefix = "/repos/owner/repo"
                size = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(size)
                if parsed.path == prefix + "/git/refs":
                    request = json.loads(body)
                    version = request["ref"].removeprefix("refs/tags/")
                    if outer.concurrent_tag_target is not None:
                        outer.tags[version] = outer.concurrent_tag_target
                    if request["ref"] != f"refs/tags/{version}" or version in outer.tags:
                        self.send_error(422)
                        return
                    outer.tags[version] = request["sha"]
                    outer.mutations.append(("tag", version))
                    self.send_json(201, {"ref": request["ref"], "object": {"sha": request["sha"], "type": "commit"}})
                elif parsed.path == prefix + "/releases":
                    request = json.loads(body)
                    release_id = 7
                    outer.release = {
                        "id": release_id,
                        "tag_name": request["tag_name"],
                        "name": request["name"],
                        "draft": request["draft"],
                        "prerelease": request["prerelease"],
                        "target_commitish": request["target_commitish"],
                        "upload_url": f"http://127.0.0.1:{outer.server.server_port}{prefix}/releases/{release_id}/assets{{?name,label}}",
                    }
                    # GitHub leaves a new draft's tag pending until publication.
                    outer.mutations.append(("create", request["tag_name"]))
                    self.send_json(201, outer.release)
                elif re.fullmatch(prefix + r"/releases/\d+/assets", parsed.path):
                    name = urllib.parse.parse_qs(parsed.query).get("name", [""])[0]
                    if name == outer.upload_failure:
                        self.send_error(500)
                        return
                    if not name or name in outer.assets:
                        self.send_error(422)
                        return
                    asset_id = outer.next_asset_id
                    outer.next_asset_id += 1
                    asset = {
                        "id": asset_id,
                        "name": name,
                        "size": len(body),
                        "state": "uploaded",
                        "url": f"http://127.0.0.1:{outer.server.server_port}{prefix}/releases/assets/{asset_id}",
                        "data": body,
                    }
                    outer.assets[name] = asset
                    outer.mutations.append(("upload", name))
                    self.send_json(201, {key: value for key, value in asset.items() if key != "data"})
                else:
                    self.send_error(404)

            def do_PATCH(self):
                if self.headers.get("Authorization") != "Bearer token":
                    self.send_error(401)
                    return
                parsed = urllib.parse.urlsplit(self.path)
                if not re.fullmatch(r"/repos/owner/repo/releases/\d+", parsed.path) or outer.release is None:
                    self.send_error(404)
                    return
                request = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
                if outer.release["tag_name"] not in outer.tags:
                    outer.tags[outer.release["tag_name"]] = outer.release["target_commitish"]
                outer.release.update(request)
                outer.mutations.append(("publish", outer.release["tag_name"], request["make_latest"]))
                self.send_json(200, outer.release)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.server = self
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()

    def addCleanup(self, test):
        test.addCleanup(self.close)

    @property
    def api_url(self):
        return f"http://127.0.0.1:{self.server.server_port}"

    def draft(self, version, commit, prerelease):
        self.release = {
            "id": 7,
            "tag_name": version,
            "name": version,
            "draft": True,
            "prerelease": prerelease,
            "target_commitish": commit,
            "upload_url": f"{self.api_url}/repos/owner/repo/releases/7/assets{{?name,label}}",
        }
        # Existing drafts may still have pending tags.

    def add_asset(self, name, data):
        asset_id = self.next_asset_id
        self.next_asset_id += 1
        self.assets[name] = {
            "id": asset_id,
            "name": name,
            "size": len(data),
            "state": "uploaded",
            "url": f"{self.api_url}/repos/owner/repo/releases/assets/{asset_id}",
            "data": data,
        }


class ReleasePublication(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.assets = self.root / "assets"
        self.assets.mkdir()
        self.commit = "a" * 40
        self.ref = "refs/heads/main"
        self.version = "0.0.1-dev.42.g" + self.commit[:12]
        self.repository = "owner/repo"
        self.write_subjects()
        self.write_bundle(self.assets / publisher.PROVENANCE, issued="candidate")
        self.remote = FakeGitHub()
        self.remote.addCleanup(self)
        self.env = {
            "GITHUB_API_URL": self.remote.api_url,
            "GITHUB_REPOSITORY": self.repository,
            "GH_TOKEN": "token",
            "VERSION": self.version,
            "COMMIT": self.commit,
            "GITHUB_REF": self.ref,
            "PRERELEASE": "true",
        }

    def write_subjects(self):
        package = self.assets / "perimeterd_1_amd64.deb"
        package.write_bytes(b"tested package bytes\n")
        digest = hashlib.sha256(package.read_bytes()).hexdigest()
        (self.assets / publisher.CHECKSUMS).write_text(f"{digest}  {package.name}\n", encoding="utf-8")

    def subject_digests(self):
        return {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in self.assets.iterdir()
            if path.name != publisher.PROVENANCE
        }

    def write_bundle(self, path, issued="candidate", subjects=None):
        body = {
            "repository": self.repository,
            "workflow": f"{self.repository}/.github/workflows/release.yml",
            "predicate_type": publisher.PREDICATE_TYPE,
            "commit": self.commit,
            "ref": self.ref,
            "issued": issued,
            "subjects": subjects if subjects is not None else self.subject_digests(),
        }
        path.write_text(json.dumps(body, sort_keys=True), encoding="utf-8")
        return path.read_bytes()

    def verify_bundle(self, bundle, subjects, repository, commit, ref):
        data = json.loads(Path(bundle).read_text(encoding="utf-8"))
        expected = {
            name: hashlib.sha256(path.read_bytes()).hexdigest()
            for name, path in subjects.items()
        }
        if (data.get("repository") != repository
                or data.get("workflow") != f"{repository}/.github/workflows/release.yml"
                or data.get("predicate_type") != publisher.PREDICATE_TYPE
                or data.get("commit") != commit
                or data.get("ref") != ref
                or data.get("subjects") != expected):
            raise publisher.PublishError("test attestation identity or subjects do not match")

    def publish(self):
        return publisher.publish(self.assets, self.env, verifier=self.verify_bundle)

    def test_new_release_uploads_verified_assets_before_publishing_draft(self):
        result = self.publish()
        self.assertEqual(result, f"verified prerelease {self.version}")
        self.assertFalse(self.remote.release["draft"])
        self.assertEqual(self.remote.release["make_latest"], "false")
        self.assertEqual(set(self.remote.assets), {path.name for path in self.assets.iterdir()})
        actions = [entry[0] for entry in self.remote.mutations]
        self.assertEqual(actions[0], "create")
        self.assertEqual(actions[-1], "publish")
        self.assertNotIn("publish", actions[:-1])
        self.assertEqual(self.remote.tags[self.version], self.commit)
        self.assertIn(("tag", self.version), self.remote.mutations)
        for name, asset in self.remote.assets.items():
            self.assertEqual(asset["data"], (self.assets / name).read_bytes())

    def test_partial_draft_resumes_missing_assets_without_replacing_existing(self):
        self.remote.draft(self.version, self.commit, True)
        existing_name = "perimeterd_1_amd64.deb"
        existing_data = (self.assets / existing_name).read_bytes()
        self.remote.add_asset(existing_name, existing_data)
        old_id = self.remote.assets[existing_name]["id"]
        self.assertNotIn(self.version, self.remote.tags)
        self.publish()
        self.assertEqual(self.remote.assets[existing_name]["id"], old_id)
        self.assertNotIn(("upload", existing_name), self.remote.mutations)
        self.assertNotIn(("create", self.version), self.remote.mutations)
        self.assertFalse(self.remote.release["draft"])

    def test_complete_matching_draft_publishes_without_reuploading(self):
        self.remote.draft(self.version, self.commit, True)
        for path in self.assets.iterdir():
            self.remote.add_asset(path.name, path.read_bytes())
        self.publish()
        self.assertEqual([entry[0] for entry in self.remote.mutations], ["tag", "publish"])
        self.assertFalse(self.remote.release["draft"])

    def test_failed_upload_leaves_draft_and_resume_finishes_missing_assets(self):
        self.remote.upload_failure = "perimeterd_1_amd64.deb"
        with self.assertRaisesRegex(publisher.APIError, "HTTP 500"):
            self.publish()
        self.assertTrue(self.remote.release["draft"])
        self.assertNotIn("publish", [entry[0] for entry in self.remote.mutations])
        existing = self.remote.assets["checksums.txt"]["id"]
        self.remote.upload_failure = None
        self.publish()
        self.assertEqual(self.remote.assets["checksums.txt"]["id"], existing)
        self.assertFalse(self.remote.release["draft"])

    def test_published_matching_release_is_verified_noop_and_keeps_old_bundle(self):
        self.remote.draft(self.version, self.commit, True)
        self.remote.tags[self.version] = self.commit
        self.remote.release.update({"draft": False, "make_latest": "false"})
        for path in self.assets.iterdir():
            data = path.read_bytes()
            if path.name == publisher.PROVENANCE:
                data = self.write_bundle(self.root / "older-provenance.json", issued="older timestamp")
            self.remote.add_asset(path.name, data)
        old_bundle = self.remote.assets[publisher.PROVENANCE]["data"]
        self.assertEqual(self.publish(), f"verified prerelease {self.version}")
        self.assertEqual(self.remote.mutations, [])
        self.assertEqual(self.remote.release["make_latest"], "false")
        self.assertEqual(self.remote.assets[publisher.PROVENANCE]["data"], old_bundle)


    def test_resolved_tag_target_is_used_instead_of_branch_target_commitish(self):
        self.remote.draft(self.version, self.commit, True)
        self.remote.tags[self.version] = self.commit
        self.remote.release["target_commitish"] = "main"
        for path in self.assets.iterdir():
            self.remote.add_asset(path.name, path.read_bytes())
        self.publish()
        self.assertFalse(self.remote.release["draft"])

    def test_wrong_remote_tag_target_fails_without_mutation(self):
        wrong = "b" * 40
        self.remote.tags[self.version] = wrong
        with self.assertRaisesRegex(publisher.PublishError, "not admitted commit"):
            self.publish()
        self.assertEqual(self.remote.tags[self.version], wrong)
        self.assertEqual(self.remote.mutations, [])

    def test_conflicting_draft_bytes_fail_without_upload_or_publication(self):
        self.remote.draft(self.version, self.commit, True)
        self.remote.add_asset("perimeterd_1_amd64.deb", b"different package bytes")
        with self.assertRaisesRegex(publisher.PublishError, "bytes conflict"):
            self.publish()
        self.assertEqual(self.remote.mutations, [])
        self.assertTrue(self.remote.release["draft"])
        self.assertEqual(self.remote.assets["perimeterd_1_amd64.deb"]["data"], b"different package bytes")

    def test_published_conflict_or_incomplete_inventory_is_never_repaired(self):
        self.remote.draft(self.version, self.commit, True)
        self.remote.tags[self.version] = self.commit
        self.remote.release.update({"draft": False, "make_latest": "false"})
        for path in self.assets.iterdir():
            data = path.read_bytes()
            if path.name == "perimeterd_1_amd64.deb":
                data = b"different public bytes"
            self.remote.add_asset(path.name, data)
        with self.assertRaisesRegex(publisher.PublishError, "bytes conflict"):
            self.publish()
        self.assertEqual(self.remote.mutations, [])
        self.remote.assets["perimeterd_1_amd64.deb"]["data"] = (
            self.assets / "perimeterd_1_amd64.deb"
        ).read_bytes()
        self.remote.assets.pop("checksums.txt")
        self.remote.mutations.clear()
        with self.assertRaisesRegex(publisher.PublishError, "missing assets"):
            self.publish()
        self.assertEqual(self.remote.mutations, [])

    def test_channel_conflict_leaves_existing_draft_untouched(self):
        self.remote.draft(self.version, self.commit, False)
        with self.assertRaisesRegex(publisher.PublishError, "wrong stable/prerelease channel"):
            self.publish()
        self.assertEqual(self.remote.mutations, [])
        self.assertTrue(self.remote.release["draft"])

    def test_unexpected_draft_asset_fails_without_mutation(self):
        self.remote.draft(self.version, self.commit, True)
        self.remote.add_asset("unexpected.txt", b"unexpected")
        with self.assertRaisesRegex(publisher.PublishError, "unexpected assets"):
            self.publish()
        self.assertEqual(self.remote.mutations, [])
        self.assertTrue(self.remote.release["draft"])

    def test_existing_provenance_with_wrong_subject_digests_fails_closed(self):
        self.remote.draft(self.version, self.commit, True)
        wrong = {"perimeterd_1_amd64.deb": "0" * 64, "checksums.txt": "0" * 64}
        self.write_bundle(self.root / "bad-provenance.json", issued="wrong", subjects=wrong)
        for path in self.assets.iterdir():
            data = (self.root / "bad-provenance.json").read_bytes() if path.name == publisher.PROVENANCE else path.read_bytes()
            self.remote.add_asset(path.name, data)
        with self.assertRaisesRegex(publisher.PublishError, "identity or subjects"):
            self.publish()
        self.assertEqual(self.remote.mutations, [])
        self.assertTrue(self.remote.release["draft"])

    def test_pending_draft_is_found_on_a_later_release_page(self):
        self.remote.other_releases = [
            {"id": 100 + number, "tag_name": f"old-{number}"}
            for number in range(100)
        ]
        self.remote.draft(self.version, self.commit, True)
        existing_name = "perimeterd_1_amd64.deb"
        self.remote.add_asset(existing_name, (self.assets / existing_name).read_bytes())
        old_id = self.remote.assets[existing_name]["id"]
        self.publish()
        self.assertFalse(self.remote.release["draft"])
        self.assertEqual(self.remote.assets[existing_name]["id"], old_id)
        self.assertNotIn(("create", self.version), self.remote.mutations)

    def test_ambiguous_release_listing_fails_without_mutation(self):
        self.remote.draft(self.version, self.commit, True)
        self.remote.other_releases.append({"id": 8, "tag_name": self.version})
        with self.assertRaisesRegex(publisher.PublishError, "ambiguous releases"):
            self.publish()
        self.assertEqual(self.remote.mutations, [])
        self.assertNotIn(self.version, self.remote.tags)

    def test_pending_draft_at_different_target_fails_before_tag_creation(self):
        self.remote.draft(self.version, "b" * 40, True)
        with self.assertRaisesRegex(publisher.PublishError, "pending target commit"):
            self.publish()
        self.assertTrue(self.remote.release["draft"])
        self.assertNotIn(self.version, self.remote.tags)
        self.assertEqual(self.remote.mutations, [])

    def test_competing_matching_tag_creation_is_reused(self):
        self.remote.concurrent_tag_target = self.commit
        self.publish()
        self.assertFalse(self.remote.release["draft"])
        self.assertEqual(self.remote.tags[self.version], self.commit)
        self.assertNotIn(("tag", self.version), self.remote.mutations)

    def test_competing_wrong_tag_creation_fails_without_upload(self):
        self.remote.concurrent_tag_target = "b" * 40
        with self.assertRaisesRegex(publisher.PublishError, "not admitted commit"):
            self.publish()
        self.assertTrue(self.remote.release["draft"])
        self.assertEqual(self.remote.tags[self.version], "b" * 40)
        self.assertEqual(self.remote.assets, {})
        self.assertEqual(self.remote.mutations, [("create", self.version)])

    def test_tag_creation_api_error_leaves_draft_pending_and_can_resume(self):
        path = "/repos/owner/repo/git/refs"
        self.remote.errors[path] = 500
        with self.assertRaisesRegex(publisher.APIError, "HTTP 500"):
            self.publish()
        self.assertTrue(self.remote.release["draft"])
        self.assertEqual(self.remote.assets, {})
        self.assertNotIn(self.version, self.remote.tags)
        self.remote.errors.pop(path)
        self.publish()
        self.assertFalse(self.remote.release["draft"])
        self.assertNotIn(("create", self.version), self.remote.mutations[1:])

    def test_published_release_without_ref_is_never_repaired(self):
        self.remote.draft(self.version, self.commit, True)
        self.remote.release["draft"] = False
        with self.assertRaisesRegex(publisher.PublishError, "no matching remote tag"):
            self.publish()
        self.assertNotIn(self.version, self.remote.tags)
        self.assertEqual(self.remote.mutations, [])

    def test_api_failure_is_not_treated_as_a_missing_release(self):
        path = "/repos/owner/repo/releases"
        self.remote.errors[path] = 500
        with self.assertRaisesRegex(publisher.APIError, "HTTP 500"):
            self.publish()
        self.assertEqual(self.remote.mutations, [])

    def test_stable_publication_requires_matching_existing_tag_and_promotes_once(self):
        self.ref = "refs/tags/1.2.3"
        self.env.update({"VERSION": "1.2.3", "PRERELEASE": "false", "GITHUB_REF": self.ref})
        self.remote.tags["1.2.3"] = self.commit
        self.write_bundle(self.assets / publisher.PROVENANCE, issued="stable")
        self.publish()
        self.assertFalse(self.remote.release["prerelease"])
        self.assertEqual(self.remote.release["make_latest"], "true")


    def test_stable_release_is_not_created_without_its_existing_tag(self):
        self.ref = "refs/tags/1.2.3"
        self.env.update({"VERSION": "1.2.3", "PRERELEASE": "false", "GITHUB_REF": self.ref})
        with self.assertRaisesRegex(publisher.PublishError, "existing verified tag"):
            self.publish()
        self.assertIsNone(self.remote.release)
        self.assertNotIn("1.2.3", self.remote.tags)
        self.assertEqual(self.remote.mutations, [])

    def test_local_checksum_mismatch_fails_before_remote_mutation(self):
        (self.assets / "perimeterd_1_amd64.deb").write_bytes(b"tampered bytes")
        with self.assertRaisesRegex(publisher.PublishError, "checksum mismatch"):
            self.publish()
        self.assertEqual(self.remote.mutations, [])


if __name__ == "__main__":
    unittest.main()
