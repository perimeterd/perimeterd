#!/usr/bin/env python3
"""Recover and publish an immutable, provenance-verified GitHub release."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

STABLE = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", re.ASCII)
PRERELEASE = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-dev\.([1-9][0-9]*)\.g([0-9a-f]{12})", re.ASCII)
PROVENANCE = "provenance.sigstore.json"
CHECKSUMS = "checksums.txt"

PREDICATE_TYPE = "https://slsa.dev/provenance/v1"

class PublishError(ValueError):
    """The remote release cannot safely advance."""


class APIError(PublishError):
    def __init__(self, method, url, status, detail):
        self.status = status
        super().__init__(f"GitHub API {method} {url} failed (HTTP {status}): {detail}")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


class GitHubAPI:
    def __init__(self, repository, token, api_url):
        self.repository = repository
        self.token = token
        self.base = api_url.rstrip("/")
        parsed = urllib.parse.urlsplit(self.base)
        if parsed.scheme != "https" and parsed.hostname not in ("localhost", "127.0.0.1"):
            raise PublishError("GITHUB_API_URL must use HTTPS")
        self.api_origin = parsed.netloc
        self.repo_path = "/repos/" + urllib.parse.quote(repository, safe="/")
        self.opener = urllib.request.build_opener(_NoRedirect())

    def _headers(self, accept="application/vnd.github+json"):
        return {
            "Accept": accept,
            "Authorization": f"Bearer {self.token}",
            "User-Agent": "perimeterd-release-publisher",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def request(self, method, url, data=None, content_type=None, accept="application/vnd.github+json"):
        if url.startswith("/"):
            url = self.base + url
        headers = self._headers(accept)
        body = None
        if data is not None:
            if isinstance(data, (dict, list)):
                body = json.dumps(data, separators=(",", ":")).encode("utf-8")
                headers["Content-Type"] = "application/json"
            else:
                body = data
                if content_type:
                    headers["Content-Type"] = content_type
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=60) as response:
                result = response.read()
        except urllib.error.HTTPError as error:
            with error:
                detail = error.read(2048).decode("utf-8", "replace")
            raise APIError(method, url, error.code, detail) from error
        except urllib.error.URLError as error:
            raise PublishError(f"GitHub API {method} {url} failed: {error.reason}") from error
        if not result:
            return None
        try:
            return json.loads(result)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise PublishError(f"GitHub API {method} {url} returned malformed JSON") from error

    def maybe_json(self, method, path):
        try:
            return self.request(method, path)
        except APIError as error:
            if error.status == 404:
                return None
            raise

    def tag_target(self, version):
        path = f"{self.repo_path}/git/ref/tags/{urllib.parse.quote(version, safe='')}"
        ref = self.maybe_json("GET", path)
        if ref is None:
            return None
        obj = ref.get("object") if isinstance(ref, dict) else None
        seen = set()
        for _ in range(10):
            if not isinstance(obj, dict) or not isinstance(obj.get("sha"), str):
                raise PublishError(f"remote tag {version} has an invalid Git object")
            sha, kind = obj["sha"], obj.get("type")
            if sha in seen:
                raise PublishError(f"remote tag {version} contains a tag-object cycle")
            seen.add(sha)
            if kind == "commit":
                return sha
            if kind != "tag":
                raise PublishError(f"remote tag {version} does not peel to a commit")
            annotated = self.request("GET", f"{self.repo_path}/git/tags/{sha}")
            obj = annotated.get("object") if isinstance(annotated, dict) else None
        raise PublishError(f"remote tag {version} has too many nested tag objects")

    def ensure_prerelease_tag(self, version, commit):
        try:
            self.request("POST", f"{self.repo_path}/git/refs", {
                "ref": f"refs/tags/{version}",
                "sha": commit,
            })
        except APIError as error:
            # Only a concurrent creator of the same ref can be accepted.
            if error.status != 422:
                raise
            target = self.tag_target(version)
            if target is None:
                raise
            if target != commit:
                raise PublishError(
                    f"remote tag {version} resolves to {target}, not admitted commit {commit}"
                ) from error
        target = self.tag_target(version)
        if target != commit:
            raise PublishError(f"remote tag {version} does not resolve to admitted commit {commit}")


    def release_by_tag(self, version):
        matches = []
        page = 1
        while True:
            releases = self.request("GET", f"{self.repo_path}/releases?per_page=100&page={page}")
            if not isinstance(releases, list) or any(not isinstance(item, dict) for item in releases):
                raise PublishError("GitHub returned a malformed release listing")
            matches.extend(item for item in releases if item.get("tag_name") == version)
            if len(releases) < 100:
                break
            page += 1
        if len(matches) > 1:
            raise PublishError(f"ambiguous releases for tag {version}: "
                               + ", ".join(str(item.get("id")) for item in matches))
        if not matches:
            return None
        release_id = matches[0].get("id")
        if type(release_id) is not int or release_id < 1:
            raise PublishError(f"release for {version} has an invalid ID")
        release = self.request("GET", f"{self.repo_path}/releases/{release_id}")
        if (not isinstance(release, dict) or release.get("id") != release_id
                or release.get("tag_name") != version):
            raise PublishError(f"release {release_id} changed identity during lookup")
        return release

    def create_draft(self, version, commit, prerelease):
        return self.request("POST", f"{self.repo_path}/releases", {
            "tag_name": version,
            "target_commitish": commit,
            "name": version,
            "draft": True,
            "prerelease": prerelease,
            "generate_release_notes": True,
        })

    def release_assets(self, release_id):
        assets = []
        page = 1
        while True:
            path = f"{self.repo_path}/releases/{release_id}/assets?per_page=100&page={page}"
            result = self.request("GET", path)
            if not isinstance(result, list):
                raise PublishError("GitHub returned a malformed release asset listing")
            assets.extend(result)
            if len(result) < 100:
                return assets
            page += 1

    def download_asset(self, asset, destination):
        url = asset.get("url")
        if not isinstance(url, str):
            raise PublishError(f"release asset {asset.get('name', '<unknown>')} has no download URL")
        parsed = urllib.parse.urlsplit(url)
        local_http = (parsed.scheme == "http" and parsed.netloc == self.api_origin
                      and parsed.hostname in ("localhost", "127.0.0.1"))
        if parsed.netloc != self.api_origin or (parsed.scheme != "https" and not local_http):
            raise PublishError(f"release asset {asset.get('name', '<unknown>')} has an unexpected download URL")
        headers = self._headers("application/octet-stream")
        for _ in range(6):
            request = urllib.request.Request(url, headers=headers)
            try:
                response = self.opener.open(request, timeout=60)
            except urllib.error.HTTPError as error:
                if error.code in (301, 302, 303, 307, 308) and error.headers.get("Location"):
                    location = error.headers["Location"]
                    error.close()
                    url = urllib.parse.urljoin(url, location)
                    parsed = urllib.parse.urlsplit(url)
                    if parsed.scheme != "https":
                        raise PublishError("release asset redirected to an insecure URL") from error
                    if parsed.netloc != self.api_origin:
                        headers.pop("Authorization", None)
                    continue
                with error:
                    detail = error.read(2048).decode("utf-8", "replace")
                raise APIError("GET", url, error.code, detail) from error
            except urllib.error.URLError as error:
                raise PublishError(f"release asset download failed: {error.reason}") from error
            with response, open(destination, "wb") as output:
                while block := response.read(1024 * 1024):
                    output.write(block)
            return
        raise PublishError("release asset download exceeded the redirect limit")

    def upload_asset(self, release, path):
        upload_url = release.get("upload_url")
        if not isinstance(upload_url, str):
            raise PublishError("draft release has no asset upload URL")
        upload_url = upload_url.split("{", 1)[0]
        parsed = urllib.parse.urlsplit(upload_url)
        api = urllib.parse.urlsplit(self.base)
        allowed_origins = {(api.scheme, api.netloc)}
        if api.scheme == "https" and api.netloc == "api.github.com":
            allowed_origins.add(("https", "uploads.github.com"))
        if ((parsed.scheme, parsed.netloc) not in allowed_origins
                or parsed.username is not None or parsed.password is not None):
            raise PublishError("GitHub returned an unexpected asset upload URL")
        query = urllib.parse.urlencode({"name": path.name})
        url = urllib.parse.urlunsplit(parsed._replace(query=query))
        result = self.request("POST", url, path.read_bytes(), "application/octet-stream")
        if not isinstance(result, dict) or result.get("name") != path.name:
            raise PublishError(f"GitHub did not confirm upload of {path.name}")
        return result

    def publish(self, release, latest):
        return self.request("PATCH", f"{self.repo_path}/releases/{release['id']}", {
            "draft": False,
            "make_latest": "true" if latest else "false",
        })


def file_sha256(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def local_assets(directory):
    directory = Path(directory)
    if not directory.is_dir() or directory.is_symlink():
        raise PublishError("release asset directory is missing or unsafe")
    entries = list(directory.iterdir())
    if any(item.is_symlink() or not item.is_file() for item in entries):
        raise PublishError("release asset directory contains a non-regular file")
    files = {item.name: item for item in entries}
    if CHECKSUMS not in files or PROVENANCE not in files:
        raise PublishError(f"release assets must include {CHECKSUMS} and {PROVENANCE}")
    manifest = {}
    for line in files[CHECKSUMS].read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([a-f0-9]{64})  ([A-Za-z0-9_.+~-]+)", line, re.ASCII)
        if not match:
            raise PublishError("invalid release checksum entry")
        checksum, name = match.groups()
        if name in manifest:
            raise PublishError(f"duplicate release checksum entry: {name}")
        manifest[name] = checksum
    expected_names = set(files) - {CHECKSUMS, PROVENANCE}
    if set(manifest) != expected_names:
        missing = sorted(expected_names - set(manifest))
        extra = sorted(set(manifest) - expected_names)
        details = []
        if missing:
            details.append("not covered by checksums: " + ", ".join(missing))
        if extra:
            details.append("missing from release directory: " + ", ".join(extra))
        raise PublishError("release checksum inventory mismatch (" + "; ".join(details) + ")")
    for name, expected in manifest.items():
        if file_sha256(files[name]) != expected:
            raise PublishError(f"release artifact checksum mismatch: {name}")
    return files


def verify_provenance(bundle, subjects, repository, commit, ref):
    signer = f"{repository}/.github/workflows/release.yml"
    for name in sorted(subjects):
        subprocess.run([
            "gh", "attestation", "verify", str(subjects[name]),
            "--repo", repository,
            "--bundle", str(bundle),
            "--signer-workflow", signer,
            "--predicate-type", PREDICATE_TYPE,
            "--source-digest", commit,
            "--source-ref", ref,
            "--format", "json",
        ], check=True)


def validate_identity(release, version, prerelease):
    if not isinstance(release, dict):
        raise PublishError("GitHub returned a malformed release")
    if release.get("tag_name") != version or release.get("name") != version:
        raise PublishError(f"release identity conflict for {version}: tag or title does not match")
    if release.get("prerelease") is not prerelease:
        raise PublishError(f"release identity conflict for {version}: wrong stable/prerelease channel")
    if type(release.get("draft")) is not bool or type(release.get("id")) is not int or release["id"] < 1:
        raise PublishError(f"release identity conflict for {version}: missing draft state or ID")
    return release


def verify_remote_assets(api, release, expected, subjects, repository, commit, ref, verifier, temporary):
    remote = api.release_assets(release["id"])
    by_name = {}
    for asset in remote:
        name = asset.get("name") if isinstance(asset, dict) else None
        if not isinstance(name, str) or name in by_name:
            raise PublishError("release contains duplicate or invalid asset names")
        asset_id = asset.get("id")
        if type(asset_id) is not int or asset_id < 1:
            raise PublishError(f"release asset {name} has an invalid ID")
        by_name[name] = asset
    unexpected = sorted(set(by_name) - set(expected))
    if unexpected:
        raise PublishError("release contains unexpected assets: " + ", ".join(unexpected))
    for name, asset in by_name.items():
        if name == PROVENANCE:
            continue
        if asset.get("state") not in (None, "uploaded"):
            raise PublishError(f"release asset {name} is not fully uploaded")
        remote_path = Path(temporary) / f"remote-{asset['id']}-{name}"
        api.download_asset(asset, remote_path)
        if file_sha256(remote_path) != file_sha256(expected[name]):
            raise PublishError(f"release asset bytes conflict with the tested candidate: {name}")
    if PROVENANCE in by_name:
        asset = by_name[PROVENANCE]
        if asset.get("state") not in (None, "uploaded"):
            raise PublishError("release provenance asset is not fully uploaded")
        bundle = Path(temporary) / "existing-provenance.sigstore.json"
        api.download_asset(asset, bundle)
        verifier(bundle, subjects, repository, commit, ref)
    return set(by_name)


def publish(directory, env, verifier=verify_provenance):
    repository = env.get("GITHUB_REPOSITORY", "")
    token = env.get("GH_TOKEN", "")
    version = env.get("VERSION", "")
    commit = env.get("COMMIT", "")
    ref = env.get("GITHUB_REF", "")
    channel = env.get("PRERELEASE", "")
    if channel not in ("true", "false"):
        raise PublishError("PRERELEASE must be true or false")
    prerelease = channel == "true"
    if not re.fullmatch(r"[^/]+/[^/]+", repository) or not token:
        raise PublishError("GITHUB_REPOSITORY and GH_TOKEN are required")
    if not re.fullmatch(r"[0-9a-f]{40,64}", commit, re.ASCII):
        raise PublishError("invalid admitted release commit")
    if prerelease:
        match = PRERELEASE.fullmatch(version)
        if not match or match.group(5) != commit[:12]:
            raise PublishError("release version does not match the admitted prerelease commit")
    elif not STABLE.fullmatch(version):
        raise PublishError("release version does not match the admitted stable channel")
    if ref != ("refs/heads/main" if prerelease else f"refs/tags/{version}"):
        raise PublishError("release ref does not match the admitted version and channel")
    api = GitHubAPI(repository, token, env.get("GITHUB_API_URL", "https://api.github.com"))
    expected = local_assets(directory)
    subjects = {name: path for name, path in expected.items() if name != PROVENANCE}
    bundle = expected[PROVENANCE]
    actual_tag = api.tag_target(version)
    if actual_tag is not None and actual_tag != commit:
        raise PublishError(f"remote tag {version} resolves to {actual_tag}, not admitted commit {commit}")
    if not prerelease and actual_tag is None:
        raise PublishError(f"stable release requires its existing verified tag {version}")
    release = api.release_by_tag(version)
    if release is None:
        verifier(bundle, subjects, repository, commit, ref)
        release = api.create_draft(version, commit, prerelease)
        validate_identity(release, version, prerelease)
        if not release["draft"]:
            raise PublishError("GitHub did not create the release as a draft")
    else:
        validate_identity(release, version, prerelease)
    if actual_tag is None and (not release["draft"]
                               or release.get("target_commitish") != commit):
        raise PublishError(f"release {version} has no matching remote tag or pending target commit")
    with tempfile.TemporaryDirectory(prefix="perimeterd-release-") as temporary:
        present = verify_remote_assets(api, release, expected, subjects, repository,
                                       commit, ref, verifier, temporary)
        missing = set(expected) - present
        if release["draft"]:
            if PROVENANCE not in present:
                verifier(bundle, subjects, repository, commit, ref)
            if actual_tag is None:
                api.ensure_prerelease_tag(version, commit)
            elif api.tag_target(version) != commit:
                raise PublishError(f"remote tag {version} changed after release lookup")
            for name in sorted(missing):
                api.upload_asset(release, expected[name])
            present = verify_remote_assets(api, release, expected, subjects, repository,
                                           commit, ref, verifier, temporary)
            missing = set(expected) - present
            if missing:
                raise PublishError("draft is still missing release assets: " + ", ".join(sorted(missing)))
            if api.tag_target(version) != commit:
                raise PublishError(f"remote tag {version} changed before publication")
            released = api.publish(release, latest=not prerelease)
            validate_identity(released, version, prerelease)
            if released["draft"]:
                raise PublishError("GitHub did not publish the complete release")
            release = released
            final = api.release_by_tag(version)
            if final is None:
                raise PublishError("published release disappeared during verification")
            validate_identity(final, version, prerelease)
            if final["draft"]:
                raise PublishError("GitHub release remains a draft after publication")
            if api.tag_target(version) != commit:
                raise PublishError(f"remote tag {version} changed after publication")
            present = verify_remote_assets(api, final, expected, subjects, repository,
                                           commit, ref, verifier, temporary)
            missing = set(expected) - present
            if missing:
                raise PublishError("published release is incomplete: " + ", ".join(sorted(missing)))
        else:
            if missing:
                raise PublishError("published release is missing assets: " + ", ".join(sorted(missing)))
            if api.tag_target(version) != commit:
                raise PublishError(f"remote tag {version} changed during verification")
    return f"verified {'prerelease' if prerelease else 'stable release'} {version}"


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: release-publish.py RELEASE_ASSET_DIRECTORY")
    try:
        print(publish(sys.argv[1], os.environ))
    except (APIError, PublishError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from error


if __name__ == "__main__":
    main()
