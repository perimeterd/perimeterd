#!/usr/bin/env python3
"""Admit a release ref and emit deterministic GitHub Actions metadata."""
import io
import json
import os
import re
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile

SCHEMA = 1
ARTIFACT_FILE = "release-metadata.json"
STABLE = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", re.ASCII)
DEV_VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-dev\.([1-9][0-9]*)\.g([0-9a-f]{12})", re.ASCII)


def git(*args, env=None):
    return subprocess.check_output(["git", *args], text=True, env=env).strip()


def metadata(ref, run_number, sha, public_keys):
    commit = git("rev-parse", "HEAD^{commit}")
    if commit != git("rev-parse", f"{sha}^{{commit}}"):
        raise ValueError("checkout does not match the triggering commit")
    subprocess.run(["git", "merge-base", "--is-ancestor", commit, "refs/remotes/origin/main"], check=True)
    if ref.startswith("refs/tags/"):
        version = ref.removeprefix("refs/tags/")
        if not STABLE.fullmatch(version):
            raise ValueError("stable tags must be bare MAJOR.MINOR.PATCH without leading zeroes")
        if git("rev-parse", f"refs/tags/{version}^{{commit}}") != commit:
            raise ValueError("tag does not point to the triggering commit")
        if not public_keys.strip():
            raise ValueError("RELEASE_SIGNING_PUBLIC_KEYS must contain trusted OpenPGP release public keys")
        # An isolated keyring prevents any runner-installed key from authorizing a release.
        with tempfile.TemporaryDirectory(prefix="perimeterd-release-gpg-") as home:
            env = dict(os.environ, GNUPGHOME=home)
            with open(os.path.join(home, "gpg.conf"), "w", encoding="utf-8") as config:
                config.write("no-auto-key-retrieve\n")
            subprocess.run(["gpg", "--batch", "--import"], input=public_keys, text=True, env=env, check=True)
            subprocess.run(["git", "-c", "gpg.format=openpgp", "-c", "gpg.program=gpg", "verify-tag", f"refs/tags/{version}"], env=env, check=True)
        prerelease = False
    elif ref == "refs/heads/main":
        if not re.fullmatch(r"[1-9][0-9]*", run_number, re.ASCII):
            raise ValueError("invalid workflow run number")
        versions = [tuple(map(int, tag.split("."))) for tag in git("tag", "--merged", commit).splitlines() if STABLE.fullmatch(tag)]
        major, minor, patch = max(versions, default=(0, 0, 0))
        version = f"{major}.{minor}.{patch + 1}-dev.{run_number}.g{commit[:12]}"
        prerelease = True
    else:
        raise ValueError("releases are restricted to stable tags and main pushes")
    return {"version": version, "prerelease": str(prerelease).lower(), "commit": commit}


def run_identity(env):
    keys = ("GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_REF", "GITHUB_SHA", "GITHUB_RUN_NUMBER")
    missing = [key for key in keys if not env.get(key)]
    if missing:
        raise ValueError(f"missing required GitHub run identity: {', '.join(missing)}")
    if not re.fullmatch(r"[^/]+/[^/]+", env["GITHUB_REPOSITORY"]):
        raise ValueError("invalid GitHub repository identity")
    if not re.fullmatch(r"[1-9][0-9]*", env["GITHUB_RUN_ID"], re.ASCII):
        raise ValueError("invalid workflow run ID")
    if not re.fullmatch(r"[1-9][0-9]*", env["GITHUB_RUN_NUMBER"], re.ASCII):
        raise ValueError("invalid workflow run number")
    return {key: env[key] for key in keys}


def validate_saved(saved, identity):
    required = set(identity) | {"schema", "version", "prerelease", "commit"}
    if not isinstance(saved, dict) or type(saved.get("schema")) is not int or saved["schema"] != SCHEMA:
        raise ValueError("persisted release metadata has an unsupported schema")
    if set(saved) != required:
        raise ValueError("persisted release metadata has unexpected or missing fields")
    for key, value in identity.items():
        if saved[key] != value:
            raise ValueError(f"persisted release metadata is bound to a different {key}")
    commit = identity["GITHUB_SHA"]
    if not re.fullmatch(r"[0-9a-f]{40,64}", commit, re.ASCII):
        raise ValueError("invalid triggering commit SHA")
    version = saved.get("version")
    prerelease = saved.get("prerelease")
    if not isinstance(version, str) or type(prerelease) is not bool:
        raise ValueError("persisted release metadata has invalid version fields")
    ref = identity["GITHUB_REF"]
    if ref.startswith("refs/tags/"):
        expected = ref.removeprefix("refs/tags/")
        if not STABLE.fullmatch(expected) or version != expected or prerelease:
            raise ValueError("persisted stable release identity does not match its tag")
    elif ref == "refs/heads/main":
        match = DEV_VERSION.fullmatch(version)
        if (not prerelease or not match or match.group(4) != identity["GITHUB_RUN_NUMBER"]
                or match.group(5) != commit[:12]):
            raise ValueError("persisted prerelease identity does not match its run")
    else:
        raise ValueError("releases are restricted to stable tags and main pushes")
    if saved.get("commit") != commit:
        raise ValueError("persisted release metadata commit does not match the triggering commit")
    return saved


def _open_url(url, token, api_origin, accept="application/vnd.github+json"):
    headers = {"Accept": accept, "X-GitHub-Api-Version": "2022-11-28"}
    if urllib.parse.urlsplit(url).netloc == api_origin:
        headers["Authorization"] = f"Bearer {token}"
    opener = urllib.request.build_opener(_NoRedirect())
    for _ in range(6):
        request = urllib.request.Request(url, headers=headers)
        try:
            response = opener.open(request, timeout=30)
        except urllib.error.HTTPError as error:
            if error.code in (301, 302, 303, 307, 308) and error.headers.get("Location"):
                location = error.headers["Location"]
                error.close()
                url = urllib.parse.urljoin(url, location)
                parsed = urllib.parse.urlsplit(url)
                if parsed.scheme != "https":
                    raise ValueError("metadata artifact download redirected to an insecure URL") from error
                headers.pop("Authorization", None)
                continue
            with error:
                detail = error.read(1024).decode("utf-8", "replace")
            raise ValueError(f"GitHub artifact API request failed (HTTP {error.code}): {detail}") from error
        with response:
            return response.read(1_048_577)
    raise ValueError("GitHub artifact download exceeded the redirect limit")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


def download_saved(identity, env):
    token = env.get("GH_TOKEN") or env.get("GITHUB_TOKEN")
    if not token:
        raise ValueError("GH_TOKEN is required to recover release metadata")
    api = env.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    parsed_api = urllib.parse.urlsplit(api)
    if parsed_api.scheme != "https" and parsed_api.hostname not in ("localhost", "127.0.0.1"):
        raise ValueError("GITHUB_API_URL must use HTTPS")
    api_origin = parsed_api.netloc
    repository = urllib.parse.quote(identity["GITHUB_REPOSITORY"], safe="/")
    endpoint = f"{api}/repos/{repository}/actions/runs/{identity['GITHUB_RUN_ID']}/artifacts"
    artifacts = []
    page = 1
    total = None
    while total is None or len(artifacts) < total:
        url = f"{endpoint}?per_page=100&page={page}"
        try:
            response = json.loads(_open_url(url, token, api_origin))
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise ValueError("GitHub returned malformed workflow artifact metadata") from error
        if not isinstance(response, dict) or not isinstance(response.get("artifacts"), list):
            raise ValueError("GitHub returned malformed workflow artifact listing")
        current_total = response.get("total_count")
        if type(current_total) is not int or current_total < 0:
            raise ValueError("GitHub returned an invalid workflow artifact count")
        if total is not None and total != current_total:
            raise ValueError("workflow artifact listing changed during pagination")
        total = current_total
        artifacts.extend(response["artifacts"])
        if len(response["artifacts"]) > 100 or (not response["artifacts"] and len(artifacts) < total):
            raise ValueError("GitHub returned an incomplete workflow artifact page")
        page += 1
    if len(artifacts) != total:
        raise ValueError("GitHub returned an incomplete workflow artifact listing")
    if any(not isinstance(item, dict) for item in artifacts):
        raise ValueError("GitHub returned malformed workflow artifact metadata")
    artifact_ids = [item.get("id") for item in artifacts]
    if (any(type(artifact_id) is not int or artifact_id < 1 for artifact_id in artifact_ids)
            or len(set(artifact_ids)) != len(artifact_ids)):
        raise ValueError("GitHub returned invalid or duplicate workflow artifact IDs")
    named = [item for item in artifacts if item.get("name") == f"release-metadata-{identity['GITHUB_RUN_ID']}"]
    if not named:
        raise ValueError("release metadata artifact is missing or expired; start a new admitted release run")
    if len(named) != 1:
        raise ValueError("release metadata artifact is ambiguous; start a new admitted release run")
    artifact = named[0]
    if type(artifact.get("expired")) is not bool:
        raise ValueError("GitHub returned invalid release metadata expiration state")
    if artifact["expired"]:
        raise ValueError("release metadata artifact has expired; start a new admitted release run")
    workflow_run = artifact.get("workflow_run")
    if isinstance(workflow_run, dict) and str(workflow_run.get("id")) != identity["GITHUB_RUN_ID"]:
        raise ValueError("release metadata artifact belongs to a different workflow run")
    artifact_id = artifact["id"]
    archive_url = f"{api}/repos/{repository}/actions/artifacts/{artifact_id}/zip"
    archive = _open_url(archive_url, token, api_origin, "application/zip")
    if len(archive) > 1_048_576:
        raise ValueError("release metadata artifact is unexpectedly large")
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
            files = [item for item in bundle.infolist() if not item.is_dir()]
            if not files or len(bundle.infolist()) != 1 or files[0].filename != ARTIFACT_FILE or files[0].file_size > 1_048_576:
                raise ValueError("release metadata artifact has unexpected contents")
            saved = json.loads(bundle.read(files[0]).decode("utf-8"))
    except (zipfile.BadZipFile, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("release metadata artifact is malformed") from error
    return validate_saved(saved, identity)


def prepare(path, env):
    identity = run_identity(env)
    attempt = env.get("GITHUB_RUN_ATTEMPT", "")
    if not re.fullmatch(r"[1-9][0-9]*", attempt, re.ASCII):
        raise ValueError("invalid workflow run attempt")
    if attempt == "1":
        admitted = metadata(identity["GITHUB_REF"], identity["GITHUB_RUN_NUMBER"],
                            identity["GITHUB_SHA"], env.get("RELEASE_SIGNING_PUBLIC_KEYS", ""))
        saved = dict(identity, schema=SCHEMA, version=admitted["version"],
                     prerelease=admitted["prerelease"] == "true", commit=admitted["commit"])
        validate_saved(saved, identity)
    else:
        saved = download_saved(identity, env)
        # Re-run all admission checks without accepting a newly computed version.
        admitted = metadata(identity["GITHUB_REF"], identity["GITHUB_RUN_NUMBER"],
                            identity["GITHUB_SHA"], env.get("RELEASE_SIGNING_PUBLIC_KEYS", ""))
        if admitted["commit"] != saved["commit"] or (admitted["prerelease"] == "true") != saved["prerelease"]:
            raise ValueError("persisted release identity no longer passes release admission")
    temporary = f"{path}.tmp"
    with open(temporary, "w", encoding="utf-8") as output:
        json.dump(saved, output, sort_keys=True, separators=(",", ":"))
        output.write("\n")
    os.replace(temporary, path)


def emit(path, env):
    identity = run_identity(env)
    with open(path, encoding="utf-8") as source:
        saved = validate_saved(json.load(source), identity)
    output_path = env.get("GITHUB_OUTPUT")
    if not output_path:
        raise ValueError("GITHUB_OUTPUT is not set")
    with open(output_path, "a", encoding="utf-8") as output:
        print(f"version={saved['version']}", file=output)
        print(f"prerelease={str(saved['prerelease']).lower()}", file=output)
        print(f"commit={saved['commit']}", file=output)


def ensure_candidate_tag(version, commit):
    if not DEV_VERSION.fullmatch(version):
        raise ValueError("only admitted prerelease candidates may create local tags")
    ref = f"refs/tags/{version}"
    existing = subprocess.run(["git", "show-ref", "--verify", "--quiet", ref], check=False)
    if existing.returncode == 0:
        target = git("rev-parse", "--verify", f"{ref}^{{commit}}")
        if target != commit:
            raise ValueError(f"candidate tag {version} resolves to {target}, not {commit}")
        return
    if existing.returncode != 1:
        raise subprocess.CalledProcessError(existing.returncode, ["git", "show-ref", "--verify", ref])
    subprocess.run(["git", "tag", version, commit], check=True)


def main():
    import sys

    if len(sys.argv) == 3 and sys.argv[1] == "--prepare":
        prepare(sys.argv[2], os.environ)
    elif len(sys.argv) == 3 and sys.argv[1] == "--emit":
        emit(sys.argv[2], os.environ)
    elif len(sys.argv) == 4 and sys.argv[1] == "--ensure-candidate-tag":
        ensure_candidate_tag(sys.argv[2], sys.argv[3])
    else:
        raise SystemExit("usage: release-metadata.py --prepare FILE | --emit FILE | --ensure-candidate-tag VERSION COMMIT")


if __name__ == "__main__":
    main()


