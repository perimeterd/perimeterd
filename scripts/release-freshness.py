#!/usr/bin/env python3
"""Gate release work on the current main commit without changing admitted identity."""
import http.client
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

STABLE = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", re.ASCII)
COMMIT_SHA = re.compile(r"[0-9a-f]{40}", re.ASCII)
QUIET_WINDOW_SECONDS = 60
API_TIMEOUT_SECONDS = 15
MAX_RESPONSE_BYTES = 1024 * 1024


class FreshnessError(ValueError):
    """The release candidate's freshness could not be safely established."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


def _commit_sha(value, name):
    if not isinstance(value, str) or not COMMIT_SHA.fullmatch(value):
        raise FreshnessError(f"{name} must be a full lowercase Git commit SHA")
    return value


def _release_ref(env):
    ref = env.get("GITHUB_REF", "")
    if ref == "refs/heads/main":
        return "main"
    if ref.startswith("refs/tags/") and STABLE.fullmatch(ref.removeprefix("refs/tags/")):
        return "stable"
    raise FreshnessError("releases are restricted to main pushes and canonical stable tags")


class GitHubAPI:
    def __init__(self, env):
        self.token = env.get("GH_TOKEN") or env.get("GITHUB_TOKEN")
        if not self.token:
            raise FreshnessError("GH_TOKEN or GITHUB_TOKEN is required for a main freshness lookup")

        repository = env.get("GITHUB_REPOSITORY", "")
        parts = repository.split("/")
        if len(parts) != 2 or not all(parts) or any(part in (".", "..") for part in parts):
            raise FreshnessError("GITHUB_REPOSITORY must be owner/repository")

        raw_base = env.get("GITHUB_API_URL", "https://api.github.com")
        try:
            parsed = urllib.parse.urlsplit(raw_base)
            hostname = parsed.hostname
            # Accessing .port also validates malformed port values.
            parsed.port
        except ValueError as error:
            raise FreshnessError("GITHUB_API_URL is invalid") from error
        if (not hostname or parsed.username or parsed.password or parsed.query or parsed.fragment
                or (parsed.scheme != "https" and not (
                    parsed.scheme == "http" and hostname.lower() in ("localhost", "127.0.0.1")
                ))):
            raise FreshnessError("GITHUB_API_URL must use HTTPS (HTTP is allowed only for loopback tests)")

        base_path = parsed.path.rstrip("/")
        self.base = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, base_path, "", ""))
        owner, name = parts
        self.ref_url = (
            f"{self.base}/repos/{urllib.parse.quote(owner, safe='')}/"
            f"{urllib.parse.quote(name, safe='')}/git/ref/heads/main"
        )
        self.opener = urllib.request.build_opener(_NoRedirect())

    def current_main_sha(self):
        request = urllib.request.Request(
            self.ref_url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "User-Agent": "perimeterd-release-freshness",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            method="GET",
        )
        try:
            with self.opener.open(request, timeout=API_TIMEOUT_SECONDS) as response:
                body = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as error:
            error.close()
            raise FreshnessError(f"GitHub main ref lookup failed (HTTP {error.code})") from None
        except (http.client.HTTPException, urllib.error.URLError, TimeoutError, OSError):
            raise FreshnessError("GitHub main ref lookup failed") from None

        if len(body) > MAX_RESPONSE_BYTES:
            raise FreshnessError("GitHub main ref lookup returned an oversized response")
        try:
            result = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise FreshnessError("GitHub main ref lookup returned malformed JSON") from None

        if not isinstance(result, dict) or result.get("ref") != "refs/heads/main":
            raise FreshnessError("GitHub main ref lookup returned an invalid ref")
        target = result.get("object")
        if not isinstance(target, dict) or target.get("type") != "commit":
            raise FreshnessError("GitHub main ref lookup returned an invalid commit object")
        return _commit_sha(target.get("sha"), "GitHub main ref SHA")


def decide(checkpoint, admitted_commit, env, sleeper=None):
    """Return (eligible, current_main_sha); only main candidates use the API."""
    if checkpoint not in ("early", "late"):
        raise FreshnessError("checkpoint must be early or late")

    admitted_commit = _commit_sha(admitted_commit, "admitted commit")
    triggering_sha = _commit_sha(env.get("GITHUB_SHA"), "GITHUB_SHA")
    if admitted_commit != triggering_sha:
        raise FreshnessError("admitted commit does not match GITHUB_SHA")

    ref_kind = _release_ref(env)
    if ref_kind == "stable":
        return True, None

    # Validate lookup configuration before waiting so a bad environment cannot turn
    # a predictable failure into a needless delay.
    api = GitHubAPI(env)
    if checkpoint == "early":
        (sleeper or time.sleep)(QUIET_WINDOW_SECONDS)

    current_sha = api.current_main_sha()
    return admitted_commit == current_sha, current_sha


def _write_summary(path, checkpoint, admitted_commit, current_sha):
    if not path:
        raise FreshnessError("GITHUB_STEP_SUMMARY is required to record a superseded candidate")
    with open(path, "a", encoding="utf-8") as summary:
        summary.write(
            "\n### Release freshness: superseded\n\n"
            f"- Checkpoint: `{checkpoint}`\n"
            f"- Admitted SHA: `{admitted_commit}`\n"
            f"- Current main SHA: `{current_sha}`\n"
            "- Reason: main advanced after the admitted commit.\n"
        )


def main(argv=None, env=None, sleeper=None):
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    checkpoint = parser.add_mutually_exclusive_group(required=True)
    checkpoint.add_argument("--early", metavar="COMMIT")
    checkpoint.add_argument("--late", metavar="COMMIT")
    args = parser.parse_args(argv)
    env = os.environ if env is None else env
    phase, admitted_commit = ("early", args.early) if args.early is not None else ("late", args.late)

    output_path = env.get("GITHUB_OUTPUT")
    if not output_path:
        print("release-freshness: GITHUB_OUTPUT is not set", file=sys.stderr)
        return 1

    try:
        eligible, current_sha = decide(phase, admitted_commit, env, sleeper=sleeper)
        if not eligible:
            _write_summary(env.get("GITHUB_STEP_SUMMARY"), phase, admitted_commit, current_sha)
        with open(output_path, "a", encoding="utf-8") as output:
            output.write(f"eligible={str(eligible).lower()}\n")
    except FreshnessError as error:
        print(f"release-freshness: {error}", file=sys.stderr)
        return 1
    except OSError:
        print("release-freshness: could not write workflow output or summary", file=sys.stderr)
        return 1

    print(f"eligible={str(eligible).lower()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
