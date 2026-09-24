#!/usr/bin/env python3
"""Admit a release ref and emit deterministic GitHub Actions metadata."""
import os
import re
import subprocess
import tempfile

STABLE = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", re.ASCII)


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


def main():
    values = metadata(os.environ["GITHUB_REF"], os.environ["GITHUB_RUN_NUMBER"],
                      os.environ["GITHUB_SHA"], os.environ.get("RELEASE_SIGNING_PUBLIC_KEYS", ""))
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        for key, value in values.items():
            print(f"{key}={value}", file=output)


if __name__ == "__main__":
    main()
