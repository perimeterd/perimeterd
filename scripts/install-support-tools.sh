#!/bin/sh
set -eu
# Linux amd64 CI/development host. Keep supporting tools outside the Go module.
destination=${1:?usage: install-support-tools.sh DESTINATION}
mkdir -p "$destination"
destination=$(realpath "$destination")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM

shellcheck_version=0.11.0
curl --fail --location --retry 3 \
    "https://github.com/koalaman/shellcheck/releases/download/v${shellcheck_version}/shellcheck-v${shellcheck_version}.linux.x86_64.tar.gz" \
    --output "$work/shellcheck.tar.gz"
printf '%s  %s\n' b7af85e41cc99489dcc21d66c6d5f3685138f06d34651e6d34b42ec6d54fe6f6 "$work/shellcheck.tar.gz" | sha256sum --check --strict
tar -xzf "$work/shellcheck.tar.gz" -C "$work" "shellcheck-v${shellcheck_version}/shellcheck"
install -m 0755 "$work/shellcheck-v${shellcheck_version}/shellcheck" "$destination/shellcheck"

# Until upstream actionlint merges runner-label support (rhysd/actionlint#683),
# use the exact reviewed PR commit. The label check remains enabled.
actionlint_commit=60be20184d723e812b8454fe72e1ef3740ce050e
curl --fail --location --retry 3 \
    "https://github.com/ericcornelissen/actionlint/archive/${actionlint_commit}.tar.gz" \
    --output "$work/actionlint.tar.gz"
printf '%s  %s\n' 59b92d8eb0806c089700a78695dccd45e04a16fd7f37e5dd4f25591034c262f5 "$work/actionlint.tar.gz" | sha256sum --check --strict
tar -xzf "$work/actionlint.tar.gz" -C "$work"
(
    cd "$work/actionlint-$actionlint_commit"
    go build -mod=readonly -o "$work/actionlint" ./cmd/actionlint
)
install -m 0755 "$work/actionlint" "$destination/actionlint"
