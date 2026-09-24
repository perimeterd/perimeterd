#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
    printf 'Usage: %s DIST_DIR ARCH UPGRADE_DIST_DIR\n' "$0" >&2
    printf 'Runs Debian and Fedora install/upgrade smoke checks in matching-architecture containers.\n' >&2
}

fail() {
    printf 'packaging smoke: %s\n' "$*" >&2
    exit 1
}

if [[ $# -ne 3 ]]; then
    usage
    exit 2
fi

dist_dir=$(realpath -e -- "$1") || fail "release artifact directory does not exist: $1"
arch=$2
upgrade_dir=$(realpath -e -- "$3") || fail "upgrade fixture directory does not exist: $3"
expected_version=${PACKAGE_EXPECTED_VERSION:-}
if [[ -z $expected_version ]]; then
    metadata_file=$dist_dir/metadata.json
    [[ -f $metadata_file ]] || fail "set PACKAGE_EXPECTED_VERSION or provide GoReleaser metadata at $metadata_file"
    command -v python3 >/dev/null 2>&1 || fail 'python3 is required to read dist/metadata.json'
    expected_version=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["version"])' "$metadata_file") || fail "cannot read GoReleaser version from $metadata_file"
fi
[[ -n $expected_version ]] || fail 'GoReleaser version metadata is empty'
case "$arch" in
    amd64|arm64) ;;
    *) fail "unsupported architecture '$arch' (expected amd64 or arm64)" ;;
esac
[[ -d $dist_dir ]] || fail "release artifact path is not a directory: $dist_dir"
[[ -d $upgrade_dir ]] || fail "upgrade fixture path is not a directory: $upgrade_dir"

runtime=${PACKAGE_CONTAINER_RUNTIME:-}
if [[ -z $runtime ]]; then
    if command -v podman >/dev/null 2>&1; then
        runtime=podman
    elif command -v docker >/dev/null 2>&1; then
        runtime=docker
    else
        fail 'install Podman or Docker, or set PACKAGE_CONTAINER_RUNTIME'
    fi
fi
command -v "$runtime" >/dev/null 2>&1 || fail "container runtime not found: $runtime"

script_dir=$(dirname -- "$(realpath -e -- "$0")")
platform="linux/$arch"
debian_image=${PACKAGE_DEBIAN_IMAGE:-docker.io/library/debian:13-slim}
fedora_image=${PACKAGE_FEDORA_IMAGE:-quay.io/fedora/fedora:44}

run_distro() (
    distro=$1 image=$2
    printf 'Packaging smoke: %s (%s) on %s using %s\n' "$distro" "$arch" "$image" "$runtime"
    container=$("$runtime" create --platform "$platform" \
        --env "PACKAGE_SMOKE_DISTRO=$distro" \
        --env "PACKAGE_SMOKE_ARCH=$arch" \
        --env "PACKAGE_EXPECTED_VERSION=$expected_version" \
        "$image" /bin/bash /container-smoke.sh)
    trap '"$runtime" rm --force "$container" >/dev/null' EXIT
    # Copy into container-owned storage rather than relabeling the checkout or
    # requiring its backing filesystem to support SELinux bind-mount labels.
    "$runtime" cp "$dist_dir/." "$container:/artifacts"
    "$runtime" cp "$upgrade_dir/." "$container:/upgrade"
    "$runtime" cp "$script_dir/container-smoke.sh" "$container:/container-smoke.sh"
    "$runtime" start --attach "$container"
)

run_distro debian "$debian_image"
run_distro fedora "$fedora_image"
