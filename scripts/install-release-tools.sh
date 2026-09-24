#!/bin/sh
set -eu
# Linux amd64 build host; produced artifacts target both supported architectures.
destination=${1:?usage: install-release-tools.sh DESTINATION}
mkdir -p "$destination"
destination=$(realpath "$destination")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
fetch() {
    name=$1 url=$2 checksum=$3 binary=$4
    curl --fail --location --retry 3 "$url" --output "$work/$name.tar.gz"
    printf '%s  %s\n' "$checksum" "$work/$name.tar.gz" | sha256sum --check --strict
    tar -xzf "$work/$name.tar.gz" -C "$work" "$binary"
    install -m 0755 "$work/$binary" "$destination/$name"
}
fetch goreleaser https://github.com/goreleaser/goreleaser/releases/download/v2.18.2/goreleaser_Linux_x86_64.tar.gz 0a96edc9d9bc594e4a41cc4d59467c182062910ab24d9d1f6dd7b667d32606d3 goreleaser
fetch syft https://github.com/anchore/syft/releases/download/v1.52.0/syft_1.52.0_linux_amd64.tar.gz caeedb81fb0491615f1ebd1761e4145d41ee86dd2cc7bf80669f9f5ad9d6133d syft
