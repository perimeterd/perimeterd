#!/usr/bin/env bash
set -Eeuo pipefail

fail() {
    printf 'packaging smoke (%s): %s\n' "${PACKAGE_SMOKE_DISTRO:-unknown}" "$*" >&2
    exit 1
}

[[ -n ${PACKAGE_SMOKE_DISTRO:-} ]] || fail 'PACKAGE_SMOKE_DISTRO is required'
[[ ${PACKAGE_SMOKE_ARCH:-} == amd64 || ${PACKAGE_SMOKE_ARCH:-} == arm64 ]] || fail 'PACKAGE_SMOKE_ARCH must be amd64 or arm64'
[[ -n ${PACKAGE_EXPECTED_VERSION:-} ]] || fail 'PACKAGE_EXPECTED_VERSION is required'

install_package_tools() {
    case "$PACKAGE_SMOKE_DISTRO" in
        debian)
            export DEBIAN_FRONTEND=noninteractive
            # The slim image excludes documentation by default; this gate must
            # install and inspect the package's documentation payload too.
            printf 'path-include=/usr/share/doc/perimeterd\npath-include=/usr/share/doc/perimeterd/*\n' > /etc/dpkg/dpkg.cfg.d/zz-perimeterd-smoke
            apt-get update -qq
            # systemd-tmpfiles is exercised in the container, but the manager
            # stays offline so package installation cannot start the daemon.
            printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
            chmod 0755 /usr/sbin/policy-rc.d
            apt-get install -y -qq systemd util-linux
            ;;
        fedora)
            dnf install -y systemd util-linux
            ;;
        *)
            fail "unsupported distribution '${PACKAGE_SMOKE_DISTRO}'"
            ;;
    esac
}

select_deb() {
    local directory=$1 wanted_arch=$2 selected=''
    local package package_arch package_name
    for package in "$directory"/*.deb; do
        [[ -f $package ]] || continue
        package_arch=$(dpkg-deb --field "$package" Architecture)
        [[ $package_arch == "$wanted_arch" ]] || continue
        package_name=$(dpkg-deb --field "$package" Package)
        [[ $package_name == perimeterd ]] || continue
        [[ -z $selected ]] || fail "multiple $wanted_arch perimeterd DEBs in $directory"
        selected=$package
    done
    [[ -n $selected ]] || fail "no $wanted_arch perimeterd DEB in $directory"
    printf '%s\n' "$selected"
}

select_rpm() {
    local directory=$1 wanted_arch=$2 selected=''
    local package package_arch package_name
    for package in "$directory"/*.rpm; do
        [[ -f $package ]] || continue
        package_arch=$(rpm --query --package --queryformat '%{ARCH}' "$package")
        [[ $package_arch == "$wanted_arch" ]] || continue
        package_name=$(rpm --query --package --queryformat '%{NAME}' "$package")
        [[ $package_name == perimeterd ]] || continue
        [[ -z $selected ]] || fail "multiple $wanted_arch perimeterd RPMs in $directory"
        selected=$package
    done
    [[ -n $selected ]] || fail "no $wanted_arch perimeterd RPM in $directory"
    printf '%s\n' "$selected"
}

check_mode() {
    local path=$1 expected=$2 actual
    [[ -e $path ]] || fail "required installed path is missing: $path"
    actual=$(stat --format='%u:%g:%a' "$path")
    [[ $actual == "0:0:$expected" ]] || fail "$path has mode/owner $actual, expected 0:0:$expected"
}

check_dependency_alternative() {
    local installed=0
    if dpkg-query --show --showformat='${db:Status-Status}' nftables 2>/dev/null | grep -Fxq installed; then
        installed=1
    elif dpkg-query --show --showformat='${db:Status-Status}' iptables 2>/dev/null | grep -Fxq installed \
        && dpkg-query --show --showformat='${db:Status-Status}' ipset 2>/dev/null | grep -Fxq installed; then
        installed=1
    fi
    [[ $installed -eq 1 ]] || fail 'DEB dependencies did not install nftables or both iptables and ipset'
}

check_rpm_dependency_alternative() {
    if rpm --quiet --query nftables; then
        return
    fi
    rpm --query --quiet --whatprovides iptables || fail 'RPM dependency resolution omitted nftables and iptables'
    rpm --query --quiet --whatprovides ipset || fail 'RPM dependency resolution omitted iptables/ipset pair'
}

check_payload() {
    local expected_arch=$1
    check_mode /usr/bin/perimeterd 755
    check_mode /etc/perimeterd 700
    check_mode /etc/perimeterd/perimeterd.yaml 600
    check_mode /etc/perimeterd/credentials.d 700
    check_mode /var/lib/perimeterd 700
    check_mode /run/perimeterd 700
    check_mode /run/perimeterd/owner.lock 600
    check_mode /run/xtables.lock 600
    [[ ! -e /run/perimeterd/lookup.sock ]] || fail 'tmpfiles unexpectedly created the daemon-owned lookup socket'
    check_mode /usr/lib/systemd/system/perimeterd.service 644
    check_mode /usr/lib/tmpfiles.d/perimeterd.conf 644
    check_mode /usr/share/doc/perimeterd/README.md 644
    check_mode /usr/share/doc/perimeterd/copyright 644
    for document in architecture configuration data-sources firewall-backends operations; do
        check_mode "/usr/share/doc/perimeterd/$document.md" 644
    done
    grep -Fqx 'ExecStart=/usr/bin/perimeterd run --config /etc/perimeterd/perimeterd.yaml' /usr/lib/systemd/system/perimeterd.service || fail 'systemd unit does not run the installed executable/configuration'
    grep -Fqx 'ProtectSystem=strict' /usr/lib/systemd/system/perimeterd.service || fail 'systemd unit is missing the strict filesystem sandbox'
    grep -Fqx 'RuntimeDirectoryPreserve=yes' /usr/lib/systemd/system/perimeterd.service || fail 'systemd unit does not retain its runtime directory'
    grep -Fqx 'ReadWritePaths=/run/xtables.lock' /usr/lib/systemd/system/perimeterd.service || fail 'systemd unit does not grant access only to the shared xtables lock'
    grep -Fq 'f /run/xtables.lock 0600 root root -' /usr/lib/tmpfiles.d/perimeterd.conf || fail 'tmpfiles config does not provision the shared xtables lock'

    if [[ $PACKAGE_SMOKE_DISTRO == debian ]]; then
        local installed_arch
        installed_arch=$(dpkg-query --show --showformat='${Architecture}' perimeterd)
        [[ $installed_arch == "$expected_arch" ]] || fail "installed DEB architecture is $installed_arch, expected $expected_arch"
        check_dependency_alternative
    else
        local installed_arch
        installed_arch=$(rpm --query --queryformat '%{ARCH}' perimeterd)
        [[ $installed_arch == "$expected_arch" ]] || fail "installed RPM architecture is $installed_arch, expected $expected_arch"
        check_rpm_dependency_alternative
    fi
}

package_version() {
    local package=$1
    if [[ $PACKAGE_SMOKE_DISTRO == debian ]]; then
        dpkg-deb --field "$package" Version
    else
        rpm --query --package --queryformat '%{VERSION}-%{RELEASE}' "$package"
    fi
}

installed_version() {
    if [[ $PACKAGE_SMOKE_DISTRO == debian ]]; then
        dpkg-query --show --showformat='${Version}' perimeterd
    else
        rpm --query --queryformat '%{VERSION}-%{RELEASE}' perimeterd
    fi
}

run_metadata_and_validate() {
    local expected_version=$1 output version commit build_time
    output=$(/usr/bin/perimeterd version)
    version=$(printf '%s\n' "$output" | sed -n 's/^version: //p')
    commit=$(printf '%s\n' "$output" | sed -n 's/^commit: //p')
    build_time=$(printf '%s\n' "$output" | sed -n 's/^build time: //p')
    [[ -n $version && $version != dev ]] || fail 'binary version metadata is missing or still set to dev'
    [[ $version == "$expected_version" ]] || fail "binary version $version does not match package version $expected_version"
    [[ $commit =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]] || fail "binary commit metadata is not a full Git object ID: $commit"
    [[ $build_time =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || fail "binary build time metadata is not UTC RFC3339: $build_time"
    /usr/bin/perimeterd validate --config /etc/perimeterd/perimeterd.yaml
}

install_package_tools
case "$PACKAGE_SMOKE_DISTRO" in
    debian)
        native_arch=$(dpkg --print-architecture)
        case "$PACKAGE_SMOKE_ARCH" in amd64) expected_arch=amd64 ;; arm64) expected_arch=arm64 ;; esac
        [[ $native_arch == "$expected_arch" ]] || fail "container architecture is $native_arch, expected $expected_arch"
        baseline_package=$(select_deb /upgrade "$expected_arch")
        release_package=$(select_deb /artifacts "$expected_arch")
        baseline_version=$(package_version "$baseline_package")
        release_version=$(package_version "$release_package")
        dpkg --compare-versions "$baseline_version" lt "$release_version" || fail "upgrade fixture version $baseline_version is not older than release $release_version"
        apt-get install -y -qq "$baseline_package"
        check_payload "$expected_arch"
        ;;
    fedora)
        case "$PACKAGE_SMOKE_ARCH" in amd64) expected_arch=x86_64 ;; arm64) expected_arch=aarch64 ;; esac
        native_arch=$(rpm --eval '%{_arch}')
        [[ $native_arch == "$expected_arch" ]] || fail "container architecture is $native_arch, expected $expected_arch"
        baseline_package=$(select_rpm /upgrade "$expected_arch")
        release_package=$(select_rpm /artifacts "$expected_arch")
        baseline_version=$(package_version "$baseline_package")
        release_version=$(package_version "$release_package")
        [[ $baseline_version != "$release_version" ]] || fail "upgrade fixture and release package both have version $release_version"
        dnf install -y "$baseline_package"
        check_payload "$expected_arch"
        ;;
esac

config=/etc/perimeterd/perimeterd.yaml
printf '\n# packaging smoke: operator-managed content must survive upgrade\n' >> "$config"
config_before=$(sha256sum "$config" | cut -d ' ' -f1)
xtables_inode_before=$(stat --format='%i' /run/xtables.lock)
owner_inode_before=$(stat --format='%i' /run/perimeterd/owner.lock)

case "$PACKAGE_SMOKE_DISTRO" in
    debian)
        apt-get install -y -qq "$release_package"
        ;;
    fedora)
        dnf install -y "$release_package"
        ;;
esac

[[ $(installed_version) == "$release_version" ]] || fail "package manager did not upgrade to $release_version"
[[ $(sha256sum "$config" | cut -d ' ' -f1) == "$config_before" ]] || fail 'operator configuration changed during package upgrade'
[[ $(stat --format='%i' /run/xtables.lock) == "$xtables_inode_before" ]] || fail 'upgrade replaced the shared xtables lock inode'
[[ $(stat --format='%i' /run/perimeterd/owner.lock) == "$owner_inode_before" ]] || fail 'upgrade replaced the lifecycle lock inode'
check_payload "$expected_arch"
run_metadata_and_validate "$PACKAGE_EXPECTED_VERSION"

# Exercise both package managers' pre-removal failure semantics without starting
# the daemon or creating any native firewall state in these containers.
printf 'retained recovery evidence\n' > /var/lib/perimeterd/package-smoke-evidence
printf 'retained credential\n' > /etc/perimeterd/credentials.d/package-smoke
chmod 0600 /etc/perimeterd/credentials.d/package-smoke
exec 9<>/run/perimeterd/owner.lock
flock -n 9
case "$PACKAGE_SMOKE_DISTRO" in
    debian) remove_command=(dpkg --remove perimeterd) ;;
    fedora) remove_command=(rpm --erase perimeterd) ;;
esac
if "${remove_command[@]}" >/tmp/perimeterd-remove.log 2>&1; then
    fail 'package removal succeeded while lifecycle ownership was held'
fi
[[ -x /usr/bin/perimeterd ]] || fail 'failed removal deleted the executable'
[[ -f /usr/lib/systemd/system/perimeterd.service ]] || fail 'failed removal deleted the service'
[[ $(sha256sum "$config" | cut -d ' ' -f1) == "$config_before" ]] || fail 'failed removal changed configuration'
[[ -f /var/lib/perimeterd/package-smoke-evidence ]] || fail 'failed removal deleted retained state'
flock -u 9
exec 9>&-
"${remove_command[@]}"
[[ ! -e /usr/bin/perimeterd ]] || fail 'successful removal retained the executable'
[[ ! -e /usr/lib/systemd/system/perimeterd.service ]] || fail 'successful removal retained the service'
if [[ $PACKAGE_SMOKE_DISTRO == debian ]]; then
    dpkg --purge perimeterd
fi
[[ -f /var/lib/perimeterd/package-smoke-evidence ]] || fail 'removal or purge deleted retained state'
[[ -f /etc/perimeterd/credentials.d/package-smoke ]] || fail 'removal or purge deleted credentials'
[[ $(stat --format='%i' /run/xtables.lock) == "$xtables_inode_before" ]] || fail 'removal replaced the shared xtables lock inode'
[[ $(stat --format='%i' /run/perimeterd/owner.lock) == "$owner_inode_before" ]] || fail 'removal replaced the lifecycle lock inode'
