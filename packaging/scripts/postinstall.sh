#!/bin/sh
set -eu

tmpfiles_conf=/usr/lib/tmpfiles.d/perimeterd.conf

systemd_pid1() {
    [ -r /proc/1/comm ] || return 1
    init_comm=
    IFS= read -r init_comm < /proc/1/comm || return 1
    [ "$init_comm" = systemd ]
}

if command -v systemd-tmpfiles >/dev/null 2>&1; then
    systemd-tmpfiles --create "$tmpfiles_conf"
elif systemd_pid1; then
    echo "perimeterd: systemd is running but systemd-tmpfiles is unavailable" >&2
    exit 1
fi

# A package may be installed in a container or on a non-systemd host. Reload
# only when systemd is PID 1; any live-manager failure is a package
# configuration failure, not a reason to silently skip provisioning.
if systemd_pid1; then
    if ! command -v systemctl >/dev/null 2>&1; then
        echo "perimeterd: systemd is running but systemctl is unavailable" >&2
        exit 1
    fi
    systemctl daemon-reload
fi

printf '%s\n' "perimeterd installed. Review /etc/perimeterd/perimeterd.yaml before manually enabling or starting perimeterd.service." >&2
