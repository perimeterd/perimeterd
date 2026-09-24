#!/bin/sh
set -eu

# Persistent state and lock paths are retained; a prior cleanup cannot
# authorize deleting data that may have changed after package removal.

# The service/unit files have been changed or removed by this point.
systemd_pid1() {
    [ -r /proc/1/comm ] || return 1
    init_comm=
    IFS= read -r init_comm < /proc/1/comm || return 1
    [ "$init_comm" = systemd ]
}

if systemd_pid1; then
    if ! command -v systemctl >/dev/null 2>&1; then
        echo "perimeterd: systemd is running but systemctl is unavailable" >&2
        exit 1
    fi
    systemctl daemon-reload
fi
