#!/bin/sh
set -eu

case "${1:-}" in
    upgrade|deconfigure|failed-upgrade|1)
        # An upgrade must preserve live policy and all durable ownership state.
        exit 0
        ;;
    remove|0)
        ;;
    *)
        echo "perimeterd: refusing removal with unknown package action '${1:-}'" >&2
        exit 1
        ;;
esac

# Do not trust a stop request alone: require an observed inactive/failed unit
# before running cleanup. Outside a running systemd manager, cleanup's shared
# lifecycle lock is the authoritative live-process exclusion check.
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
    systemctl stop perimeterd.service
    if ! active_state=$(systemctl show --property=ActiveState --value perimeterd.service); then
        echo "perimeterd: cannot verify perimeterd.service is inactive" >&2
        exit 1
    fi
    case "$active_state" in
        inactive|failed)
            ;;
        *)
            echo "perimeterd: perimeterd.service remains $active_state after stop" >&2
            exit 1
            ;;
    esac
fi

if [ ! -x /usr/bin/perimeterd ]; then
    echo "perimeterd: installed executable is unavailable; refusing to remove without cleanup" >&2
    exit 1
fi
/usr/bin/perimeterd cleanup

