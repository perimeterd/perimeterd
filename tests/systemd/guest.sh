#!/usr/bin/env bash
set -Eeuo pipefail

if (($# != 2)) || [[ "$1" != full && "$1" != fast ]]; then
  printf 'usage: guest.sh full|fast /path/to/perimeterd.deb\n' >&2
  exit 2
fi
mode=$1
deb_path=$2
if [[ $EUID -ne 0 ]]; then
  printf 'guest gate must run as root inside the disposable VM\n' >&2
  exit 2
fi
exec > >(tee -a /var/log/perimeterd-systemd-gate.log) 2>&1

readonly UNIT=perimeterd.service
readonly UNIT_FILE=/usr/lib/systemd/system/perimeterd.service
readonly TMPFILES_FILE=/usr/lib/tmpfiles.d/perimeterd.conf
readonly CONFIG=/etc/perimeterd/perimeterd.yaml
readonly RUNTIME_DIR=/run/perimeterd
readonly OWNER_LOCK=/run/perimeterd/owner.lock
readonly XTABLES_LOCK=/run/xtables.lock
readonly METRICS_URL=http://127.0.0.1:19095/metrics
readonly SOURCE_PORT=18181
readonly SOURCE_URL=http://127.0.0.1:18181/list
readonly MARKER_DIR=/run/perimeterd
readonly RESTART_DROPIN_DIR=/run/systemd/system/perimeterd.service.d

fixture_pid=
xtables_lock_pid=

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  local result=$?
  for pid in "$fixture_pid" "$xtables_lock_pid"; do
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill -TERM "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  systemctl stop perimeterd-systemd-lock-holder.service >/dev/null 2>&1 || true
  return "$result"
}

trap cleanup EXIT


log() {
  printf '\n[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

require_absent() {
  [[ ! -e "$1" ]] || fail "expected $1 to be absent"
}

show_property() {
  systemctl show --property="$1" --value "$UNIT"
}

assert_property() {
  local key=$1 expected=$2 got
  got=$(show_property "$key")
  [[ "$got" == "$expected" ]] || fail "$key is '$got', expected '$expected'"
}

assert_true_property() {
  local key=$1 got
  got=$(show_property "$key")
  case "${got,,}" in
    yes|true|1) ;;
    *) fail "$key is '$got', expected enabled" ;;
  esac
}

assert_unit_contract() {
  local capability_set ambient_set family_set family_count readonly_paths
  [[ -f "$UNIT_FILE" ]] || fail "packaged service unit missing at $UNIT_FILE"
  [[ -f "$TMPFILES_FILE" ]] || fail "packaged tmpfiles payload missing at $TMPFILES_FILE"
  [[ $(show_property LoadState) == loaded ]] || fail "systemd did not load the packaged unit"
  [[ $(show_property FragmentPath) == "$UNIT_FILE" ]] || fail "systemd unit is not the packaged payload"
  local timeout_value
  assert_property Type notify
  assert_property NotifyAccess main
  timeout_value=$(show_property TimeoutStartUSec)
  case "$timeout_value" in
    '90s'|'1min 30s') ;;
    *) fail "TimeoutStartUSec is '$timeout_value', expected 90 seconds" ;;
  esac
  assert_property Restart on-failure
  assert_property RestartUSec '5s'
  assert_property RuntimeDirectory perimeterd
  assert_property RuntimeDirectoryPreserve yes
  assert_property StateDirectory perimeterd
  assert_property StateDirectoryMode 0700
  assert_property RuntimeDirectoryMode 0700
  assert_property ProtectSystem strict
  assert_property UMask 0077
  readonly_paths=$(show_property ReadWritePaths)
  [[ " $readonly_paths " == *' /run/xtables.lock '* ]] || fail "ReadWritePaths does not permit the shared xtables lock: $readonly_paths"
  assert_true_property ProtectHome
  assert_true_property ProtectControlGroups
  assert_true_property ProtectKernelTunables
  assert_true_property ProtectKernelModules
  assert_true_property NoNewPrivileges
  assert_true_property PrivateTmp
  assert_true_property RestrictSUIDSGID
  capability_set=$(show_property CapabilityBoundingSet)
  ambient_set=$(show_property AmbientCapabilities)
  capability_set=${capability_set,,}
  ambient_set=${ambient_set,,}
  [[ "$capability_set" == 'cap_net_admin cap_net_raw' || "$capability_set" == 'cap_net_raw cap_net_admin' ]] || fail "unexpected CapabilityBoundingSet: $capability_set"
  [[ "$ambient_set" == 'cap_net_admin cap_net_raw' || "$ambient_set" == 'cap_net_raw cap_net_admin' ]] || fail "unexpected AmbientCapabilities: $ambient_set"
  family_set=$(show_property RestrictAddressFamilies)
  for family in AF_UNIX AF_INET AF_INET6 AF_NETLINK; do
    [[ " $family_set " == *" $family "* ]] || fail "RestrictAddressFamilies omits $family: $family_set"
  done
  [[ ${#family_set} -gt 0 ]] || fail 'RestrictAddressFamilies is empty'
  family_count=$(wc -w <<<"$family_set")
  [[ "$family_count" == 4 ]] || fail "unexpected RestrictAddressFamilies set: $family_set"
}

set_variant() {
  local variant=$1 name target
  case "$variant" in
    nft) variant=nft ;;
    legacy) variant=legacy ;;
    *) fail "unsupported iptables variant $variant" ;;
  esac
  for name in iptables ip6tables; do
    target="/usr/sbin/${name}-${variant}"
    [[ -x "$target" ]] || fail "required iptables alternative is missing: $target"
    update-alternatives --set "$name" "$target"
  done
  check_variant "$variant"
}

check_variant() {
  local variant=$1 expected tool output
  case "$variant" in
    nft) expected=nf_tables ;;
    legacy) expected=legacy ;;
    *) fail "unsupported iptables variant $variant" ;;
  esac
  for tool in iptables ip6tables iptables-save ip6tables-save iptables-restore ip6tables-restore; do
    output=$("$tool" --version 2>&1) || fail "$tool --version failed: $output"
    [[ "$output" == *"$expected"* ]] || fail "$tool selected the wrong implementation for $variant: $output"
  done
  ipset --version >/dev/null || fail 'ipset --version failed'
}

write_config() {
  local deny_action=$1
  cat >"$CONFIG" <<EOF
version: 1
logging:
  level: error
  format: text
metrics:
  listen: "127.0.0.1:19095"
global:
  allowlist: []
  blocklist: []
firewall:
  backend: iptables
  deny_action: $deny_action
  ipv4: true
  ipv6: true
  iptables:
    attachments:
      - chain: INPUT
        direction: ingress
      - chain: OUTPUT
        direction: egress
geo:
  refresh_interval: 24h
  request_timeout: 1s
  refresh_jitter: 1s
ip_lists:
  delayed:
    url: "$SOURCE_URL"
    refresh_interval: 24h
    request_timeout: 180s
groups: {}
policies:
  - name: systemd-delayed-list
    priority: 100
    direction: egress
    mode: blocklist
    traffic: ["any"]
    include:
      ip_lists: [delayed]
crowdsec:
  enabled: false
EOF
  chmod 0600 "$CONFIG"
  /usr/bin/perimeterd validate --config "$CONFIG"
}

health_value() {
  curl --fail --silent --show-error --max-time 3 "$METRICS_URL" \
    | awk '$1 == "perimeterd_enforcement_health" { print $2; found = 1 } END { if (!found) exit 1 }'
}

wait_health() {
  local expected=$1 seconds=$2 got
  local end=$((SECONDS + seconds))
  while ((SECONDS < end)); do
    if got=$(health_value 2>/dev/null) && [[ "$got" == "$expected" ]]; then
      return 0
    fi
    sleep 1
  done
  got=$(health_value 2>/dev/null || true)
  fail "enforcement health did not become $expected (last value: ${got:-unavailable})"
}

wait_active() {
  local seconds=$1 state
  local end=$((SECONDS + seconds))
  while ((SECONDS < end)); do
    state=$(show_property ActiveState)
    case "$state" in
      active) return 0 ;;
      failed) journalctl -u "$UNIT" --no-pager -n 100; fail 'systemd service failed before READY=1' ;;
    esac
    sleep 1
  done
  journalctl -u "$UNIT" --no-pager -n 100
  fail "systemd service did not become active within ${seconds}s (state=$(show_property ActiveState))"
}

wait_no_journal() {
  local seconds=$1
  local end=$((SECONDS + seconds))
  while ((SECONDS < end)); do
    [[ ! -e /var/lib/perimeterd/journal.json ]] && return 0
    sleep 1
  done
  fail 'transaction journal remained after successful recovery'
}

assert_owned_rules() {
  local v4 v6
  v4=$(iptables-save --counters)
  v6=$(ip6tables-save --counters)
  [[ "$v4" == *'perimeterd owner='* ]] || fail 'IPv4 perimeterd-owned rules are missing'
  [[ "$v6" == *'perimeterd owner='* ]] || fail 'IPv6 perimeterd-owned rules are missing'
}

assert_no_owned_rules() {
  local v4 v6
  v4=$(iptables-save --counters)
  v6=$(ip6tables-save --counters)
  [[ "$v4" != *'perimeterd owner='* ]] || fail 'IPv4 perimeterd-owned rules remain after cleanup'
  [[ "$v6" != *'perimeterd owner='* ]] || fail 'IPv6 perimeterd-owned rules remain after cleanup'
}

start_delayed_source() {
  python3 -u - <<'PY' >/var/log/perimeterd-systemd-source.log 2>&1 &
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import time

served = False

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        global served
        if self.path != "/list":
            self.send_error(404)
            return
        if not served:
            served = True
            print("first source request held for 100 seconds", flush=True)
            time.sleep(100)
        payload = b"203.0.113.77/32\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        print(format % args, flush=True)

ThreadingHTTPServer(("127.0.0.1", 18181), Handler).serve_forever()
PY
  fixture_pid=$!
  local attempt
  for attempt in {1..20}; do
    if python3 - "$SOURCE_PORT" <<'PY'
import socket, sys
with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=1):
    pass
PY
    then
      return 0
    fi
    sleep 1
  done
  fail 'delayed local source fixture did not listen'
}

start_service_and_wait() {
  local seconds=$1
  systemctl start --no-block "$UNIT"
  wait_active "$seconds"
  wait_health 1 30
  [[ -s /var/lib/perimeterd/active.json ]] || fail 'active revision was not durably published'
  [[ ! -e /var/lib/perimeterd/journal.json ]] || fail 'ready service retained an unexpected transaction journal'
  assert_owned_rules
}

inode_of() {
  stat -c '%d:%i' "$1"
}

hold_xtables_lock() {
  # The readiness probe briefly takes the same lock. A nonblocking holder can
  # lose that race and exit before the probe observes it.
  flock --no-fork "$XTABLES_LOCK" sleep 7200 &
  xtables_lock_pid=$!
  local attempt
  for ((attempt=0; attempt<20; attempt++)); do
    if ! flock -n "$XTABLES_LOCK" -c true >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  fail 'could not acquire the shared xtables lock for the stalled-startup scenario'
}


install_restore_fault() {
  local real_restore path_dropin pid service_path
  real_restore=$(PATH=/usr/sbin:/usr/bin command -v ip6tables-restore)
  [[ "$real_restore" == /usr/sbin/ip6tables-restore && -x "$real_restore" ]] || fail "cannot resolve the selected IPv6 restore binary at /usr/sbin/ip6tables-restore: $real_restore"
  cat >/usr/local/sbin/ip6tables-restore <<EOF
#!/bin/sh
set -eu
real_restore=/usr/sbin/\${0##*/}
input=\$(/usr/bin/mktemp /run/perimeterd/systemd-gate-restore.XXXXXX)
trap '/bin/rm -f "\$input"' EXIT
/bin/cat >"\$input"
if [ -e /run/perimeterd/systemd-gate-fault ]; then
  payload=\$(/bin/cat "\$input")
  case "\$real_restore:\$payload" in
    */ip6tables-restore:*"/dispatch"*)
      /usr/bin/touch /run/perimeterd/systemd-gate-fault-hit
      ;;
  esac
  # IPv4 has already switched when the IPv6 dispatch fails. Keep both
  # writers faulted afterward so compensation cannot silently recover it.
  if [ -e /run/perimeterd/systemd-gate-fault-hit ] && [ -s "\$input" ]; then
      attempts=0
      if [ -r /run/perimeterd/systemd-gate-fault-dispatch-attempts ]; then
        attempts=\$(/bin/cat /run/perimeterd/systemd-gate-fault-dispatch-attempts)
      fi
      attempts=\$((attempts + 1))
      printf '%s\n' "\$attempts" >/run/perimeterd/systemd-gate-fault-dispatch-attempts
      printf 'injected IPv6 dispatch failure %s (argv0=%s args=%s)\n' "\$attempts" "\$real_restore" "\$*" >>/run/perimeterd/systemd-gate-restore.trace
      /usr/bin/touch /run/perimeterd/systemd-gate-fault-hit
      exit 42
  fi
fi
printf 'passed restore (argv0=%s args=%s)\n' "\$real_restore" "\$*" >>/run/perimeterd/systemd-gate-restore.trace
"\$real_restore" "\$@" <"\$input"
EOF
  chmod 0755 /usr/local/sbin/ip6tables-restore
  cp /usr/local/sbin/ip6tables-restore /usr/local/sbin/iptables-restore
  mkdir -p "$RESTART_DROPIN_DIR"
  path_dropin="$RESTART_DROPIN_DIR/88-systemd-gate-restore-path.conf"
  rm -f "$MARKER_DIR/systemd-gate-fault-hit" \
    "$MARKER_DIR/systemd-gate-fault-dispatch-attempts" \
    "$MARKER_DIR/systemd-gate-restore.trace"
  if [[ ! -f "$path_dropin" ]]; then
    cat >"$path_dropin" <<'EOF'
[Service]
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
EOF
    systemctl daemon-reload
    systemctl restart "$UNIT"
    wait_active 90
    wait_health 1 30
  fi
  pid=$(show_property MainPID)
  service_path=$(tr '\0' '\n' <"/proc/$pid/environ" | sed -n 's/^PATH=//p')
  [[ "$service_path" == /usr/local/sbin:* ]] || fail "fault wrapper is not first on the service PATH: ${service_path:-unavailable}"
  : >"$MARKER_DIR/systemd-gate-fault"
}

remove_removal_lock_hook() {
  systemctl stop perimeterd-systemd-lock-holder.service
  rm -f "$RESTART_DROPIN_DIR/91-systemd-gate-removal-lock.conf"
  rm -f "$RESTART_DROPIN_DIR/88-systemd-gate-restore-path.conf"
  rmdir "$RESTART_DROPIN_DIR" 2>/dev/null || true
  rm -f /run/systemd/system/perimeterd-systemd-lock-holder.service
  rm -f /usr/local/sbin/perimeterd-systemd-lock-ready
  systemctl daemon-reload
}

fault_diagnostics() {
  local state health hit attempts journal mainpid service_path
  state=$(show_property ActiveState 2>/dev/null || true)
  health=$(health_value 2>/dev/null || true)
  hit=no
  [[ -e "$MARKER_DIR/systemd-gate-fault-hit" ]] && hit=yes
  attempts=0
  [[ -r "$MARKER_DIR/systemd-gate-fault-dispatch-attempts" ]] && attempts=$(<"$MARKER_DIR/systemd-gate-fault-dispatch-attempts")
  journal=missing
  [[ -s /var/lib/perimeterd/journal.json ]] && journal=present
  mainpid=$(show_property MainPID 2>/dev/null || true)
  service_path=
  if [[ "$mainpid" =~ ^[1-9][0-9]*$ ]]; then
    service_path=$(tr '\0' '\n' <"/proc/$mainpid/environ" | sed -n 's/^PATH=//p' || true)
  fi
  printf 'Fault-injection diagnostics: unit_state=%s health=%s fault_hit=%s dispatch_failures=%s journal=%s MainPID=%s PATH=%s\n' \
    "${state:-unavailable}" "${health:-unavailable}" "$hit" "$attempts" "$journal" "${mainpid:-unavailable}" "${service_path:-unavailable}" >&2
  if [[ -s /var/lib/perimeterd/journal.json ]]; then
    printf '%s\n' 'Durable transaction journal:' >&2
    cat /var/lib/perimeterd/journal.json >&2
  fi
  if [[ -s "$MARKER_DIR/systemd-gate-restore.trace" ]]; then
    printf '%s\n' 'Restore-wrapper trace:' >&2
    cat "$MARKER_DIR/systemd-gate-restore.trace" >&2
  fi
  systemctl show --property=ActiveState,SubState,Result,ExecMainStatus,MainPID "$UNIT" >&2 || true
  journalctl -u "$UNIT" --no-pager -n 100 >&2 || true
}

wait_degraded() {
  local end=$((SECONDS + 30)) health attempts
  while ((SECONDS < end)); do
    attempts=0
    [[ -r "$MARKER_DIR/systemd-gate-fault-dispatch-attempts" ]] && attempts=$(<"$MARKER_DIR/systemd-gate-fault-dispatch-attempts")
    if [[ -e "$MARKER_DIR/systemd-gate-fault-hit" && -s /var/lib/perimeterd/journal.json && "$attempts" =~ ^[0-9]+$ ]] \
      && ((attempts >= 2)); then
      health=$(health_value 2>/dev/null || true)
      if [[ "$health" == 0 ]]; then
        return 0
      fi
    fi
    sleep 0.2
  done
  fault_diagnostics
  fail "faulted native apply did not reach degraded state after failed candidate and compensation restores"
}

install_removal_lock_hook() {
  mkdir -p "$RESTART_DROPIN_DIR"
  cat >/run/systemd/system/perimeterd-systemd-lock-holder.service <<'EOF'
[Unit]
Description=perimeterd systemd-gate lifecycle-lock holder

[Service]
Type=simple
ExecStart=/usr/bin/flock /run/perimeterd/owner.lock /usr/bin/sleep 600
ExecStartPost=/usr/local/sbin/perimeterd-systemd-lock-ready
EOF
  cat >/usr/local/sbin/perimeterd-systemd-lock-ready <<'EOF'
#!/bin/sh
set -eu
attempt=0
while [ "$attempt" -lt 100 ]; do
  if ! /usr/bin/flock -n /run/perimeterd/owner.lock /bin/true >/dev/null 2>&1; then
    exit 0
  fi
  attempt=$((attempt + 1))
  /bin/sleep 0.1
done
exit 1
EOF
  chmod 0755 /usr/local/sbin/perimeterd-systemd-lock-ready
  cat >"$RESTART_DROPIN_DIR/91-systemd-gate-removal-lock.conf" <<'EOF'
[Service]
ExecStopPost=/usr/bin/systemctl start perimeterd-systemd-lock-holder.service
EOF
  systemctl daemon-reload
}


recover_degraded_state() {
  rm -f "$MARKER_DIR/systemd-gate-fault"
  wait_health 1 60
  wait_no_journal 60
  rm -f /usr/local/sbin/{ip6tables,iptables}-restore "$MARKER_DIR/systemd-gate-fault-hit"
  assert_owned_rules
}

cleanup_service_state() {
  systemctl stop "$UNIT"
  [[ $(show_property ActiveState) == inactive ]] || fail 'perimeterd did not stop before cleanup'
  /usr/bin/perimeterd cleanup
  assert_no_owned_rules
  [[ $(inode_of "$OWNER_LOCK") == "$owner_inode_initial" ]] || fail 'cleanup replaced the lifecycle-lock inode'
  [[ $(inode_of "$XTABLES_LOCK") == "$xtables_inode_initial" ]] || fail 'cleanup replaced the xtables-lock inode'
  [[ $(inode_of "$RUNTIME_DIR") == "$runtime_inode_initial" ]] || fail 'cleanup replaced the runtime-directory inode'
}

assert_startup_sandbox() {
  local pid uid cap_bnd cap_eff cap_amb marker
  pid=$(show_property MainPID)
  [[ "$pid" =~ ^[1-9][0-9]*$ ]] || fail "active service has invalid MainPID '$pid'"
  uid=$(awk '$1 == "Uid:" { print $2 }' "/proc/$pid/status")
  [[ "$uid" == 0 ]] || fail "service is not running as root: uid=$uid"
  cap_bnd=$(awk '$1 == "CapBnd:" { print $2 }' "/proc/$pid/status")
  cap_eff=$(awk '$1 == "CapEff:" { print $2 }' "/proc/$pid/status")
  [[ $(readlink -- "/proc/$pid/exe") == /usr/bin/perimeterd ]] || fail 'systemd did not execute the installed perimeterd binary'
  cap_amb=$(awk '$1 == "CapAmb:" { print $2 }' "/proc/$pid/status")
  ((16#$cap_bnd == 12288)) || fail "service capability bounding set is not NET_ADMIN+NET_RAW: $cap_bnd"
  ((16#$cap_eff == 12288)) || fail "service effective capabilities are not NET_ADMIN+NET_RAW: $cap_eff"
  ((16#$cap_amb == 12288)) || fail "service ambient capabilities are not NET_ADMIN+NET_RAW: $cap_amb"
  marker=$(mktemp /tmp/perimeterd-host-tmp.XXXXXX)
  if nsenter -t "$pid" -m -- /usr/bin/test -e "$marker"; then
    rm -f "$marker"
    fail 'PrivateTmp does not isolate the service temporary directory'
  fi
  rm -f "$marker"
  if nsenter -t "$pid" -m -- /usr/bin/touch /etc/perimeterd/.systemd-gate-write 2>/dev/null; then
    rm -f /etc/perimeterd/.systemd-gate-write
    fail 'ProtectSystem=strict left the service configuration directory writable'
  fi
}

log 'Confirming the freshly booted VM has no xtables lock or runtime directory'
[[ -d /run/systemd/system ]] || fail 'the guest is not booted with systemd as PID 1'
require_absent "$XTABLES_LOCK"
require_absent "$RUNTIME_DIR"

log 'Installing the staged DEB after boot and checking package-time tmpfiles provisioning'
[[ -f "$deb_path" ]] || fail "package artifact is missing: $deb_path"
apt-get update
apt-get install --yes "$deb_path"
[[ $(dpkg-query -W -f='${db:Status-Status}' perimeterd) == installed ]] || fail 'the DEB did not install perimeterd'
[[ -x /usr/bin/perimeterd ]] || fail 'installed perimeterd binary is missing or non-executable'
[[ $(show_property LoadState) == loaded ]] || fail 'package post-install did not reload systemd units'
[[ $(show_property ActiveState) == inactive ]] || fail 'package installation unexpectedly started the unconfigured service'
enabled_state=$(systemctl is-enabled "$UNIT" 2>/dev/null || true)
case "$enabled_state" in
  disabled|static|indirect) ;;
  *) fail "package installation unexpectedly enabled perimeterd.service: $enabled_state" ;;
esac
[[ -d "$RUNTIME_DIR" ]] || fail 'late package installation did not create /run/perimeterd'
[[ -f "$OWNER_LOCK" ]] || fail 'late package installation did not provision the lifecycle lock'
[[ -f "$XTABLES_LOCK" ]] || fail 'late package installation did not provision the shared xtables lock'
[[ $(stat -c '%a:%u:%g' "$RUNTIME_DIR") == 700:0:0 ]] || fail 'runtime directory ownership or mode is incorrect'
[[ $(stat -c '%a:%u:%g' "$OWNER_LOCK") == 600:0:0 ]] || fail 'lifecycle lock ownership or mode is incorrect'
[[ $(stat -c '%a:%u:%g' "$XTABLES_LOCK") == 600:0:0 ]] || fail 'xtables lock ownership or mode is incorrect'
owner_inode_initial=$(inode_of "$OWNER_LOCK")
runtime_inode_initial=$(inode_of "$RUNTIME_DIR")
xtables_inode_initial=$(inode_of "$XTABLES_LOCK")
systemd-tmpfiles --create "$TMPFILES_FILE"
systemd-tmpfiles --create "$TMPFILES_FILE"
[[ $(inode_of "$OWNER_LOCK") == "$owner_inode_initial" ]] || fail 'tmpfiles replaced the existing lifecycle-lock inode'
[[ $(inode_of "$XTABLES_LOCK") == "$xtables_inode_initial" ]] || fail 'tmpfiles replaced the existing xtables-lock inode'
[[ $(inode_of "$RUNTIME_DIR") == "$runtime_inode_initial" ]] || fail 'tmpfiles replaced the runtime-directory inode'

log 'Installing native test dependencies without changing the package-provisioned lock'
apt-get install --yes --no-install-recommends iptables ipset curl python3 util-linux
modprobe ip_tables
modprobe ip6_tables
modprobe iptable_filter
modprobe ip6table_filter
[[ $(inode_of "$XTABLES_LOCK") == "$xtables_inode_initial" ]] || fail 'native-tool installation replaced the xtables-lock inode'
[[ $(inode_of "$RUNTIME_DIR") == "$runtime_inode_initial" ]] || fail 'native-tool installation replaced the runtime-directory inode'
command -v nsenter >/dev/null || fail 'util-linux did not install nsenter'
assert_unit_contract

log 'Selecting the legacy iptables family and preparing a local-only policy'
# Legacy restore honors the shared xtables flock used by the startup-deadline
# scenario. iptables-nft uses nft transactions and does not wait on that lock.
set_variant legacy
write_config drop
start_delayed_source
start_time=$SECONDS
systemctl start --no-block "$UNIT"
while ((SECONDS - start_time < 93)); do
  state=$(show_property ActiveState)
  case "$state" in
    active) fail 'service became ready before the >90-second source fixture completed' ;;
    failed) journalctl -u "$UNIT" --no-pager -n 100; fail 'service failed instead of extending its systemd activation' ;;
  esac
  sleep 1
done
[[ $(show_property ActiveState) == activating ]] || fail 'service did not remain activating after the initial 90-second systemd window'
log 'The initial 90-second activation window elapsed while the real Type=notify unit remained activating'
wait_active 180
((SECONDS - start_time > 90)) || fail 'delayed service activation did not exceed 90 seconds'
wait_health 1 30
assert_owned_rules
[[ $(ipset save) == *'203.0.113.77'* ]] || fail 'the delayed source prefix was not applied to the real kernel ipset state'
assert_startup_sandbox

log 'Checking service/cleanup lock exclusion, restart inode retention, and degraded-health recovery'
active_hash_before=$(sha256sum /var/lib/perimeterd/active.json | awk '{print $1}')
if timeout 10s /usr/bin/perimeterd cleanup > /var/log/perimeterd-live-cleanup.log 2>&1; then
  fail 'cleanup unexpectedly acquired lifecycle ownership while the systemd service was active'
fi
cleanup_output=$(</var/log/perimeterd-live-cleanup.log)
[[ "$cleanup_output" == *'already held'* ]] || fail "live cleanup failed for an unexpected reason: $cleanup_output"
if timeout 10s /usr/bin/perimeterd run --config "$CONFIG" > /var/log/perimeterd-live-run.log 2>&1; then
  fail 'a concurrent perimeterd run unexpectedly started beside the systemd service'
fi
run_output=$(</var/log/perimeterd-live-run.log)
[[ "$run_output" == *'already held'* ]] || fail "concurrent run failed for an unexpected reason: $run_output"
[[ $(inode_of "$OWNER_LOCK") == "$owner_inode_initial" ]] || fail 'lock exclusion replaced the lifecycle-lock inode'
[[ $(inode_of "$RUNTIME_DIR") == "$runtime_inode_initial" ]] || fail 'lock exclusion replaced the runtime-directory inode'
[[ $(sha256sum /var/lib/perimeterd/active.json | awk '{print $1}') == "$active_hash_before" ]] || fail 'lock exclusion changed the active revision'
assert_owned_rules
systemctl restart "$UNIT"
wait_active 90
wait_health 1 30
[[ $(inode_of "$OWNER_LOCK") == "$owner_inode_initial" ]] || fail 'systemd restart replaced the lifecycle-lock inode'
[[ $(inode_of "$XTABLES_LOCK") == "$xtables_inode_initial" ]] || fail 'systemd restart replaced the xtables-lock inode'
[[ $(inode_of "$RUNTIME_DIR") == "$runtime_inode_initial" ]] || fail 'systemd restart replaced the runtime-directory inode'
assert_owned_rules

install_restore_fault
active_hash_before=$(sha256sum /var/lib/perimeterd/active.json | awk '{print $1}')
write_config reject
systemctl reload "$UNIT"
wait_degraded
for _ in 1 2 3 4 5; do
  [[ $(show_property ActiveState) == active ]] || fail 'degraded enforcement terminated the systemd service'
  [[ $(health_value) == 0 ]] || fail 'degraded enforcement health recovered before the fault was removed'
  [[ -s /var/lib/perimeterd/journal.json ]] || fail 'degraded enforcement discarded its recovery journal'
  sleep 1
done
active_hash_degraded=$(sha256sum /var/lib/perimeterd/active.json | awk '{print $1}')
[[ "$active_hash_degraded" == "$active_hash_before" ]] || fail 'failed apply published a new active revision'

if [[ "$mode" == full ]]; then
  log 'Preserving a real pending-apply journal and exercising the production 75-minute stalled-startup deadline'
  systemctl stop "$UNIT"
  [[ -s /var/lib/perimeterd/journal.json ]] || fail 'stopping the degraded service discarded its recovery journal'
  rm -f /usr/local/sbin/{ip6tables,iptables}-restore "$MARKER_DIR/systemd-gate-fault" "$MARKER_DIR/systemd-gate-fault-hit"
  mkdir -p "$RESTART_DROPIN_DIR"
  cat >"$RESTART_DROPIN_DIR/90-systemd-gate-one-shot-start.conf" <<'EOF'
[Service]
Restart=no
EOF
  systemctl daemon-reload
  hold_xtables_lock
  stall_start=$SECONDS
  systemctl start --no-block "$UNIT"
  while ((SECONDS - stall_start < 93)); do
    state=$(show_property ActiveState)
    case "$state" in
      active) fail 'stalled recovery became ready before the xtables lock was released' ;;
      failed) journalctl -u "$UNIT" --no-pager -n 100; fail 'stalled recovery failed before the production startup deadline' ;;
    esac
    sleep 1
  done
  [[ $(show_property ActiveState) == activating ]] || fail 'systemd did not extend the stalled recovery beyond 90 seconds'
  stall_deadline=$((SECONDS + 76 * 60))
  while ((SECONDS < stall_deadline)); do
    state=$(show_property ActiveState)
    [[ "$state" == failed || "$state" == inactive ]] && break
    [[ "$state" == activating ]] || fail "unexpected stalled startup state: $state"
    sleep 10
  done
  elapsed=$((SECONDS - stall_start))
  state=$(show_property ActiveState)
  [[ "$state" == failed ]] || fail "stalled initialization was not terminated at the 75-minute startup bound (state=$state elapsed=${elapsed}s)"
  ((elapsed >= 74 * 60 && elapsed <= 76 * 60)) || fail "stalled startup terminated outside the 75-minute deadline window (${elapsed}s)"
  [[ -s /var/lib/perimeterd/journal.json ]] || fail 'startup timeout discarded the pending recovery journal'
  [[ -s /var/lib/perimeterd/active.json ]] || fail 'startup timeout discarded the active recovery record'
  [[ $(inode_of "$OWNER_LOCK") == "$owner_inode_initial" ]] || fail 'stalled startup replaced the lifecycle-lock inode'
  [[ $(inode_of "$XTABLES_LOCK") == "$xtables_inode_initial" ]] || fail 'stalled startup replaced the xtables-lock inode'
  [[ $(inode_of "$RUNTIME_DIR") == "$runtime_inode_initial" ]] || fail 'stalled startup replaced the runtime-directory inode'
  kill -TERM "$xtables_lock_pid" 2>/dev/null || true
  wait "$xtables_lock_pid" 2>/dev/null || true
  xtables_lock_pid=
  assert_owned_rules
  rm -f "$RESTART_DROPIN_DIR/90-systemd-gate-one-shot-start.conf"
  rmdir "$RESTART_DROPIN_DIR" 2>/dev/null || true
  systemctl daemon-reload
  systemctl reset-failed "$UNIT"
  start_service_and_wait 180
  wait_no_journal 30
  [[ $(inode_of "$OWNER_LOCK") == "$owner_inode_initial" ]] || fail 'startup recovery replaced the lifecycle-lock inode'
  [[ $(inode_of "$RUNTIME_DIR") == "$runtime_inode_initial" ]] || fail 'startup recovery replaced the runtime-directory inode'
else
  log 'Fast mode omits only the real 75-minute startup-bound wait; recovering the injected transaction normally'
  recover_degraded_state
fi

log 'Cleaning legacy service state before switching to the nf_tables tool family'
cleanup_service_state
set_variant nft
write_config drop
start_service_and_wait 90
systemctl restart "$UNIT"
wait_active 90
wait_health 1 30
[[ $(inode_of "$OWNER_LOCK") == "$owner_inode_initial" ]] || fail 'nf_tables-family restart replaced the lifecycle-lock inode'
[[ $(inode_of "$XTABLES_LOCK") == "$xtables_inode_initial" ]] || fail 'nf_tables-family restart replaced the xtables-lock inode'
[[ $(inode_of "$RUNTIME_DIR") == "$runtime_inode_initial" ]] || fail 'nf_tables-family restart replaced the runtime-directory inode'
assert_owned_rules

log 'Proving failed package removal preserves live recovery and ownership evidence'
install_restore_fault
write_config reject
systemctl reload "$UNIT"
wait_degraded
[[ -s /var/lib/perimeterd/journal.json ]] || fail 'removal-failure fixture has no recovery journal'
active_hash_degraded=$(sha256sum /var/lib/perimeterd/active.json | awk '{print $1}')
install_removal_lock_hook
if dpkg --remove perimeterd >/var/log/perimeterd-failed-remove.log 2>&1; then
  fail 'package removal succeeded while systemd deliberately held lifecycle ownership after stopping the service'
fi
remove_output=$(</var/log/perimeterd-failed-remove.log)
[[ "$remove_output" == *'already held'* || "$remove_output" == *'owner.lock'* ]] || fail "package removal failed for an unexpected reason: $remove_output"
[[ $(show_property ActiveState) == inactive ]] || fail 'failed package removal did not stop the service'
[[ $(systemctl show --property=ActiveState --value perimeterd-systemd-lock-holder.service) == active ]] || fail 'systemd did not acquire the post-stop lifecycle lock for the failed-removal scenario'
if flock -n "$OWNER_LOCK" -c true >/dev/null 2>&1; then
  fail 'failed-removal fixture did not retain lifecycle-lock exclusion'
fi
[[ -x /usr/bin/perimeterd ]] || fail 'failed removal deleted the installed binary'
[[ -f "$UNIT_FILE" ]] || fail 'failed removal deleted the installed systemd unit'
[[ -f "$CONFIG" ]] || fail 'failed removal deleted the installed configuration'
[[ -s /var/lib/perimeterd/journal.json ]] || fail 'failed removal discarded recovery journal evidence'
[[ -s /var/lib/perimeterd/active.json ]] || fail 'failed removal discarded active ownership metadata'
[[ $(sha256sum /var/lib/perimeterd/active.json | awk '{print $1}') == "$active_hash_degraded" ]] || fail 'failed removal changed active ownership metadata'
[[ $(inode_of "$OWNER_LOCK") == "$owner_inode_initial" ]] || fail 'failed removal replaced the lifecycle-lock inode'
[[ $(inode_of "$XTABLES_LOCK") == "$xtables_inode_initial" ]] || fail 'failed removal replaced the xtables-lock inode'
[[ $(inode_of "$RUNTIME_DIR") == "$runtime_inode_initial" ]] || fail 'failed removal replaced the runtime-directory inode'
assert_owned_rules

remove_removal_lock_hook
rm -f "$MARKER_DIR/systemd-gate-fault" "$MARKER_DIR/systemd-gate-fault-hit" /usr/local/sbin/{ip6tables,iptables}-restore
log 'Retrying final package removal without the injected lock failure'
dpkg --remove perimeterd
assert_no_owned_rules
require_absent /usr/bin/perimeterd
require_absent "$UNIT_FILE"
[[ $(inode_of "$XTABLES_LOCK") == "$xtables_inode_initial" ]] || fail 'successful package removal unlinked or replaced the shared xtables lock'
[[ $(inode_of "$OWNER_LOCK") == "$owner_inode_initial" ]] || fail 'successful package removal unlinked or replaced the lifecycle lock'
[[ $(inode_of "$RUNTIME_DIR") == "$runtime_inode_initial" ]] || fail 'successful package removal replaced the runtime-directory inode'
dpkg --purge perimeterd
[[ $(inode_of "$XTABLES_LOCK") == "$xtables_inode_initial" ]] || fail 'purge unlinked or replaced the shared xtables lock'
[[ $(inode_of "$OWNER_LOCK") == "$owner_inode_initial" ]] || fail 'purge unlinked or replaced the lifecycle lock'
[[ $(inode_of "$RUNTIME_DIR") == "$runtime_inode_initial" ]] || fail 'purge replaced the runtime-directory inode'
log 'PASS: installed systemd VM acceptance completed'
