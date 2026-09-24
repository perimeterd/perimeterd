#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: tests/systemd/run.sh [--fast] <deb-or-artifact-directory>

Boots a disposable Ubuntu 26.04 systemd VM, installs the amd64 DEB, and runs
its actual perimeterd.service under the packaged filesystem/capability sandbox.
The full gate waits for the production 75-minute startup deadline; --fast skips
only that slow stalled-startup case and still exercises the >90-second notify
activation scenario.

Host prerequisites: qemu-system-x86_64, qemu-img, cloud-localds,
ssh-keygen, ssh, scp, curl, sha256sum, and Python 3. On Ubuntu install them
with: sudo apt-get install cloud-image-utils qemu-system-x86 qemu-utils
openssh-client curl python3.

The VM uses QEMU user-mode networking, never a TAP/bridge on the host. Ubuntu's
pinned cloud image is cached at SYSTEMD_VM_IMAGE_CACHE (or
~/.cache/perimeterd/systemd); diagnostic logs are retained at
SYSTEMD_VM_OUTPUT_DIR (or /tmp/perimeterd-systemd-gate).
EOF
}

mode=full
package_arg=
while (($#)); do
  case "$1" in
    --fast)
      mode=fast
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      if (($# != 1)) || [[ -n "$package_arg" ]]; then
        usage >&2
        exit 2
      fi
      package_arg=$1
      shift
      ;;
    -* )
      usage >&2
      exit 2
      ;;
    *)
      if [[ -n "$package_arg" ]]; then
        usage >&2
        exit 2
      fi
      package_arg=$1
      shift
      ;;
  esac
done

if [[ -z "$package_arg" ]]; then
  usage >&2
  exit 2
fi

if [[ -d "$package_arg" ]]; then
  shopt -s nullglob
  package_matches=("$package_arg"/*amd64.deb)
  if ((${#package_matches[@]} != 1)); then
    printf 'expected exactly one amd64 DEB in %s, found %d\n' "$package_arg" "${#package_matches[@]}" >&2
    exit 2
  fi
  package_arg=${package_matches[0]}
fi
if [[ ! -f "$package_arg" || "$package_arg" != *amd64.deb ]]; then
  printf 'expected an existing amd64 .deb package, got %s\n' "$package_arg" >&2
  exit 2
fi
package_path=$(readlink -f -- "$package_arg")

for command_name in qemu-system-x86_64 qemu-img cloud-localds ssh-keygen ssh scp curl sha256sum python3; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    printf 'required host command %s is missing; install the systemd VM prerequisites listed by --help\n' "$command_name" >&2
    exit 2
  fi
done

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
guest_script="$repo_root/tests/systemd/guest.sh"
if [[ ! -x "$guest_script" ]]; then
  printf 'guest acceptance script is missing or not executable: %s\n' "$guest_script" >&2
  exit 2
fi

image_name=ubuntu-26.04-server-cloudimg-amd64.img
image_url=https://cloud-images.ubuntu.com/releases/resolute/release-20260918/$image_name
image_sha256=4908fb59ccd4e87ae4e8e973b7ef56f535448eacb24a87fd787270c0048987bc
cache_dir=${SYSTEMD_VM_IMAGE_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/perimeterd/systemd}
mkdir -p -- "$cache_dir"
image_path="$cache_dir/$image_name"
if [[ ! -e "$image_path" ]]; then
  partial_path="$image_path.partial.$$"
  trap 'rm -f -- "$partial_path"' EXIT
  curl --fail --location --retry 3 --retry-all-errors --connect-timeout 20 --max-time 1800 \
    "$image_url" --output "$partial_path"
  printf '%s  %s\n' "$image_sha256" "$partial_path" | sha256sum --check --strict
  mv -- "$partial_path" "$image_path"
  trap - EXIT
fi
printf '%s  %s\n' "$image_sha256" "$image_path" | sha256sum --check --strict

output_root=${SYSTEMD_VM_OUTPUT_DIR:-${TMPDIR:-/tmp}/perimeterd-systemd-gate}
mkdir -p -- "$output_root"
output_dir=$(mktemp -d "$output_root/run.XXXXXXXX")
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/perimeterd-systemd-vm.XXXXXXXX")
serial_log="$output_dir/serial.log"
qemu_log="$output_dir/qemu.log"
guest_log="$output_dir/guest-gate.log"
qemu_pid=

cleanup() {
  local result=$?
  if [[ -n "$qemu_pid" ]] && kill -0 "$qemu_pid" 2>/dev/null; then
    kill -TERM "$qemu_pid" 2>/dev/null || true
    wait "$qemu_pid" 2>/dev/null || true
  fi
  rm -rf -- "$work_dir"
  printf 'Systemd VM diagnostics: %s\n' "$output_dir"
  return "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

ssh_key="$work_dir/id_ed25519"
ssh-keygen -q -t ed25519 -N '' -C perimeterd-systemd-gate -f "$ssh_key"
public_key=$(<"$ssh_key.pub")
cat >"$work_dir/user-data" <<EOF
#cloud-config
users:
  - name: perimeterd-gate
    gecos: Perimeterd systemd acceptance
    groups: [adm, sudo]
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: true
    ssh_authorized_keys:
      - '$public_key'
ssh_pwauth: false
disable_root: true
EOF
instance_id="perimeterd-systemd-$(date -u +%s)-$$"
printf 'instance-id: %s\nlocal-hostname: perimeterd-systemd-gate\n' "$instance_id" >"$work_dir/meta-data"
cloud-localds "$work_dir/seed.iso" "$work_dir/user-data" "$work_dir/meta-data"
qemu-img create -q -f qcow2 -F qcow2 -b "$image_path" "$work_dir/guest.qcow2" 16G

ssh_port=$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)
accel=tcg
if [[ -r /dev/kvm && -w /dev/kvm ]]; then
  accel=kvm
fi
qemu-system-x86_64 \
  -machine q35 \
  -accel "$accel" \
  -cpu max \
  -smp 2 \
  -m 4096 \
  -boot order=c,menu=off \
  -drive "if=virtio,format=qcow2,file=$work_dir/guest.qcow2" \
  -drive "file=$work_dir/seed.iso,format=raw,media=cdrom,readonly=on" \
  -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$ssh_port-:22" \
  -device virtio-net-pci,netdev=net0 \
  -serial "file:$serial_log" \
  -monitor none \
  -display none \
  -no-reboot >"$qemu_log" 2>&1 &
qemu_pid=$!

ssh_options=(
  -i "$ssh_key"
  -p "$ssh_port"
  -o BatchMode=yes
  -o ConnectTimeout=5
  -o ConnectionAttempts=1
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o LogLevel=ERROR
  -o ServerAliveInterval=15
  -o ServerAliveCountMax=4
)
ssh_command=(ssh "${ssh_options[@]}" "perimeterd-gate@127.0.0.1")
scp_options=(
  -i "$ssh_key"
  -P "$ssh_port"
  -o BatchMode=yes
  -o ConnectTimeout=5
  -o ConnectionAttempts=1
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o LogLevel=ERROR
)

printf 'Booting Ubuntu 26.04 VM with QEMU %s; package=%s mode=%s\n' "$accel" "$package_path" "$mode"
printf 'Pinned image SHA-256: %s\n' "$image_sha256" >"$output_dir/image.sha256"
ssh_deadline=$((SECONDS + 600))
while ((SECONDS < ssh_deadline)); do
  if ! kill -0 "$qemu_pid" 2>/dev/null; then
    printf 'QEMU exited before guest SSH became available\n' >&2
    cat "$qemu_log" "$serial_log" 2>/dev/null || true
    exit 1
  fi
  if "${ssh_command[@]}" true >/dev/null 2>&1; then
    break
  fi
  sleep 5
done
if ((SECONDS >= ssh_deadline)); then
  printf 'guest SSH did not become available within 10 minutes\n' >&2
  cat "$qemu_log" "$serial_log" 2>/dev/null || true
  exit 1
fi

"${ssh_command[@]}" sudo -n cloud-init status --wait
scp "${scp_options[@]}" "$package_path" "perimeterd-gate@127.0.0.1:/tmp/perimeterd.deb"
scp "${scp_options[@]}" "$guest_script" "perimeterd-gate@127.0.0.1:/tmp/perimeterd-systemd-gate.sh"
"${ssh_command[@]}" sudo -n chmod 0700 /tmp/perimeterd-systemd-gate.sh
printf 'Running real package/systemd acceptance in the disposable VM\n'
"${ssh_command[@]}" sudo -n bash /tmp/perimeterd-systemd-gate.sh "$mode" /tmp/perimeterd.deb 2>&1 | tee "$guest_log"
printf 'PASS: installed systemd package gate (%s mode)\n' "$mode"
