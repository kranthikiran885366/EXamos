#!/usr/bin/env bash
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$(cd "$SCRIPT_DIR/../../.." && pwd)"
EVIDENCE_ROOT="$WORKSPACE/tests/virtual-hardware/evidence"
RUN_DIR="${EXAMOS_VH_RUN_DIR:-}"
START_IN_PROGRESS=0

fail() {
    printf '[VH-VM] FAIL: %s\n' "$*" >&2
    exit 1
}

blocked() {
    printf '[VH-VM] BLOCKED: %s\n' "$*" >&2
    exit 2
}

require_run_dir() {
    [[ -n "$RUN_DIR" ]] || blocked "EXAMOS_VH_RUN_DIR must identify one evidence run."
    [[ ! -L "$RUN_DIR" ]] || fail "Run directory may not be a symlink."
    mkdir -p -- "$EVIDENCE_ROOT"
    RUN_DIR="$(realpath -m -- "$RUN_DIR")"
    case "$RUN_DIR" in
        "$EVIDENCE_ROOT"/*) ;;
        *) fail "Run directory must be below $EVIDENCE_ROOT." ;;
    esac
    [[ -d "$RUN_DIR" ]] || blocked "Run directory does not exist: $RUN_DIR"
}

active_epoch() {
    local name
    [[ -f "$RUN_DIR/active-epoch" ]] || return 1
    IFS= read -r name < "$RUN_DIR/active-epoch"
    [[ "$name" =~ ^epoch-[0-9]{3,}$ ]] || fail "Invalid active-epoch marker."
    [[ -d "$RUN_DIR/$name" ]] || fail "The active VM epoch is missing."
    printf '%s\n' "$RUN_DIR/$name"
}

choose_firmware() {
    local code vars
    for pair in \
        "/usr/share/OVMF/OVMF_CODE_4M.fd|/usr/share/OVMF/OVMF_VARS_4M.fd" \
        "/usr/share/OVMF/OVMF_CODE.fd|/usr/share/OVMF/OVMF_VARS.fd" \
        "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd|/usr/share/OVMF/OVMF_VARS_4M.ms.fd"; do
        code="${pair%%|*}"
        vars="${pair#*|}"
        if [[ -f "$code" && -f "$vars" ]]; then
            printf '%s\n%s\n' "$code" "$vars"
            return 0
        fi
    done
    return 1
}

create_epoch() {
    local epoch_number="$1"
    local epoch_name epoch_dir raw code vars ram cpu_count base_hash
    epoch_name="$(printf 'epoch-%03d' "$epoch_number")"
    epoch_dir="$RUN_DIR/$epoch_name"
    [[ ! -e "$epoch_dir" && ! -L "$epoch_dir" ]] ||
        fail "Refusing to overwrite existing VM state: $epoch_dir"

    raw="${EXAMOS_VH_IMAGE:-$WORKSPACE/image/examos.raw}"
    [[ "$raw" = /* ]] || raw="$WORKSPACE/$raw"
    [[ -f "$raw" && ! -L "$raw" ]] ||
        blocked "Selected raw SPPIO image is unavailable or is not a regular file."
    raw="$(realpath -e -- "$raw")"
    command -v qemu-img >/dev/null 2>&1 || blocked "qemu-img is required."
    command -v qemu-system-x86_64 >/dev/null 2>&1 || blocked "QEMU is required."
    command -v swtpm >/dev/null 2>&1 || blocked "swtpm is required."

    mapfile -t firmware < <(choose_firmware) ||
        blocked "A matching OVMF code/variable template pair was not found."
    [[ "${#firmware[@]}" -eq 2 ]] || blocked "Could not select an OVMF firmware pair."
    code="${firmware[0]}"
    vars="${firmware[1]}"
    ram="${EXAMOS_VH_RAM_MB:-2048}"
    cpu_count="${EXAMOS_VH_CPUS:-2}"
    [[ "$ram" =~ ^[0-9]+$ && "$ram" -ge 1024 && "$ram" -le 8192 ]] ||
        fail "EXAMOS_VH_RAM_MB must be between 1024 and 8192."
    [[ "$cpu_count" =~ ^[1-9][0-9]?$ && "$cpu_count" -le 8 ]] ||
        fail "EXAMOS_VH_CPUS must be between 1 and 8."

    mkdir -m 700 -- "$epoch_dir"
    mkdir -m 700 -- "$epoch_dir/tpm"
    cp -- "$vars" "$epoch_dir/OVMF_VARS.fd"
    chmod 600 "$epoch_dir/OVMF_VARS.fd"
    qemu-img create -f qcow2 -F raw -b "$raw" "$epoch_dir/disk-overlay.qcow2" >/dev/null

    base_hash=""
    if [[ -n "${EXAMOS_VH_BASE_HASH:-}" ]]; then
        base_hash="$EXAMOS_VH_BASE_HASH"
    elif [[ "$raw" == "$(realpath -e -- "$WORKSPACE/image/examos.raw" 2>/dev/null || true)" &&
          -f "$RUN_DIR/reports/toolchain-inventory.json" ]]; then
        base_hash="$(python3 - "$RUN_DIR/reports/toolchain-inventory.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    print(json.load(stream)["images"]["examos.raw"].get("sha256", ""))
PY
)"
    fi
    if [[ -z "$base_hash" ]]; then
        base_hash="$(sha256sum "$raw" | awk '{print $1}')"
    fi

    python3 - "$epoch_dir/vm.json" "$raw" "$epoch_dir/disk-overlay.qcow2" \
        "$code" "$epoch_dir/OVMF_VARS.fd" \
        "$ram" "$cpu_count" "$base_hash" <<'PY'
import hashlib
import json
import pathlib
import sys
from datetime import datetime, timezone

(
    target, raw, overlay, code, variables, ram, cpus, raw_hash,
) = sys.argv[1:]
def digest(path):
    h = hashlib.sha256()
    with pathlib.Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

record = {
    "schema": "sppio.virtual-hardware.vm.v2",
    "created_at_utc": datetime.now(timezone.utc).isoformat(),
    "machine": "q35",
    "cpu_model": "host-if-kvm-else-max",
    "memory_mib": int(ram),
    "cpus": int(cpus),
    "base_image": raw,
    "base_image_format": "raw",
    "base_image_sha256": raw_hash,
    "overlay_image": overlay,
    "overlay_format": "qcow2",
    "overlay_backing_is_read_only_source": True,
    "ovmf_code": code,
    "ovmf_code_sha256": digest(code),
    "ovmf_variables": variables,
    "ovmf_variables_sha256_initial": digest(variables),
    "tpm": {
        "implementation": "swtpm",
        "version": "2.0",
        "state_directory": str(pathlib.Path(overlay).parent / "tpm"),
        "server_transport": "private-unixio-socket",
        "control_transport": "private-unixio-socket",
        "physical_tpm_used": False,
    },
    "network": "none",
    "monitor": "disabled",
    "boot": "UEFI OVMF; existing SPPIO disk via disposable qcow2 overlay",
}
with pathlib.Path(target).open("x", encoding="utf-8") as stream:
    json.dump(record, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY
    printf '%s\n' "$epoch_name" > "$RUN_DIR/active-epoch.tmp"
    mv -- "$RUN_DIR/active-epoch.tmp" "$RUN_DIR/active-epoch"
    printf '[VH-VM] Created isolated state %s (base image unchanged).\n' "$epoch_name"
}

pid_is_ours() {
    local pid="$1" needle="$2"
    [[ "$pid" =~ ^[0-9]+$ && -r "/proc/$pid/cmdline" ]] || return 1
    tr '\0' ' ' < "/proc/$pid/cmdline" | grep -Fq -- "$needle"
}

process_running() {
    local pid="$1" state
    [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null || return 1
    state="$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null || true)"
    [[ -n "$state" && "$state" != "Z" ]]
}

start_one() {
    local kind="$1" accel="$2" epoch_dir="$3" json_file="$4"
    local qemu memory cpus code vars disk control_dir server_socket control_socket
    local display_args=()
    mapfile -t fields < <(python3 - "$json_file" "$kind" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    data = json.load(stream)
if sys.argv[2] == "tpm":
    values = [
        data["tpm"]["state_directory"],
    ]
else:
    values = [
        data["memory_mib"],
        data["cpus"],
        data["ovmf_code"],
        data["ovmf_variables"],
        data["overlay_image"],
    ]
for value in values:
    print(value)
PY
)
    if [[ "$kind" == "tpm" ]]; then
        local state_dir="${fields[0]}"
        control_dir="$(mktemp -d /tmp/sppio-vh-XXXXXX)" ||
            fail "Could not create a private short TPM socket directory."
        server_socket="$control_dir/swtpm.sock"
        control_socket="$server_socket.ctrl"
        printf '%s\n' "$control_dir" > "$epoch_dir/tpm-socket-directory"
        nohup swtpm socket --tpm2 --tpmstate "dir=$state_dir" \
            --server "type=unixio,path=$server_socket" \
            --ctrl "type=unixio,path=$control_socket" \
            --flags not-need-init,startup-clear \
            > "$epoch_dir/swtpm.log" 2>&1 </dev/null &
        printf '%s\n' "$!" > "$epoch_dir/swtpm.pid"
        local swtpm_pid
        swtpm_pid="$(cat "$epoch_dir/swtpm.pid")"
        for _ in $(seq 1 50); do
            process_running "$swtpm_pid" ||
                fail "swtpm exited; inspect $epoch_dir/swtpm.log."
            [[ -S "$server_socket" && -S "$control_socket" ]] && break
            sleep 0.1
        done
        [[ -S "$server_socket" && -S "$control_socket" ]] ||
            fail "swtpm did not create both Unix sockets; inspect $epoch_dir/swtpm.log."
        if ! TPM2TOOLS_TCTI="swtpm:path=$server_socket" \
            tpm2_startup -c > "$epoch_dir/tpm-startup.log" 2>&1; then
            if ! grep -qiE 'already|initialized|initialize' "$epoch_dir/tpm-startup.log"; then
                fail "The virtual TPM did not complete startup."
            fi
        fi
        TPM2TOOLS_TCTI="swtpm:path=$server_socket" \
            tpm2_getcap properties-fixed > "$epoch_dir/tpm-capabilities.txt" 2>&1 ||
            fail "The virtual TPM did not answer a TPM 2.0 capability query."
        return
    fi

    memory="${fields[0]}"
    cpus="${fields[1]}"
    code="${fields[2]}"
    vars="${fields[3]}"
    disk="${fields[4]}"
    control_dir="$(tpm_socket_directory "$epoch_dir")" ||
        fail "The TPM Unix socket directory record is missing or invalid; reset this VM epoch."
    server_socket="$control_dir/swtpm.sock"
    control_socket="$server_socket.ctrl"
    [[ -S "$server_socket" && -S "$control_socket" ]] ||
        fail "The TPM Unix sockets are unavailable; stop and restart the VM."
    qemu="$(command -v qemu-system-x86_64)"
    local cpu_model
    if [[ "$accel" == "kvm" ]]; then
        cpu_model="host"
    else
        cpu_model="max"
    fi

    local display_backend="${EXAMOS_VH_DISPLAY:-none}"
    case "$display_backend" in
        none) display_args=(-display none) ;;
        gtk) display_args=(-vga std -display gtk) ;;
        vnc) display_args=(-vga std -display vnc=127.0.0.1:0) ;;
        *) fail "EXAMOS_VH_DISPLAY must be none, gtk, or vnc." ;;
    esac

    # QEMU uses the UnixIO control channel; TPM tools use the server socket.
    nohup "$qemu" -name "sppio-vh-$(basename "$RUN_DIR")" -machine q35 -boot order=c \
        -accel "$accel" -cpu "$cpu_model" -m "$memory" -smp "$cpus" \
        -drive "if=pflash,unit=0,format=raw,readonly=on,file=$code" \
        -drive "if=pflash,unit=1,format=raw,file=$vars" \
        -chardev "socket,id=chrtpm,path=$server_socket" \
        -tpmdev "emulator,id=tpm0,chardev=chrtpm" \
        -device tpm-tis,tpmdev=tpm0 \
        -device qemu-xhci \
        -drive "file=$disk,format=qcow2,if=virtio" \
        -nic none "${display_args[@]}" -monitor none \
        -serial "file:$epoch_dir/serial.log" -no-reboot \
        > "$epoch_dir/qemu-$accel.log" 2>&1 </dev/null &
    printf '%s\n' "$!" > "$epoch_dir/qemu.pid"
    sleep 2
    kill -0 "$(cat "$epoch_dir/qemu.pid")" 2>/dev/null
}

start_vm() {
    local epoch_dir json_file accel_request accel_help display_backend manifest_schema
    local control_dir server_socket control_socket
    epoch_dir="$(active_epoch)" || blocked "Create a VM state first."
    json_file="$epoch_dir/vm.json"
    [[ -f "$json_file" ]] || fail "VM manifest is missing."
    manifest_schema="$(python3 - "$json_file" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    print(json.load(stream).get("schema", ""))
PY
)"
    [[ "$manifest_schema" == "sppio.virtual-hardware.vm.v2" ]] ||
        blocked "This VM epoch uses an incompatible manifest; stop it and create a fresh epoch with reset-test-vm.sh."
    [[ -f "$epoch_dir/qemu.pid" ]] && process_running "$(cat "$epoch_dir/qemu.pid")" &&
        fail "QEMU is already running."
    [[ -f "$epoch_dir/swtpm.pid" ]] && process_running "$(cat "$epoch_dir/swtpm.pid")" &&
        fail "swtpm is already running."

    accel_request="${EXAMOS_VH_ACCEL:-auto}"
    case "$accel_request" in auto|kvm|tcg) ;; *) fail "EXAMOS_VH_ACCEL must be auto, kvm, or tcg." ;; esac
    display_backend="${EXAMOS_VH_DISPLAY:-none}"
    case "$display_backend" in none|gtk|vnc) ;; *) fail "EXAMOS_VH_DISPLAY must be none, gtk, or vnc." ;; esac
    accel_help="$(qemu-system-x86_64 -accel help 2>&1 || true)"
    START_IN_PROGRESS=1
    if [[ "$accel_request" == "kvm" || ( "$accel_request" == "auto" &&
        -w /dev/kvm && "$accel_help" == *kvm* ) ]]; then
        start_one tpm kvm "$epoch_dir" "$json_file"
        if start_one qemu kvm "$epoch_dir" "$json_file"; then
            printf 'kvm\n' > "$epoch_dir/acceleration"
        else
            printf '[VH-VM] KVM startup failed; falling back to QEMU TCG.\n' | tee "$epoch_dir/kvm-fallback.txt"
            local pid
            pid="$(cat "$epoch_dir/qemu.pid" 2>/dev/null || true)"
            if [[ -n "$pid" ]] && pid_is_ours "$pid" "$RUN_DIR"; then
                kill -TERM "$pid" 2>/dev/null || true
                sleep 1
                wait "$pid" 2>/dev/null || true
            fi
            rm -f -- "$epoch_dir/qemu.pid"
            [[ "$accel_request" == "kvm" ]] && blocked "KVM was explicitly requested but could not start."
            start_one qemu tcg "$epoch_dir" "$json_file" ||
                blocked "Neither KVM nor TCG could start the QEMU guest."
            printf 'tcg\n' > "$epoch_dir/acceleration"
        fi
    else
        [[ "$accel_request" != "kvm" ]] ||
            blocked "KVM is unavailable in this WSL environment."
        start_one tpm tcg "$epoch_dir" "$json_file"
        start_one qemu tcg "$epoch_dir" "$json_file" ||
            blocked "QEMU TCG could not start the guest."
        printf 'tcg\n' > "$epoch_dir/acceleration"
    fi
    control_dir="$(tpm_socket_directory "$epoch_dir")" ||
        fail "The TPM Unix socket directory record is missing or invalid after startup."
    server_socket="$control_dir/swtpm.sock"
    control_socket="$server_socket.ctrl"
    python3 - "$epoch_dir/vm-runtime.json" "$(cat "$epoch_dir/acceleration")" \
        "$(cat "$epoch_dir/qemu.pid")" "$(cat "$epoch_dir/swtpm.pid")" \
        "${EXAMOS_VH_DISPLAY:-none}" "$server_socket" "$control_socket" <<'PY'
import json
import pathlib
import sys
from datetime import datetime, timezone

path, accel, qemu_pid, swtpm_pid, display_backend, server_socket, control_socket = sys.argv[1:]
record = {
    "started_at_utc": datetime.now(timezone.utc).isoformat(),
    "acceleration": accel,
    "qemu_pid": int(qemu_pid),
    "swtpm_pid": int(swtpm_pid),
    "tpm_server_transport": "private-unixio-socket",
    "tpm_server_socket": server_socket,
    "tpm_control_transport": "private-unixio-socket",
    "tpm_control_socket": control_socket,
    "network": "none",
    "monitor": "disabled",
    "display": "vnc-loopback" if display_backend == "vnc" else display_backend,
}
with pathlib.Path(path).open("w", encoding="utf-8") as stream:
    json.dump(record, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY
    printf '[VH-VM] QEMU and swtpm started with %s acceleration; network and monitor are disabled.\n' \
        "$(cat "$epoch_dir/acceleration")"
    START_IN_PROGRESS=0
}

stop_process() {
    local name="$1" pid_file="$2" pid=""
    [[ -f "$pid_file" ]] || return 0
    pid="$(cat "$pid_file")"
    [[ "$pid" =~ ^[0-9]+$ ]] || fail "Invalid $name PID file."
    if ! process_running "$pid"; then
        return 0
    fi
    pid_is_ours "$pid" "$RUN_DIR" || fail "Refusing to stop PID $pid; it is not owned by this test run."
    kill -TERM "$pid"
    for _ in $(seq 1 40); do
        process_running "$pid" || return 0
        sleep 0.25
    done
    pid_is_ours "$pid" "$RUN_DIR" ||
        fail "PID $pid changed identity; refusing forceful termination."
    kill -KILL "$pid"
    for _ in $(seq 1 20); do
        process_running "$pid" || return 0
        sleep 0.25
    done
    fail "$name PID $pid did not stop."
}

tpm_socket_directory() {
    local epoch_dir="$1" record="$1/tpm-socket-directory" control_dir
    [[ ! -L "$record" ]] || fail "Refusing to follow a TPM socket-directory record symlink."
    [[ -f "$record" ]] || return 1
    IFS= read -r control_dir < "$record"
    [[ "$control_dir" =~ ^/tmp/sppio-vh-[[:alnum:]]{6}$ ]] ||
        fail "Refusing to use an invalid TPM socket directory."
    printf '%s\n' "$control_dir"
}

cleanup_tpm_sockets() {
    local epoch_dir="$1" record="$1/tpm-socket-directory" control_dir server_socket control_socket unexpected
    [[ ! -L "$record" ]] || fail "Refusing to follow a TPM socket-directory record symlink."
    [[ -f "$record" ]] || return 0
    control_dir="$(tpm_socket_directory "$epoch_dir")" ||
        fail "Refusing to clean an invalid TPM socket directory."
    server_socket="$control_dir/swtpm.sock"
    control_socket="$server_socket.ctrl"
    if [[ -e "$control_dir" || -L "$control_dir" ]]; then
        [[ -d "$control_dir" && ! -L "$control_dir" ]] ||
            fail "Refusing to clean a TPM socket path that is not a real directory."
        [[ "$(stat -c '%u' "$control_dir")" == "$(id -u)" ]] ||
            fail "Refusing to clean a TPM socket directory owned by another user."
        if [[ -L "$server_socket" || -L "$control_socket" ||
            ( -e "$server_socket" && ! -S "$server_socket" ) ||
            ( -e "$control_socket" && ! -S "$control_socket" ) ]]; then
            fail "Refusing to remove an unexpected TPM socket path."
        fi
        unexpected="$(find "$control_dir" -mindepth 1 -maxdepth 1 \
            ! -name swtpm.sock ! -name swtpm.sock.ctrl -print -quit)"
        [[ -z "$unexpected" ]] ||
            fail "Refusing to remove unexpected data in the TPM socket directory."
        rm -f -- "$server_socket" "$control_socket"
        rmdir -- "$control_dir"
    fi
    rm -f -- "$record"
}

stop_vm() {
    local epoch_dir
    epoch_dir="$(active_epoch)" || blocked "Create a VM state first."
    stop_process qemu "$epoch_dir/qemu.pid"
    stop_process swtpm "$epoch_dir/swtpm.pid"
    cleanup_tpm_sockets "$epoch_dir"
    if [[ -f "$epoch_dir/vm-runtime.json" ]]; then
        python3 - "$epoch_dir/vm-runtime.json" <<'PY'
import json
import pathlib
import sys
from datetime import datetime, timezone

path = pathlib.Path(sys.argv[1])
record = json.loads(path.read_text(encoding="utf-8"))
record["stopped_at_utc"] = datetime.now(timezone.utc).isoformat()
record["running"] = False
with path.open("w", encoding="utf-8") as stream:
    json.dump(record, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY
    fi
    printf '[VH-VM] Stopped only processes recorded for %s; TPM and firmware state were preserved.\n' \
        "$epoch_dir"
}

stop_qemu() {
    local epoch_dir qemu_pid swtpm_pid control_dir server_socket control_socket state_dir json_file
    epoch_dir="$(active_epoch)" || blocked "Create a VM state first."

    # ── 1. Stop QEMU ─────────────────────────────────────────────────────
    # Kill QEMU first to release its exclusive connection to the swtpm
    # control socket ($server_socket.ctrl).
    [[ -f "$epoch_dir/qemu.pid" ]] || fail "QEMU PID record is missing."
    qemu_pid="$(cat "$epoch_dir/qemu.pid")"
    [[ "$qemu_pid" =~ ^[0-9]+$ ]] || fail "Invalid QEMU PID record."
    if process_running "$qemu_pid"; then
        pid_is_ours "$qemu_pid" "$RUN_DIR" ||
            fail "Refusing to stop QEMU PID $qemu_pid; it is not owned by this test run."
        if ! kill -KILL "$qemu_pid" 2>/dev/null && process_running "$qemu_pid"; then
            fail "Could not terminate QEMU PID $qemu_pid to release the TPM connection."
        fi
        for _ in $(seq 1 40); do
            process_running "$qemu_pid" || break
            sleep 0.1
        done
        process_running "$qemu_pid" &&
            fail "QEMU PID $qemu_pid did not stop; TPM state was not saved."
    fi

    # ── 2. Persist volatile state (PCR values) ───────────────────────────
    # With QEMU disconnected, the control socket is now free.
    # Force swtpm to persist its volatile state (containing measured boot PCRs)
    # to disk via swtpm_ioctl -v.
    control_dir="$(tpm_socket_directory "$epoch_dir")" ||
        fail "The TPM Unix socket directory record is missing or invalid."
    server_socket="$control_dir/swtpm.sock"
    control_socket="$server_socket.ctrl"
    [[ -d "$control_dir" && ! -L "$control_dir" ]] ||
        fail "The recorded TPM socket directory is unavailable or unsafe."
    [[ "$(stat -c '%u' "$control_dir")" == "$(id -u)" ]] ||
        fail "The recorded TPM socket directory is owned by another user."
    [[ -S "$server_socket" && ! -L "$server_socket" &&
       -S "$control_socket" && ! -L "$control_socket" ]] ||
        fail "The TPM server/control sockets are unavailable; volatile state cannot be saved."
    [[ -f "$epoch_dir/swtpm.pid" ]] || fail "swtpm PID record is missing."
    swtpm_pid="$(cat "$epoch_dir/swtpm.pid")"
    [[ "$swtpm_pid" =~ ^[0-9]+$ ]] || fail "Invalid swtpm PID record."
    process_running "$swtpm_pid" ||
        fail "Recorded swtpm PID $swtpm_pid is not running; volatile state cannot be saved."
    pid_is_ours "$swtpm_pid" "$RUN_DIR" ||
        fail "Refusing to control swtpm PID $swtpm_pid; it is not owned by this test run."

    printf '[VH-VM] Persisting swtpm volatile state to disk …\n'
    if ! swtpm_ioctl --unix "$control_socket" -v \
        >"$epoch_dir/swtpm-ioctl-save.log" 2>&1; then
        cat "$epoch_dir/swtpm-ioctl-save.log" >&2
        fail "swtpm_ioctl could not persist volatile TPM state; refusing to continue."
    fi
    printf '[VH-VM] swtpm volatile state (PCR measurements) saved successfully.\n'

    # ── 3. Restart swtpm with preserved volatile state ────────────────────
    # Kill the swtpm process that was attached to QEMU so it releases any
    # stale client state, and restart it with --flags not-need-init,startup-state
    # so it cleanly reloads the saved volatile state (containing measured boot PCRs).
    if ! kill -KILL "$swtpm_pid" 2>/dev/null && process_running "$swtpm_pid"; then
        fail "Could not stop the original swtpm process after saving its volatile state."
    fi
    for _ in $(seq 1 40); do
        process_running "$swtpm_pid" || break
        sleep 0.1
    done
    process_running "$swtpm_pid" &&
        fail "Original swtpm PID $swtpm_pid did not stop; refusing to start a second TPM."

    json_file="$epoch_dir/vm.json"
    [[ -f "$json_file" && ! -L "$json_file" ]] || fail "VM metadata is missing or unsafe."
    state_dir="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["tpm"]["state_directory"])' "$json_file")" ||
        fail "Could not read the recorded TPM state directory."
    [[ -d "$state_dir" && ! -L "$state_dir" ]] ||
        fail "The recorded TPM state directory is unavailable or unsafe."
    [[ ! -L "$server_socket" && ( ! -e "$server_socket" || -S "$server_socket" ) &&
       ! -L "$control_socket" && ( ! -e "$control_socket" || -S "$control_socket" ) ]] ||
        fail "Unexpected data remains at a TPM socket path after the original swtpm stopped."
    rm -f -- "$server_socket" "$control_socket"
    server_socket="$control_dir/swtpm.sock"
    control_socket="$server_socket.ctrl"
    nohup swtpm socket --tpm2 --tpmstate "dir=$state_dir" \
        --server "type=unixio,path=$server_socket" \
        --ctrl "type=unixio,path=$control_socket" \
        --flags not-need-init,startup-state \
        > "$epoch_dir/swtpm.log" 2>&1 </dev/null &
    printf '%s\n' "$!" > "$epoch_dir/swtpm.pid"
    swtpm_pid="$(cat "$epoch_dir/swtpm.pid")"
    pid_is_ours "$swtpm_pid" "$RUN_DIR" ||
        fail "Restarted swtpm process is not owned by this test run."
    for _ in $(seq 1 50); do
        swtpm_pid="$(cat "$epoch_dir/swtpm.pid")"
        if ! process_running "$swtpm_pid"; then
            cat "$epoch_dir/swtpm.log" >&2
            fail "swtpm exited while restarting with preserved state."
        fi
        [[ -S "$server_socket" && -S "$control_socket" ]] && break
        sleep 0.1
    done
    [[ -S "$server_socket" && -S "$control_socket" ]] ||
        fail "swtpm did not restart with preserved state; inspect $epoch_dir/swtpm.log."

    # Resume the TPM from preserved state without clearing PCRs
    if ! TPM2TOOLS_TCTI="swtpm:path=$server_socket" tpm2_startup \
        >"$epoch_dir/tpm-startup-resume.log" 2>&1; then
        if ! grep -qiE 'TPM_RC_INITIALIZE|TPM error: 0x100|already initialized' \
            "$epoch_dir/tpm-startup-resume.log"; then
            cat "$epoch_dir/tpm-startup-resume.log" >&2
            fail "TPM startup failed for a reason other than the expected already-initialized state."
        fi
        printf '[VH-VM] TPM was already initialized from preserved volatile state.\n'
    fi
    TPM2TOOLS_TCTI="swtpm:path=$server_socket" tpm2_getcap properties-fixed \
        >"$epoch_dir/tpm-resume-capabilities.txt" 2>&1 ||
        fail "Restarted TPM did not answer a capability query; preserved state is unusable."

    if [[ -f "$epoch_dir/vm-runtime.json" ]]; then
        python3 - "$epoch_dir/vm-runtime.json" "$(cat "$epoch_dir/swtpm.pid")" "$server_socket" "$control_socket" <<'PY'
import json
import pathlib
import sys
from datetime import datetime, timezone

path = pathlib.Path(sys.argv[1])
record = json.loads(path.read_text(encoding="utf-8"))
record["qemu_stopped_at_utc"] = datetime.now(timezone.utc).isoformat()
record["qemu_running"] = False
record["swtpm_pid"] = int(sys.argv[2])
record["tpm_server_socket"] = sys.argv[3]
record["tpm_control_socket"] = sys.argv[4]
with path.open("w", encoding="utf-8") as stream:
    json.dump(record, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY
    fi
    printf '[VH-VM] Stopped QEMU while preserving the recorded swtpm state under %s.\n' \
        "$epoch_dir"
}

check_vm() {
    local epoch_dir
    epoch_dir="$(active_epoch)" || blocked "Create a VM state first."
    [[ -f "$epoch_dir/qemu.pid" && -f "$epoch_dir/swtpm.pid" ]] ||
        fail "QEMU/swtpm PID records are missing."
    pid_is_ours "$(cat "$epoch_dir/qemu.pid")" "$RUN_DIR" ||
        fail "Recorded QEMU process is not running for this test run."
    pid_is_ours "$(cat "$epoch_dir/swtpm.pid")" "$RUN_DIR" ||
        fail "Recorded swtpm process is not running for this test run."
    printf '[VH-VM] QEMU and swtpm are running; state remains under %s.\n' "$epoch_dir"
}

reset_vm() {
    local current number
    current="$(active_epoch)" || blocked "Create a VM state before resetting it."
    if [[ -f "$current/qemu.pid" ]] && process_running "$(cat "$current/qemu.pid")"; then
        fail "Stop the VM before creating a fresh state epoch."
    fi
    if [[ -f "$current/swtpm.pid" ]] && process_running "$(cat "$current/swtpm.pid")"; then
        fail "Stop swtpm before creating a fresh state epoch."
    fi
    cleanup_tpm_sockets "$current"
    number=$((10#$(basename "$current" | sed 's/^epoch-//') + 1))
    create_epoch "$number"
    printf '[VH-VM] Reset created a new epoch; previous TPM/NVRAM/evidence were retained.\n'
}

cleanup_failed_start() {
    local rc=$?
    if [[ "$START_IN_PROGRESS" -eq 1 ]]; then
        local epoch_dir
        epoch_dir="$(active_epoch 2>/dev/null || true)"
        if [[ -n "$epoch_dir" ]]; then
            if ! stop_process qemu "$epoch_dir/qemu.pid"; then
                printf '[VH-VM] Cleanup warning: QEMU could not be stopped safely.\n' >&2
            fi
            if ! stop_process swtpm "$epoch_dir/swtpm.pid"; then
                printf '[VH-VM] Cleanup warning: swtpm could not be stopped safely.\n' >&2
            fi
            if ! cleanup_tpm_sockets "$epoch_dir"; then
                printf '[VH-VM] Cleanup warning: TPM sockets could not be cleaned safely.\n' >&2
            fi
        fi
    fi
    return "$rc"
}

trap cleanup_failed_start EXIT
require_run_dir
command_name="${1:-}"
case "$command_name" in
    create)
        if active_epoch >/dev/null 2>&1; then
            printf '[VH-VM] Existing VM state retained; use reset-test-vm.sh for a fresh epoch.\n'
        else
            create_epoch 1
        fi
        ;;
    start) start_vm ;;
    stop) stop_vm ;;
    check) check_vm ;;
    reset) reset_vm ;;
    stop-qemu) stop_qemu ;;
    *) fail "Usage: $0 {create|start|stop|stop-qemu|check|reset}" ;;
esac
