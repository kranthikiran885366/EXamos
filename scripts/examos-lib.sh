#!/usr/bin/env bash
# =============================================================================
# ExamOS shared discovery library — source this file, do not execute directly.
# Provides: P0 provenance, OVMF, image, and QEMU discovery helpers.
# =============================================================================

examos_p0_load_format() {
    local root="${1:-$(pwd)}"
    local file="$root/image/p0/format.conf"
    [ -r "$file" ] || return 1
    local key value line
    declare -A format_values=()
    while IFS= read -r line || [ -n "$line" ]; do
        [[ "$line" =~ ^[[:space:]]*(#.*)?$ ]] && continue
        [[ "$line" =~ ^([A-Z0-9_]+)=([[:xdigit:]-]+)$ ]] || return 1
        key="${BASH_REMATCH[1]}"
        value="${BASH_REMATCH[2]}"
        case "$key" in
            EXAMOS_P0_ESP_TYPE_GUID|EXAMOS_P0_ROOT_TYPE_GUID) ;;
            *) return 1 ;;
        esac
        [ -z "${format_values[$key]+set}" ] || return 1
        format_values[$key]="$value"
    done < "$file"
    EXAMOS_P0_ESP_TYPE_GUID="${format_values[EXAMOS_P0_ESP_TYPE_GUID]:-}"
    EXAMOS_P0_ROOT_TYPE_GUID="${format_values[EXAMOS_P0_ROOT_TYPE_GUID]:-}"
    local guid_regex='^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$'
    [[ "$EXAMOS_P0_ESP_TYPE_GUID" =~ $guid_regex ]] || return 1
    [[ "$EXAMOS_P0_ROOT_TYPE_GUID" =~ $guid_regex ]] || return 1
    [ "${EXAMOS_P0_ESP_TYPE_GUID,,}" != "${EXAMOS_P0_ROOT_TYPE_GUID,,}" ] || return 1
    export EXAMOS_P0_ESP_TYPE_GUID EXAMOS_P0_ROOT_TYPE_GUID
}

# Return source-tree changes while excluding only files that P0 itself
# regenerates. This keeps evidence writes from contaminating gate provenance.
examos_p0_source_status() {
    local root="${1:-$(pwd)}"
    python3 "$root/scripts/source-state.py" "$root" --format porcelain
}

# Remove terminal color sequences and normalize serial carriage returns before
# evaluating guest readiness markers. Console output can split marker text with
# ANSI color codes even though the guest reached the target successfully.
examos_normalize_serial_log() {
    local input="${1:-}" output="${2:-}"
    [ -n "$input" ] && [ -r "$input" ] && [ -n "$output" ] || return 1
    LC_ALL=C sed -E 's/\x1B\[[0-9;?]*m//g' "$input" | LC_ALL=C tr '\r' '\n' > "$output"
}

# Build one canonical P0 disk image with the exact first-boot provisioning tree
# consumed by both the release image build and reproducibility comparison.
examos_p0_mkosi_build() {
    [ "$#" -eq 6 ] || return 2
    local workspace="$1" output_dir="$2" cache_dir="$3" build_dir="$4"
    local extra_dir="$5" build_log="$6" mkosi_bin cxx_bin source_date_epoch
    mkosi_bin="$(command -v mkosi)" || return 1
    cxx_bin="$(command -v g++)" || return 1
    source_date_epoch="$(git -C "$workspace" show -s --format=%ct HEAD)" || return 1
    [[ "$source_date_epoch" =~ ^[0-9]+$ ]] || return 1
    mkdir -p "$output_dir" "$cache_dir" "$build_dir" \
        "$extra_dir/usr/local/sbin" "$(dirname "$build_log")" || return 1
    "$cxx_bin" -std=c++17 -O2 -Wall -Wextra -Werror \
        -D_FORTIFY_SOURCE=2 -fstack-protector-strong -Wformat=2 \
        -Werror=format-security -fPIE -pie -Wl,-z,relro,-z,now \
        "$workspace/image/p0/dev-console-setup.cpp" \
        -o "$extra_dir/usr/local/sbin/examos-dev-console-setup" || return 1
    chmod 0755 "$extra_dir/usr/local/sbin/examos-dev-console-setup" || return 1
    SOURCE_DATE_EPOCH="$source_date_epoch" \
    SYSTEMD_REPART_MKFS_OPTIONS_VFAT="--invariant" \
    "$mkosi_bin" --force -C "$workspace/image/p0" \
        --source-date-epoch "$source_date_epoch" \
        --cache-directory "$cache_dir" \
        --output-directory "$output_dir" \
        --build-directory "$build_dir" \
        --extra-tree="$workspace/image/p0/dev-console-tree" \
        --extra-tree="$extra_dir" \
        build 2>&1 | tee "$build_log"
}

examos_p0_validate_run_dir() {
    local root="${1:-$(pwd)}" directory="${2:-${EXAMOS_P0_ARTIFACT_DIR:-}}"
    [ -n "$directory" ] || return 1
    local runs_dir resolved marker
    runs_dir="$(realpath -m -- "$root/artifacts/p0/runs")" || return 1
    resolved="$(realpath -m -- "$directory")" || return 1
    [ "$directory" = "$resolved" ] || return 1
    case "$resolved" in
        "$runs_dir"/run-*) ;;
        *) return 1 ;;
    esac
    [ "$(dirname "$resolved")" = "$runs_dir" ] || return 1
    [ -d "$resolved" ] && [ ! -L "$directory" ] || return 1
    [ -f "$resolved/.run-id" ] && [ ! -L "$resolved/.run-id" ] || return 1
    marker="$(cat "$resolved/.run-id")" || return 1
    [ "$marker" = "${resolved##*/}" ]
}

# Find OVMF_CODE firmware. Prints path to stdout, returns 1 if not found.
examos_find_ovmf_code() {
    local candidates=(
        "/usr/share/OVMF/OVMF_CODE_4M.fd"
        "/usr/share/OVMF/OVMF_CODE.fd"
        "/usr/share/ovmf/OVMF.fd"
        "/usr/share/edk2/ovmf/OVMF_CODE_4M.fd"
        "/usr/share/edk2-ovmf/x64/OVMF_CODE.fd"
        "/usr/share/qemu/OVMF.fd"
    )
    for c in "${candidates[@]}"; do
        [ -f "$c" ] && { echo "$c"; return 0; }
    done
    # Dynamic fallback
    local found
    found=$(find /usr/share -maxdepth 4 -name 'OVMF_CODE*.fd' 2>/dev/null | head -1)
    [ -n "$found" ] && { echo "$found"; return 0; }
    return 1
}

# Find OVMF_VARS template. Prints path to stdout, returns 1 if not found.
examos_find_ovmf_vars() {
    local candidates=(
        "/usr/share/OVMF/OVMF_VARS_4M.fd"
        "/usr/share/OVMF/OVMF_VARS.fd"
        "/usr/share/ovmf/OVMF_VARS.fd"
        "/usr/share/edk2/ovmf/OVMF_VARS_4M.fd"
        "/usr/share/edk2-ovmf/x64/OVMF_VARS.fd"
    )
    for c in "${candidates[@]}"; do
        [ -f "$c" ] && { echo "$c"; return 0; }
    done
    local found
    found=$(find /usr/share -maxdepth 4 -name 'OVMF_VARS*.fd' 2>/dev/null | head -1)
    [ -n "$found" ] && { echo "$found"; return 0; }
    return 1
}

# Find the built ExamOS disk image under a given root directory.
# Usage: examos_find_image <workspace_root>
# Prints path to stdout, returns 1 if not found.
examos_find_image() {
    local root="${1:-$(pwd)}"
    local candidates=(
        "$root/output/examos.raw"
        "$root/output/examos"
        "$root/output/image.raw"
        "$root/image/examos.raw.raw"
        "$root/image/examos.raw"
        "$root/image/examos.img"
    )
    for c in "${candidates[@]}"; do
        [ -f "$c" ] && [ -s "$c" ] && ! [ -L "$c" ] && { echo "$c"; return 0; }
    done
    # Dynamic fallback: search output/ then image/
    local found
    found=$(find "$root/output" "$root/image" -maxdepth 2 -type f \
            \( -name '*.raw' -o -name '*.img' \) \
            ! -name '*.lck' 2>/dev/null | head -1)
    [ -n "$found" ] && [ -s "$found" ] && { echo "$found"; return 0; }
    return 1
}

# Probe whether QEMU can actually initialize KVM. Device-node permissions alone
# are insufficient in containers and WSL, where the KVM ioctl can still fail.
examos_kvm_available() {
    command -v qemu-system-x86_64 >/dev/null 2>&1 || return 1
    command -v timeout >/dev/null 2>&1 || return 1

    local probe_status=0
    timeout 2s qemu-system-x86_64 \
        -machine none -accel kvm -nodefaults -display none -S \
        -monitor none -serial none >/dev/null 2>&1 || probe_status=$?
    [ "$probe_status" -eq 124 ]
}

# Detect usable QEMU acceleration, not merely a readable /dev/kvm node.
# Prints "-accel kvm -cpu host" or "-accel tcg -cpu max".
examos_qemu_accel() {
    if examos_kvm_available; then
        echo "-accel kvm -cpu host"
    else
        echo "-accel tcg -cpu max"
    fi
}

# Derive a bounded QEMU allocation from resources currently available to WSL.
# Three quarters of available memory and one quarter of CPU capacity are
# allocated to the guest, leaving host resources available to run the test;
# reject hosts that cannot provide the minimum memory required by the P0 image.
examos_qemu_resources() {
    local available_kib host_cpus memory_mb guest_cpus
    available_kib=$(awk '/^MemAvailable:/ { print $2; exit }' /proc/meminfo)
    host_cpus=$(nproc)
    [[ "$available_kib" =~ ^[0-9]+$ ]] || return 1
    [[ "$host_cpus" =~ ^[1-9][0-9]*$ ]] || return 1

    memory_mb=$((available_kib * 3 / 4096))
    guest_cpus=$(((host_cpus + 3) / 4))
    [ "$memory_mb" -ge 1024 ] || return 1
    printf '%s\t%s\n' "$memory_mb" "$guest_cpus"
}
