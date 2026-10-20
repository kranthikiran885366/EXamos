#!/usr/bin/env bash
# Capture VMware Workstation UEFI optical-boot evidence for a named ISO.
# Does not start a VM that could alter host EFI, TPM, or Windows boot config.
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${EXAMOS_P0_VMWARE_OUT:-$WORKSPACE/artifacts/p0/vmware}"
mkdir -p "$OUT"
ISO="${EXAMOS_P0_ISO:-}"
status=BLOCKED
REASON_FILE="$(mktemp)"
trap 'rm -f "$REASON_FILE"' EXIT

note() { printf '%s\n' "$1" >>"$REASON_FILE"; echo "[P0-VMWARE] $2: $1" >&2; }
block() { status=BLOCKED; note "$1" BLOCKED; }
fail() { status=FAIL; note "$1" FAIL; }

commit="$(git -C "$WORKSPACE" rev-parse HEAD 2>/dev/null || echo UNKNOWN)"
iso_sha="NOT_SUPPLIED"
vmware_version="NOT_FOUND"
vmx_path="${EXAMOS_P0_VMWARE_VMX:-}"
guest="NOT_RUN"

if [ -z "$ISO" ]; then
    block "EXAMOS_P0_ISO is unset; refuse to invent a media path"
elif [ ! -f "$ISO" ]; then
    fail "ISO path does not exist: $ISO"
else
    iso_sha="$(sha256sum "$ISO" | awk '{ print $1 }')"
    echo "$iso_sha  $(basename "$ISO")" >"$OUT/iso.sha256"
fi

VMRUN=""
for c in vmrun \
         "/mnt/c/Program Files (x86)/VMware/VMware Workstation/vmrun.exe" \
         "/mnt/c/Program Files/VMware/VMware Workstation/vmrun.exe"; do
    if command -v "$c" >/dev/null 2>&1 || [ -x "$c" ]; then
        VMRUN="$c"
        break
    fi
done

if [ -z "$VMRUN" ]; then
    block "VMware Workstation vmrun is not available on this host"
else
    vmware_version="$("$VMRUN" 2>&1 | head -n 3 | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')"
    printf '%s\n' "$vmware_version" >"$OUT/vmware-version.txt"
fi

if [ -z "$vmx_path" ]; then
    block "EXAMOS_P0_VMWARE_VMX is unset; VM configuration was not captured"
elif [ ! -f "$vmx_path" ]; then
    fail "EXAMOS_P0_VMWARE_VMX does not exist: $vmx_path"
else
    grep -Ei '^(firmware|guestOS|uefi|sata0:|ide1:|scsi0:|nvme|firmwareType)' "$vmx_path" \
        >"$OUT/vm-config-excerpt.txt" || true
    if ! grep -qiE 'firmware\s*=\s*"efi"' "$vmx_path"; then
        fail "VM firmware is not UEFI (firmware=efi required)"
    fi
    cp "$vmx_path" "$OUT/vmx.copy"
fi

if [ -n "${EXAMOS_P0_VMWARE_GUEST_LOG:-}" ] && [ -f "${EXAMOS_P0_VMWARE_GUEST_LOG}" ]; then
    cp "${EXAMOS_P0_VMWARE_GUEST_LOG}" "$OUT/guest-serial.log"
    guest="SUPPLIED_LOG"
else
    block "guest serial/log not supplied (EXAMOS_P0_VMWARE_GUEST_LOG); auto-start is disabled to protect the Windows host"
fi

python3 - "$OUT/vmware-boot-result.json" "$status" "$commit" "$iso_sha" \
    "$vmware_version" "${vmx_path:-}" "$guest" "$REASON_FILE" <<'PY'
import json, sys, datetime
out, status, commit, iso_sha, version, vmx, guest, reason_path = sys.argv[1:9]
with open(reason_path, encoding="utf-8") as fh:
    reasons = [line.strip() for line in fh if line.strip()]
if status == "FAIL":
    result = "FAIL"
elif reasons:
    result = "BLOCKED"
else:
    result = status
report = {
    "schema": "examos.p0.vmware-optical-boot.v1",
    "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "source_commit": commit,
    "result": result,
    "iso_sha256": iso_sha,
    "vmware_version": version,
    "vmx_path": vmx or None,
    "guest_result": guest,
    "host_firmware_modified": False,
    "windows_boot_modified": False,
    "tpm_modified": False,
    "reasons": reasons,
    "release_eligible": False,
}
with open(out, "w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2)
    fh.write("\n")
print(json.dumps(report, indent=2))
sys.exit(0 if result == "PASS" else 2 if result == "BLOCKED" else 1)
PY
