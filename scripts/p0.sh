#!/usr/bin/env bash
# =============================================================================
# ExamOS P0 — Master Orchestration & Acceptance Gate Script
# scripts/p0.sh
# =============================================================================
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/.." && pwd)"
RUNS_DIR="$WORKSPACE/artifacts/p0/runs"
source "$WORKSPACE/scripts/examos-lib.sh"

GIT_COMMIT="$(git -C "$WORKSPACE" rev-parse HEAD)"
if ! SOURCE_STATUS="$(examos_p0_source_status "$WORKSPACE")"; then
    echo "[P0] FATAL: unable to determine source worktree state." >&2
    exit 2
fi
SOURCE_TREE_STATE="CLEAN"
SOURCE_DIRTY_PATH_COUNT=0
if [ -n "$SOURCE_STATUS" ]; then
    SOURCE_TREE_STATE="DIRTY"
    SOURCE_DIRTY_PATH_COUNT="$(printf '%s\n' "$SOURCE_STATUS" | wc -l | tr -d ' ')"
    echo "[P0] BLOCKED: source tree has $SOURCE_DIRTY_PATH_COUNT modified or untracked source paths." >&2
    echo "[P0] No build, boot test, or evidence artifact was changed. Commit or preserve the current work before running the release gate." >&2
    printf '%s\n' "$SOURCE_STATUS" >&2
    exit 2
fi
P0_CONFIG="$WORKSPACE/image/p0/mkosi.conf"
VERSION_FILE="$WORKSPACE/docs/releases/version.yaml"
[ -s "$P0_CONFIG" ] || { echo "[P0] FATAL: P0 mkosi configuration is missing: $P0_CONFIG" >&2; exit 2; }
[ -s "$VERSION_FILE" ] || { echo "[P0] FATAL: product version file is missing: $VERSION_FILE" >&2; exit 2; }
BUILD_CONFIG_SHA256="$(sha256sum "$P0_CONFIG" | cut -d' ' -f1)"
PRODUCT_VERSION="$(awk -F': *' '$1 == "version" { print $2; exit }' "$VERSION_FILE")"
[ -n "$PRODUCT_VERSION" ] || { echo "[P0] FATAL: product version is missing." >&2; exit 2; }
TARGET_ARCH="$(awk -F= '/^[[:space:]]*Architecture[[:space:]]*=/ { gsub(/[[:space:]]/, "", $2); print $2; exit }' "$P0_CONFIG")"
QEMU_ACCEL_ARGS="$(examos_qemu_accel)" || {
    echo "[P0] FATAL: requested QEMU acceleration is unavailable or invalid." >&2
    exit 2
}
case "$QEMU_ACCEL_ARGS" in
    *"-accel kvm"*) SELECTED_QEMU_ACCELERATION="KVM"; EXAMOS_P0_QEMU_ACCEL="kvm" ;;
    *"-accel tcg"*) SELECTED_QEMU_ACCELERATION="TCG"; EXAMOS_P0_QEMU_ACCEL="tcg" ;;
    *) echo "[P0] FATAL: QEMU acceleration selector returned an unsupported value." >&2; exit 2 ;;
esac
export EXAMOS_P0_QEMU_ACCEL
mkdir -p "$RUNS_DIR"
if [ -n "${EXAMOS_P0_ARTIFACT_DIR:-}" ]; then
    ARTIFACT_DIR="$(realpath -m -- "$EXAMOS_P0_ARTIFACT_DIR")"
    case "$ARTIFACT_DIR" in
        "$RUNS_DIR"/run-*) ;;
        *) echo "[P0] FATAL: explicit evidence directory must be a run-* directory under $RUNS_DIR." >&2; exit 2 ;;
    esac
    [ ! -e "$ARTIFACT_DIR" ] && [ ! -L "$ARTIFACT_DIR" ] || {
        echo "[P0] FATAL: evidence run directory already exists; refusing to overwrite it." >&2
        exit 2
    }
    mkdir -m 0750 "$ARTIFACT_DIR"
else
    ARTIFACT_DIR="$(mktemp -d "$RUNS_DIR/run-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")"
    chmod 0750 "$ARTIFACT_DIR"
fi
printf '%s\n' "${ARTIFACT_DIR##*/}" > "$ARTIFACT_DIR/.run-id"
chmod 0640 "$ARTIFACT_DIR/.run-id"
export EXAMOS_P0_ARTIFACT_DIR="$ARTIFACT_DIR"
printf 'P0_EVIDENCE_DIR=%s\n' "$ARTIFACT_DIR"
HOST_ARCH="$(uname -m)"
HOST_OS="$(uname -s)"
HOST_KERNEL="$(uname -r)"
HOST_CPUS="$(nproc)"
HOST_MEMORY_BYTES="$(awk '/^MemTotal:/ { print $2 * 1024; exit }' /proc/meminfo)"
HOST_VIRTUALIZATION="$(systemd-detect-virt --vm 2>/dev/null || echo none)"
EVIDENCE_ENVIRONMENT="LINUX_QEMU_OVMF"
if grep -qiE 'microsoft|wsl' /proc/sys/kernel/osrelease 2>/dev/null; then
    EVIDENCE_ENVIRONMENT="WSL2_QEMU_OVMF"
fi

RESULTS_FINALIZED=0
CURRENT_STEP="pipeline initialization"
write_interrupted_result() {
    local exit_code=$?
    if [ "$RESULTS_FINALIZED" -eq 0 ]; then
        cat > "$ARTIFACT_DIR/results.json" <<EOF
{
  "phase": "P0",
  "version": "$PRODUCT_VERSION",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "git_commit": "$GIT_COMMIT",
  "source_tree_state": "$SOURCE_TREE_STATE",
  "source_dirty_path_count_at_start": $SOURCE_DIRTY_PATH_COUNT,
  "status": "FAIL",
  "release_classification": "NOT_APPROVED",
  "failed_stage": "$CURRENT_STEP",
  "exit_code": $exit_code,
  "evidence_environment": "$EVIDENCE_ENVIRONMENT",
  "host_architecture": "$HOST_ARCH",
  "target_architecture": "$TARGET_ARCH"
}
EOF
    fi
}
trap write_interrupted_result EXIT
cat > "$ARTIFACT_DIR/results.json" <<EOF
{
  "phase": "P0",
  "version": "$PRODUCT_VERSION",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "git_commit": "$GIT_COMMIT",
  "source_tree_state": "$SOURCE_TREE_STATE",
  "source_dirty_path_count_at_start": $SOURCE_DIRTY_PATH_COUNT,
  "status": "IN_PROGRESS",
  "release_classification": "NOT_APPROVED",
  "evidence_environment": "$EVIDENCE_ENVIRONMENT",
  "host_architecture": "$HOST_ARCH",
  "target_architecture": "$TARGET_ARCH"
}
EOF

echo "============================================================"
echo "          EXAMOS PHASE 0 (P0) ACCEPTANCE PIPELINE"
echo "============================================================"

# Step 1: Host Validation
CURRENT_STEP="host prerequisite validation"
echo ""
echo ">>> STEP 1/10: Running Host & Environment Verification..."
bash "$WORKSPACE/tests/p0/host-check.sh"

# Step 2: Environment Docto
CURRENT_STEP="environment doctor"
echo ""
echo ">>> STEP 2/10: Running Environment Doctor Diagnostics..."
bash "$WORKSPACE/tests/p0/examos-doctor.sh"

# Step 3: Repository Layout & Secret Material Scan
CURRENT_STEP="repository integrity and secret scan"
echo ""
echo ">>> STEP 3/10: Checking Repository Structure & Secret Material..."
bash "$WORKSPACE/tests/p0/repository-check.sh"
bash "$WORKSPACE/tests/p0/pin-check.sh" --record "$ARTIFACT_DIR/pinned-inputs-result.json"
CHECK_PINNED_INPUTS="PASS"
bash "$WORKSPACE/tests/p0/agent-config-contract-test.sh"
python3 "$WORKSPACE/tests/p0/results-schema-test.py"

# Step 4: Tool Version & OVMF Firmware Discovery
CURRENT_STEP="toolchain and firmware discovery"
echo ""
echo ">>> STEP 4/10: Collecting Tool Versions & Firmware Paths..."
{
    git --version
    mkosi --version
    qemu-system-x86_64 --version | head -n 1
    qemu-img --version | head -n 1
    g++ --version | head -n 1
    swtpm --version | head -n 1
    tpm2_pcrread --version | head -n 1
    sbsign --version 2>&1 || true
    veritysetup --version
    mksquashfs -version 2>&1 | head -n 1
} > "$ARTIFACT_DIR/tool-versions.txt"

{
    source "$WORKSPACE/scripts/examos-lib.sh"
    echo "OVMF_CODE: $(examos_find_ovmf_code || true)"
    echo "OVMF_VARS: $(examos_find_ovmf_vars || true)"
} > "$ARTIFACT_DIR/ovmf-info.txt"

# Step 5: Build ExamOS Target Image
CURRENT_STEP="canonical disk image build"
echo ""
echo ">>> STEP 5/10: Building Target Disk Image..."
P0_BUILD_START_EPOCH="$(date +%s)" bash "$WORKSPACE/tests/p0/build.sh"

# Step 6: Build a hybrid ISO from the P0 disk's verified partitions.
CURRENT_STEP="hybrid ISO build"
echo ""
echo ">>> STEP 6/10: Building UEFI Hybrid ISO from the P0 Disk..."
bash "$WORKSPACE/tests/p0/build-iso.sh"

# Step 7: QEMU / OVMF Boot Test
CURRENT_STEP="QEMU disk boot ($SELECTED_QEMU_ACCELERATION)"
echo ""
echo ">>> STEP 7/10: Executing QEMU / OVMF Disk Boot Validation..."
bash "$WORKSPACE/tests/p0/boot.sh"

# Step 8: Exercise native first-boot account setup and serial login.
CURRENT_STEP="first-boot account and login"
echo ""
echo ">>> STEP 8/10: Testing First-Boot Account Creation and Login..."
CHECK_FIRST_BOOT="FAIL"
bash "$WORKSPACE/tests/p0/first-boot-test.sh"
CHECK_FIRST_BOOT="PASS"
CURRENT_STEP="first-boot interrupted-setup recovery"
echo "[P0] Exercising first-boot recovery from a persisted completion marker with a missing account..."
CHECK_FIRST_BOOT_RECOVERY="FAIL"
bash "$WORKSPACE/tests/p0/first-boot-recovery-test.sh"
CHECK_FIRST_BOOT_RECOVERY="PASS"

# Step 9: QEMU / OVMF ISO Boot Test
CURRENT_STEP="QEMU UEFI optical ISO boot"
echo ""
echo ">>> STEP 9/10: Executing QEMU / OVMF UEFI Optical ISO Boot Validation..."
bash "$WORKSPACE/tests/p0/boot-iso.sh"

# Step 10: Assemble Metadata & Results JSON
CURRENT_STEP="aggregate P0 evidence"
echo ""
echo ">>> STEP 10/10: Assembling P0 Results & Build Metadata..."

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
IMAGE_HASH=$(cut -d' ' -f1 < "$ARTIFACT_DIR/image.sha256" 2>/dev/null || echo "UNKNOWN")
IMAGE_SIZE=$(cat "$ARTIFACT_DIR/image-size.txt" 2>/dev/null || echo "UNKNOWN")
ISO_SIZE="UNKNOWN"
ISO_RELATIVE="UNKNOWN"
if [ -s "$ARTIFACT_DIR/examos-p0.iso" ]; then
    ISO_SIZE="$(stat -c '%s' "$ARTIFACT_DIR/examos-p0.iso")"
    ISO_RELATIVE="$(realpath --relative-to="$WORKSPACE" "$ARTIFACT_DIR/examos-p0.iso")"
fi

cat > "$ARTIFACT_DIR/build-info.txt" <<INFOEOF
Timestamp: $TIMESTAMP
Git Commit: $GIT_COMMIT
Source Tree: $SOURCE_TREE_STATE
Dirty Paths at Gate Start: $SOURCE_DIRTY_PATH_COUNT
P0 mkosi Config SHA-256: $BUILD_CONFIG_SHA256
Host OS: $(uname -s) $(uname -r)
Architecture: $(uname -m)
CPU Count: $(nproc)
RAM: $(free -h | awk '/^Mem:/ {print $2}')
Storage Free: $(df -h / | tail -1 | awk '{print $4}')
Virtualization: $HOST_VIRTUALIZATION
mkosi Version: $(mkosi --version 2>/dev/null || echo "UNKNOWN")
QEMU Version: $(qemu-system-x86_64 --version 2>/dev/null | head -1 || echo "UNKNOWN")
OVMF Code: $(grep 'OVMF_CODE:' "$ARTIFACT_DIR/ovmf-info.txt" | cut -d' ' -f2)
Artifact SHA-256: $IMAGE_HASH
Artifact Size: $IMAGE_SIZE
INFOEOF

# Derive check results from actual test outputs
CHECK_ARCH="FAIL"
if [ "$HOST_ARCH" = "x86_64" ] && [ "$TARGET_ARCH" = "x86-64" ]; then CHECK_ARCH="PASS"; fi
CHECK_KVM="FAIL"
if examos_kvm_available; then CHECK_KVM="PASS"; fi
CHECK_QEMU="FAIL"; command -v qemu-system-x86_64 >/dev/null 2>&1 && CHECK_QEMU="PASS"
CHECK_OVMF="FAIL"
for _cand in /usr/share/OVMF/OVMF_CODE_4M.fd /usr/share/OVMF/OVMF_CODE.fd /usr/share/ovmf/OVMF.fd; do
    [ -f "$_cand" ] && { CHECK_OVMF="PASS"; break; }
done
CHECK_SWTPM="NOT_REQUIRED"; command -v swtpm >/dev/null 2>&1 && CHECK_SWTPM="AVAILABLE"
CHECK_MKOSI="FAIL"; command -v mkosi >/dev/null 2>&1 && CHECK_MKOSI="PASS"
CHECK_ARTIFACT="FAIL"
if [ -n "$IMAGE_HASH" ] && [ "$IMAGE_HASH" != "UNKNOWN" ] && \
   [ -s "$ARTIFACT_DIR/image-path.txt" ] && [ -s "$ARTIFACT_DIR/image-size.txt" ]; then
    CHECK_ARTIFACT="PASS"
fi
CHECK_CHECKSUM="FAIL"
if [ "$CHECK_ARTIFACT" = "PASS" ] && sha256sum --check --status "$ARTIFACT_DIR/image.sha256"; then
    CHECK_CHECKSUM="PASS"
fi
CHECK_BUILD="FAIL"
if jq -e --arg hash "$IMAGE_HASH" --arg commit "$GIT_COMMIT" \
    --arg image_path "$(cat "$ARTIFACT_DIR/image-path.txt" 2>/dev/null || echo UNKNOWN)" \
    --arg config_hash "$BUILD_CONFIG_SHA256" \
    --arg tree "$SOURCE_TREE_STATE" --argjson dirty "$SOURCE_DIRTY_PATH_COUNT" \
    '.status == "PASS" and .image_sha256 == $hash
     and .source_commit == $commit and .source_tree_state == $tree
     and .source_dirty_path_count == $dirty
     and .build_config_sha256 == $config_hash
     and .image_path == $image_path
     and .image_size_bytes > 0' \
    "$ARTIFACT_DIR/build-result.json" >/dev/null 2>&1; then
    CHECK_BUILD="PASS"
fi
CHECK_BOOT="FAIL"
if jq -e --arg hash "$IMAGE_HASH" --arg acceleration "$SELECTED_QEMU_ACCELERATION" \
    '.status == "PASS" and .image_sha256 == $hash and
     .image_sha256_after_boot == $hash and .source_image_unchanged == true and
     .readiness_observed == true and
     .qemu_acceleration == $acceleration and .qemu_memory_mib > 0 and .qemu_vcpus > 0 and
     ([.markers.kernel, .markers.systemd, .markers.multi_user_target,
       .markers.serial_login_prompt] | all)' \
    "$ARTIFACT_DIR/boot-result.json" >/dev/null 2>&1; then
    CHECK_BOOT="PASS"
fi
CHECK_FIRST_BOOT="FAIL"
if jq -e --arg hash "$IMAGE_HASH" --arg acceleration "$SELECTED_QEMU_ACCELERATION" \
    '.status == "PASS" and .image_sha256 == $hash and
     .image_sha256_after_test == $hash and .source_image_unchanged == true and
     .snapshot_isolated == true and .guest_account_created == true and
     .qemu_acceleration == $acceleration and .qemu_memory_mib > 0 and .qemu_vcpus > 0 and
     .authenticated_serial_login == true and
     .non_root_uid_and_sudo_group_verified == true and
     .setup_executable_owner_mode_verified == true' \
    "$ARTIFACT_DIR/first-boot-result.json" >/dev/null 2>&1; then
    CHECK_FIRST_BOOT="PASS"
fi
CHECK_FIRST_BOOT_RECOVERY="FAIL"
RECOVERY_FIXTURE_HASH="UNKNOWN"
RECOVERY_FIXTURE_HASH_FILE="$ARTIFACT_DIR/recovery-test-image.sha256"
RECOVERY_FIXTURE_IMAGE="$ARTIFACT_DIR/recovery-test-image.raw"
if [ -s "$RECOVERY_FIXTURE_IMAGE" ] && [ ! -L "$RECOVERY_FIXTURE_IMAGE" ] &&
    [ -s "$RECOVERY_FIXTURE_HASH_FILE" ] && [ ! -L "$RECOVERY_FIXTURE_HASH_FILE" ]; then
    RECOVERY_FIXTURE_HASH="$(sha256sum "$RECOVERY_FIXTURE_IMAGE" | cut -d' ' -f1)"
    RECOVERY_RECORDED_HASH="$(cut -d' ' -f1 "$RECOVERY_FIXTURE_HASH_FILE")"
    [ "$RECOVERY_FIXTURE_HASH" = "$RECOVERY_RECORDED_HASH" ] ||
        RECOVERY_FIXTURE_HASH="UNKNOWN"
fi
if jq -e --arg canonical_hash "$IMAGE_HASH" --arg commit "$GIT_COMMIT" \
    --arg acceleration "$SELECTED_QEMU_ACCELERATION" \
    --arg fixture_hash "$RECOVERY_FIXTURE_HASH" \
    '.schema == "examos.p0.first-boot-recovery.v1" and
     .phase == "P0" and .check == "first_boot_recovery" and .status == "PASS" and
     .source_commit == $commit and .canonical_image_sha256 == $canonical_hash and
     $fixture_hash != "UNKNOWN" and .fixture_image_sha256 == $fixture_hash and
     .scenario == "complete_marker_missing_account" and
     .qemu_acceleration == $acceleration and .qemu_memory_mib > 0 and .qemu_vcpus > 0 and
     .snapshot_isolated == true and .missing_account_reconciled == true and
     .pending_setup_resumed == true and .authenticated_serial_login == true' \
    "$ARTIFACT_DIR/first-boot-recovery-result.json" >/dev/null 2>&1; then
    CHECK_FIRST_BOOT_RECOVERY="PASS"
fi
ISO_HASH=$(cut -d' ' -f1 < "$ARTIFACT_DIR/iso.sha256" 2>/dev/null || echo "UNKNOWN")
CHECK_ISO_BUILD="FAIL"
if jq -e --arg disk "$IMAGE_HASH" --arg iso "$ISO_HASH" --arg commit "$GIT_COMMIT" \
    --arg tree "$SOURCE_TREE_STATE" --argjson dirty "$SOURCE_DIRTY_PATH_COUNT" \
    '.status == "PASS" and .source_disk_sha256 == $disk and .iso_sha256 == $iso
     and .source_commit == $commit and .source_tree_state_at_start == $tree
     and .dirty_path_count_at_start == $dirty' \
    "$ARTIFACT_DIR/iso-build-result.json" >/dev/null 2>&1; then
    CHECK_ISO_BUILD="PASS"
fi
CHECK_ISO_BOOT="FAIL"
if jq -e --slurpfile build "$ARTIFACT_DIR/iso-build-result.json" \
    --arg disk "$IMAGE_HASH" --arg iso "$ISO_HASH" \
    --arg acceleration "$SELECTED_QEMU_ACCELERATION" '
    . as $boot | $build[0] as $build
    | $boot.status == "PASS" and $build.status == "PASS"
      and $boot.iso_sha256 == $iso and $boot.iso_sha256_after_boot == $iso
      and $boot.source_iso_unchanged == true
      and $build.iso_sha256 == $iso
      and $build.source_disk_sha256 == $disk
      and $boot.source_disk_sha256 == $disk
      and $boot.uki_sha256 == $build.uki_sha256
      and $boot.source_uki_sha256 == $build.source_uki_sha256
      and $boot.source_initrd_sha256 == $build.source_initrd_sha256
      and $boot.root_filesystem_sha256 == $build.root_filesystem_sha256
      and $boot.root_filesystem_uuid == $build.root_filesystem_uuid
      and $boot.source_commit == $build.source_commit
      and $boot.source_tree_state_at_start == $build.source_tree_state_at_start
      and $boot.dirty_path_count_at_start == $build.dirty_path_count_at_start
      and $boot.qemu_acceleration == $acceleration
      and $boot.qemu_stopped_after_readiness == true
      and $boot.qemu_memory_mib > 0 and $boot.qemu_vcpus > 0
      and ([ $boot.markers.kernel, $boot.markers.systemd,
             $boot.markers.canonical_root_selected,
             $boot.markers.volatile_overlay_selected,
             $boot.markers.canonical_root_mounted,
             $boot.markers.multi_user_target,
             $boot.markers.serial_login_prompt ] | all)
    ' "$ARTIFACT_DIR/iso-boot-result.json" >/dev/null 2>&1; then
    CHECK_ISO_BOOT="PASS"
fi
CHECK_IMAGE_FORENSICS="BLOCKED"
if ! bash "$WORKSPACE/tests/p0/image-forensics.sh" \
    > "$ARTIFACT_DIR/image-forensics-output.log" 2>&1; then
    CHECK_IMAGE_FORENSICS="FAIL"
fi
if [ -s "$ARTIFACT_DIR/enterprise/image-forensics.json" ] && jq -e \
    --arg image "$IMAGE_HASH" \
    '.schema == "examos.p0.forensics.v1" and .artifact_sha256 == $image
     and .gpt_table == "PASS" and .esp_partition == "PASS"
     and .root_partition == "PASS" and .hash_integrity == "PASS"
     and .status == "PASS"' \
    "$ARTIFACT_DIR/enterprise/image-forensics.json" >/dev/null 2>&1; then
    CHECK_IMAGE_FORENSICS="PASS"
else
    CHECK_IMAGE_FORENSICS="FAIL"
fi
CHECK_REPRODUCIBLE_BUILD="BLOCKED"
REPRODUCIBILITY_SHA256="UNKNOWN"
CURRENT_STEP="two-build image reproducibility"
if EXAMOS_P0_REPRO_MODE=image \
    EXAMOS_P0_REPRO_OUT="$ARTIFACT_DIR/reproducibility" \
    bash "$WORKSPACE/tests/p0/reproducible-build.sh"; then
    REPRODUCIBILITY_RUN_STATUS=0
else
    REPRODUCIBILITY_RUN_STATUS=$?
fi
REPRO_REPORT="$ARTIFACT_DIR/reproducibility/report.json"
if [ -s "$REPRO_REPORT" ]; then
    REPRODUCIBILITY_SHA256="$(sha256sum "$REPRO_REPORT" | cut -d' ' -f1)"
    REPRO_RESULT="$(jq -r '.result // "INVALID"' "$REPRO_REPORT" 2>/dev/null || echo INVALID)"
    case "$REPRO_RESULT" in
        PASS)
            if python3 "$WORKSPACE/tests/p0/validate-reproducibility.py" \
                "$REPRO_REPORT" \
                "$ARTIFACT_DIR/reproducibility/build-a.sha256" \
                "$ARTIFACT_DIR/reproducibility/build-b.sha256" "$GIT_COMMIT" \
                "$(git -C "$WORKSPACE" show -s --format=%ct "$GIT_COMMIT")"; then
                CHECK_REPRODUCIBLE_BUILD="PASS"
            else
                CHECK_REPRODUCIBLE_BUILD="FAIL"
            fi
            ;;
        BLOCKED) CHECK_REPRODUCIBLE_BUILD="BLOCKED" ;;
        *) CHECK_REPRODUCIBLE_BUILD="FAIL" ;;
    esac
elif [ "$REPRODUCIBILITY_RUN_STATUS" -eq 0 ]; then
    CHECK_REPRODUCIBLE_BUILD="FAIL"
else
    CHECK_REPRODUCIBLE_BUILD="FAIL"
fi
CHECK_SECRETS="FAIL"
if bash "$WORKSPACE/tests/p0/private-key-check.sh" "$WORKSPACE"; then
    CHECK_SECRETS="PASS"
fi
CHECK_SOURCE_TREE="PASS"
if ! CURRENT_SOURCE_STATUS="$(examos_p0_source_status "$WORKSPACE")"; then
    CHECK_SOURCE_TREE="FAIL"
elif [ "$(git -C "$WORKSPACE" rev-parse HEAD)" != "$GIT_COMMIT" ] ||
    [ -n "$CURRENT_SOURCE_STATUS" ]; then
    CHECK_SOURCE_TREE="FAIL"
fi

CURRENT_STEP="aggregate P0 evidence"
OVERALL="PASS"
for _c in "$CHECK_ARCH" "$CHECK_KVM" "$CHECK_QEMU" "$CHECK_OVMF" "$CHECK_MKOSI" \
          "$CHECK_ARTIFACT" "$CHECK_CHECKSUM" "$CHECK_SECRETS" "$CHECK_BUILD" \
          "$CHECK_BOOT" "$CHECK_FIRST_BOOT" "$CHECK_FIRST_BOOT_RECOVERY" \
          "$CHECK_ISO_BUILD" "$CHECK_ISO_BOOT" \
          "$CHECK_IMAGE_FORENSICS" "$CHECK_PINNED_INPUTS" "$CHECK_REPRODUCIBLE_BUILD" \
          "$CHECK_SOURCE_TREE"; do
    if [ "$_c" = "FAIL" ]; then
        OVERALL="FAIL"
        break
    elif [ "$_c" = "BLOCKED" ] && [ "$OVERALL" = "PASS" ]; then
        OVERALL="BLOCKED"
    fi
done

cat > "$ARTIFACT_DIR/results.json" <<JSONEOF
{
  "schema": "examos.p0.results.v1",
  "phase": "P0",
  "version": "$PRODUCT_VERSION",
  "timestamp": "$TIMESTAMP",
  "git_commit": "$GIT_COMMIT",
  "source_tree_state": "$SOURCE_TREE_STATE",
  "source_dirty_path_count_at_start": $SOURCE_DIRTY_PATH_COUNT,
  "build_config_sha256": "$BUILD_CONFIG_SHA256",
  "evidence_environment": "$EVIDENCE_ENVIRONMENT",
  "host": {
    "os": "$HOST_OS",
    "kernel": "$HOST_KERNEL",
    "architecture": "$HOST_ARCH",
    "virtualization": "$HOST_VIRTUALIZATION",
    "cpu_count": $HOST_CPUS,
    "memory_bytes": $HOST_MEMORY_BYTES,
    "target_architecture": "$TARGET_ARCH"
  },
  "release_classification": "DEVELOPMENT_CANDIDATE",
  "status": "$OVERALL",
  "disk_artifact": {
    "path": "$(cat "$ARTIFACT_DIR/image-path.txt" 2>/dev/null || echo UNKNOWN)",
    "sha256": "$IMAGE_HASH",
    "size_bytes": "$IMAGE_SIZE"
  },
  "iso_artifact": {
    "path": "$ISO_RELATIVE",
    "sha256": "$ISO_HASH",
    "size_bytes": "$ISO_SIZE"
  },
  "checks": {
    "host_architecture": "$CHECK_ARCH",
    "kvm_access": "$CHECK_KVM",
    "qemu_installed": "$CHECK_QEMU",
    "ovmf_discovered": "$CHECK_OVMF",
    "swtpm_ready": "$CHECK_SWTPM",
    "mkosi_build": "$CHECK_MKOSI",
    "build_pipeline": "$CHECK_BUILD",
    "guest_boot": "$CHECK_BOOT",
    "first_boot_account": "$CHECK_FIRST_BOOT",
    "first_boot_recovery": "$CHECK_FIRST_BOOT_RECOVERY",
    "iso_build": "$CHECK_ISO_BUILD",
    "iso_boot": "$CHECK_ISO_BOOT",
    "image_forensics": "$CHECK_IMAGE_FORENSICS",
    "pinned_inputs": "$CHECK_PINNED_INPUTS",
    "reproducible_build": "$CHECK_REPRODUCIBLE_BUILD",
    "reproducibility_sha256": "$REPRODUCIBILITY_SHA256",
    "artifact_generated": "$CHECK_ARTIFACT",
    "artifact_checksum_valid": "$CHECK_CHECKSUM",
    "artifact_checksum": "$IMAGE_HASH",
    "iso_checksum": "$ISO_HASH",
    "secrets_clean": "$CHECK_SECRETS",
    "source_tree_clean": "$CHECK_SOURCE_TREE"
  }
}
JSONEOF

if ! python3 "$WORKSPACE/tests/p0/validate-results.py" \
    "$WORKSPACE/schemas/p0-results-v1.schema.json" "$ARTIFACT_DIR/results.json" \
    > "$ARTIFACT_DIR/results-schema-validation.log" 2>&1; then
    cat "$ARTIFACT_DIR/results-schema-validation.log" >&2
    jq '.status = "FAIL"' "$ARTIFACT_DIR/results.json" > "$ARTIFACT_DIR/.results.json.tmp" &&
        mv -- "$ARTIFACT_DIR/.results.json.tmp" "$ARTIFACT_DIR/results.json"
    RESULTS_FINALIZED=1
    exit 1
fi
RESULTS_FINALIZED=1

echo ""
echo "========================================"
echo "        EXAMOS P0 STATUS SUMMARY        "
echo "========================================"
printf "%-25s %s\n" "Architecture"         "$CHECK_ARCH"
printf "%-25s %s\n" "KVM"                  "$CHECK_KVM"
printf "%-25s %s\n" "QEMU"                 "$CHECK_QEMU"
printf "%-25s %s\n" "OVMF"                 "$CHECK_OVMF"
printf "%-25s %s\n" "swtpm"                "$CHECK_SWTPM"
printf "%-25s %s\n" "mkosi"                "$CHECK_MKOSI"
printf "%-25s %s\n" "Artifact"             "$CHECK_ARTIFACT"
printf "%-25s %s\n" "Build Evidence"       "$CHECK_BUILD"
printf "%-25s %s\n" "Boot Evidence"        "$CHECK_BOOT"
printf "%-25s %s\n" "First-Boot Account"   "$CHECK_FIRST_BOOT"
printf "%-25s %s\n" "ISO Build"            "$CHECK_ISO_BUILD"
printf "%-25s %s\n" "ISO Optical Boot"     "$CHECK_ISO_BOOT"
printf "%-25s %s\n" "Secrets"              "$CHECK_SECRETS"
printf "%-25s %s (%s paths)\n" "Source Tree" "$SOURCE_TREE_STATE" "$SOURCE_DIRTY_PATH_COUNT"
echo "========================================"
echo "P0 RESULT: $OVERALL"
echo "========================================"

case "$OVERALL" in
    PASS) exit 0 ;;
    FAIL) exit 1 ;;
    BLOCKED) exit 2 ;;
    *) echo "[P0] FATAL: invalid aggregate status: $OVERALL" >&2; exit 1 ;;
esac
