#!/usr/bin/env python3
"""Read-only SPPIO source, artifact, host, and virtual-hardware inventory."""

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
TOOLS = {
    "qemu-system-x86_64": ["qemu-system-x86_64", "--version"],
    "qemu-img": ["qemu-img", "--version"],
    "swtpm": ["swtpm", "--version"],
    "tpm2-tools": ["tpm2_getcap", "--version"],
    "tpm2-abrmd": ["tpm2-abrmd", "--version"],
    "ovmf": [],
    "sbsign": ["sbsign", "--version"],
    "pesign": ["pesign", "--version"],
    "ukify": ["ukify", "--version"],
    "systemd-measure": ["systemd-measure", "--version"],
    "cryptsetup": ["cryptsetup", "--version"],
    "veritysetup": ["veritysetup", "--version"],
    "mount": ["mount", "--version"],
    "openssl": ["openssl", "version"],
    "mokutil": ["mokutil", "--version"],
    "efibootmgr": ["efibootmgr", "--version"],
    "e2fsprogs": ["e2fsck", "-V"],
    "squashfs-tools": ["mksquashfs", "-version"],
    "jq": ["jq", "--version"],
    "python3": [sys.executable, "--version"],
    "shellcheck": ["shellcheck", "--version"],
    "bats": ["bats", "--version"],
    "postgresql-initdb": [],
    "postgresql-pg_ctl": [],
    "postgresql-psql": ["psql", "--version"],
}


def command_version(name, command):
    executable = shutil.which(command[0]) if command else None
    result = {
        "available": executable is not None,
        "path": executable,
        "version": None,
        "detail": None,
    }
    if not executable:
        return result
    if not command:
        return result
    try:
        completed = subprocess.run(
            command, check=False, capture_output=True, text=True, timeout=8
        )
        text = (completed.stdout + completed.stderr).strip().splitlines()
        result["version"] = text[0][:300] if text else f"exit {completed.returncode}"
        result["detail"] = "\n".join(text[:8])[:1600]
    except (OSError, subprocess.TimeoutExpired) as error:
        result["detail"] = str(error)
    return result


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def detect_partitions(path):
    partitions = []
    with path.open("rb") as image:
        mbr = image.read(512)
        if len(mbr) != 512:
            return partitions
        entries = []
        if mbr[510:512] == b"\x55\xaa":
            entries = [
                {
                    "index": index + 1,
                    "type": entry[4],
                    "start_lba": int.from_bytes(entry[8:12], "little"),
                    "sectors": int.from_bytes(entry[12:16], "little"),
                }
                for index in range(4)
                if (entry := mbr[446 + index * 16 : 462 + index * 16])[4] != 0
            ]
        if any(entry["type"] == 0xEE for entry in entries):
            image.seek(512)
            header = image.read(512)
            if header[:8] == b"EFI PART":
                entry_lba = int.from_bytes(header[72:80], "little")
                entry_count = int.from_bytes(header[80:84], "little")
                entry_size = int.from_bytes(header[84:88], "little")
                entries = []
                image.seek(entry_lba * 512)
                for index in range(min(entry_count, 256)):
                    record = image.read(entry_size)
                    if len(record) != entry_size or record[:16] == bytes(16):
                        continue
                    entries.append(
                        {
                            "index": index + 1,
                            "type_guid": record[:16].hex(),
                            "start_lba": int.from_bytes(record[32:40], "little"),
                            "end_lba": int.from_bytes(record[40:48], "little"),
                            "sectors": int.from_bytes(record[40:48], "little")
                            - int.from_bytes(record[32:40], "little")
                            + 1,
                        }
                    )
        for entry in entries:
            start = entry["start_lba"] * 512
            image.seek(start)
            boot = image.read(4096)
            fs = "unknown"
            if len(boot) >= 1082 and boot[1080:1082] == b"\x53\xef":
                fs = "ext filesystem (ext2/3/4 magic)"
            elif boot[:4] == b"hsqs":
                fs = "SquashFS"
            elif boot[3:11] == b"NTFS    ":
                fs = "NTFS"
            elif boot[54:62] in (b"FAT12   ", b"FAT16   ") or boot[82:90] == b"FAT32   ":
                fs = "FAT"
            entry["filesystem_magic"] = fs
            partitions.append(entry)
    return partitions


def memory_info():
    result = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith(("MemTotal:", "MemAvailable:")):
                key, value = line.split(":", 1)
                result[key] = value.strip()
    except OSError:
        pass
    return result


def git_probe(arguments, timeout=5):
    try:
        result = subprocess.run(
            ["git", "-C", str(ROOT), *arguments],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None, f"timed out after {timeout} seconds"
    except OSError as error:
        return None, f"could not execute git: {error}"
    if result.returncode != 0:
        return None, result.stderr.strip() or f"git exited with status {result.returncode}"
    return result.stdout.strip(), None


def ovmf_files():
    candidates = []
    for base in (Path("/usr/share/OVMF"), Path("/usr/share/edk2/ovmf")):
        if base.is_dir():
            for path in sorted(base.glob("OVMF_*.fd")):
                try:
                    candidates.append(
                        {
                            "path": str(path),
                            "size_bytes": path.stat().st_size,
                            "sha256": sha256_file(path),
                        }
                    )
                except OSError:
                    continue
    return candidates


def postgres_binary(name):
    for base in sorted(Path("/usr/lib/postgresql").glob("*/bin"), reverse=True):
        candidate = base / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    path = shutil.which(name)
    return path


def image_info(name):
    path = ROOT / "image" / name
    if not path.is_file():
        return {"path": str(path), "present": False}
    item = {
        "path": str(path),
        "present": True,
        "size_bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }
    if name == "examos.raw":
        item["partitions"] = detect_partitions(path)
    if name == "examos.iso":
        with path.open("rb") as stream:
            stream.seek(16 * 2048)
            descriptor = stream.read(2048)
        item["iso9660_primary_volume_descriptor"] = descriptor[1:6] == b"CD001"
    sidecar = path.with_suffix(path.suffix + ".sha256")
    if sidecar.is_file():
        expected = sidecar.read_text(encoding="utf-8").split()[0].lower()
        item["sidecar_sha256"] = expected
        item["sidecar_matches"] = expected == item["sha256"]
    return item


def source_audit():
    mkosi = ROOT / "image" / "mkosi.conf"
    verity = ROOT / "image" / "scripts" / "dm-verity-setup.sh"
    trust = ROOT / "image" / "config" / "p3.conf"
    mkosi_text = mkosi.read_text(encoding="utf-8") if mkosi.exists() else ""
    verity_text = verity.read_text(encoding="utf-8") if verity.exists() else ""
    trust_text = trust.read_text(encoding="utf-8") if trust.exists() else ""
    return {
        "image_build": {
            "configuration": str(mkosi.relative_to(ROOT)),
            "declares_disk_output": "Format=disk" in mkosi_text,
            "bootloader": next(
                (line.split("=", 1)[1] for line in mkosi_text.splitlines()
                 if line.startswith("Bootloader=")),
                None,
            ),
            "declares_uki_or_secureboot": any(
                token in mkosi_text.lower()
                for token in ("uki", "secureboot", "secure-boot")
            ),
        },
        "dm_verity": {
            "post_build_setup_script": str(verity.relative_to(ROOT)),
            "present": verity.exists(),
            "explicitly_host_artifact_only": "HOST_ARTIFACT_ONLY" in verity_text,
            "descriptor_only_boot_integration": "NOT_INTEGRATED" in verity_text,
        },
        "p3_configuration": {
            "path": str(trust.relative_to(ROOT)),
            "present": trust.exists(),
            "declares_measured_pcrs": "MEASURED_PCRS=0,4,7,11" in trust_text,
            "physical_device_workflow": (ROOT / "scripts" / "enroll-physical-tpm.sh").exists(),
            "signed_registry_loader": (ROOT / "server" / "attestation" / "attestation_config.c").exists(),
            "database_attestation_test": (ROOT / "tests" / "server" / "attestation_db_integration_test.c").exists(),
        },
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)

    tools = {}
    for name, command in TOOLS.items():
        if name == "ovmf":
            files = ovmf_files()
            tools[name] = {
                "available": bool(files),
                "files": files,
                "version": None,
            }
        elif name == "postgresql-initdb":
            path = postgres_binary("initdb")
            tools[name] = {"available": bool(path), "path": path, "version": None}
        elif name == "postgresql-pg_ctl":
            path = postgres_binary("pg_ctl")
            tools[name] = {"available": bool(path), "path": path, "version": None}
        else:
            tools[name] = command_version(name, command)

    accelerators = []
    qemu = shutil.which("qemu-system-x86_64")
    if qemu:
        result = subprocess.run(
            [qemu, "-accel", "help"], capture_output=True, text=True, timeout=8
        )
        accelerators = [
            line.strip() for line in (result.stdout + result.stderr).splitlines()
            if line.strip() and line.strip() not in ("Accelerators supported in QEMU binary:",)
        ]
    kvm_path = Path("/dev/kvm")
    hardware_devices = {
        name: Path(name).exists()
        for name in ("/dev/tpm0", "/dev/tpmrm0")
    }
    try:
        stat = kvm_path.stat()
        kvm = {
            "present": True,
            "readable": os.access(kvm_path, os.R_OK),
            "writable": os.access(kvm_path, os.W_OK),
            "mode": oct(stat.st_mode & 0o777),
        }
    except OSError:
        kvm = {"present": False, "readable": False, "writable": False}

    disk = shutil.disk_usage(ROOT)
    host = {
        "platform": platform.platform(),
        "kernel": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "wsl": bool(os.environ.get("WSL_DISTRO_NAME") or "microsoft" in platform.release().lower()),
        "wsl_distro_name": os.environ.get("WSL_DISTRO_NAME"),
        "cpu_count": os.cpu_count(),
        "memory": memory_info(),
        "workspace_disk": {
            "path": str(ROOT),
            "total_bytes": disk.total,
            "free_bytes": disk.free,
        },
        "qemu_accelerators_reported": accelerators,
        "kvm": kvm,
        "physical_tpm_device_nodes_present": hardware_devices,
    }
    images = {
        name: image_info(name)
        for name in (
            "examos.raw",
            "examos.iso",
            "examos.vmlinuz",
            "examos.initrd",
        )
    }
    git_status_text, git_status_error = git_probe(
        ["status", "--short", "--untracked-files=no"]
    )
    commit_text, commit_error = git_probe(["rev-parse", "HEAD"])
    branch_text, branch_error = git_probe(["branch", "--show-current"])
    record = {
        "schema": "sppio.virtual-hardware.inventory.v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "workspace": str(ROOT),
        "git_commit": commit_text,
        "git_commit_error": commit_error,
        "git_branch": branch_text,
        "git_branch_error": branch_error,
        "git_worktree_status": git_status_text.splitlines() if git_status_text is not None else None,
        "git_worktree_status_error": git_status_error,
        "git_status_scope": "tracked files only; untracked files are not included",
        "host": host,
        "tools": tools,
        "images": images,
        "source_implementation": source_audit(),
        "safety": {
            "production_database_touched": False,
            "physical_tpm_accessed": False,
            "physical_firmware_or_disks_modified": False,
            "production_signing_keys_used": False,
        },
    }
    worktree_state = (
        "unknown"
        if git_status_text is None
        else "yes" if git_status_text else "no"
    )
    json_path = output / "toolchain-inventory.json"
    with json_path.open("x", encoding="utf-8") as stream:
        json.dump(record, stream, indent=2, sort_keys=True)
        stream.write("\n")

    phase0 = {
        "schema": "sppio.virtual-hardware.phase0-inventory.v1",
        "generated_at_utc": record["generated_at_utc"],
        "source_commit": record["git_commit"],
        "source_branch": record["git_branch"],
        "worktree_status": record["git_worktree_status"],
        "worktree_status_error": record["git_worktree_status_error"],
        "existing_image_architecture": record["source_implementation"]["image_build"],
        "existing_tpm_and_attestation": record["source_implementation"]["p3_configuration"],
        "existing_dm_verity": record["source_implementation"]["dm_verity"],
        "image_artifacts": images,
        "environment": host,
        "toolchain": tools,
        "compatibility_assessment": {
            "qemu_tcg_available": "tcg" in accelerators,
            "kvm_device_accessible": kvm["present"] and kvm["readable"] and kvm["writable"],
            "kvm_acceleration_runtime_tested": False,
            "wsl_firmware_limitation": host["wsl"],
            "physical_tpm_tested": False,
            "production_database_tested": False,
        },
        "preservation": {
            "raw_image_modified": False,
            "iso_modified": False,
            "existing_postgres_data_modified": False,
            "host_firmware_or_physical_disks_modified": False,
        },
    }
    phase0_path = output / "phase0-inventory.json"
    with phase0_path.open("x", encoding="utf-8") as stream:
        json.dump(phase0, stream, indent=2, sort_keys=True)
        stream.write("\n")

    lines = [
        "# Virtual Hardware and Repository Inventory",
        "",
        f"- Generated: `{record['generated_at_utc']}`",
        f"- Workspace: `{ROOT}`",
        f"- Commit: `{record['git_commit'] or 'unavailable'}`",
        f"- Branch: `{record['git_branch'] or 'unavailable'}`",
        f"- Tracked worktree changes: `{worktree_state}`.",
        f"- Git status scope: `{record['git_status_scope']}`.",
        *(
            [f"- Git status note: `{git_status_error}`."]
            if git_status_error else []
        ),
        f"- Host: `{host['platform']}`",
        f"- WSL: `{host['wsl']}` ({host['wsl_distro_name'] or 'not identified'})",
        f"- CPUs: `{host['cpu_count']}`",
        f"- Workspace free bytes: `{disk.free}`",
        "",
        "## Toolchain",
        "",
        "| Tool | Available | Version / detail |",
        "|---|---:|---|",
    ]
    for name, value in tools.items():
        detail = value.get("version") or value.get("path")
        if not detail and value.get("files"):
            detail = ", ".join(item["path"] for item in value["files"])
        if not detail:
            detail = "not found"
        lines.append(f"| `{name}` | {'yes' if value['available'] else 'no'} | `{str(detail).replace('|', '/').replace('`', '')}` |")
    lines.extend(
        [
            "",
            "## Virtualization",
            "",
            f"- QEMU accelerators reported: `{', '.join(accelerators) or 'unavailable'}`",
            f"- `/dev/kvm`: `{kvm}`",
            f"- Physical TPM nodes detected (not opened): `{hardware_devices}`",
            "",
            "## Existing image artifacts",
            "",
        ]
    )
    for name, image in images.items():
        if not image["present"]:
            lines.append(f"- `{name}`: not present.")
            continue
        lines.append(
            f"- `{name}`: {image['size_bytes']} bytes; SHA-256 `{image['sha256']}`."
        )
        if "sidecar_matches" in image and not image["sidecar_matches"]:
            lines.append(
                f"  Existing sidecar SHA-256 `{image['sidecar_sha256']}` does not match the current file."
            )
        if image.get("partitions"):
            for part in image["partitions"]:
                lines.append(
                    f"  Partition {part['index']}: LBA {part['start_lba']}, "
                    f"{part['sectors']} sectors; detected `{part['filesystem_magic']}`."
                )
    lines.extend(
        [
            "",
            "A structured Phase 0 source and environment inventory is recorded in `phase0-inventory.json`.",
            "",
            "## Existing implementation",
            "",
            "- The current mkosi profile produces a disk image and selects its configured bootloader.",
            "- The dm-verity setup is a host-side artifact-generation path; its own manifest states that the root hash is not yet integrated into boot.",
            "- P3 configuration names PCRs 0, 4, 7, and 11. The source includes physical TPM enrollment, signed-registry loading, and a PostgreSQL attestation integration test.",
            "- Existing generated VM, image, trust, and evidence files were not modified by inventory collection.",
            "",
            "## Safety",
            "",
            "- Read-only inventory only; no packages installed, services started, disks mounted, or TPM commands sent.",
            "- This report does not establish physical TPM, Secure Boot enforcement, organization approval, or production readiness.",
            "",
        ]
    )
    md_path = output / "toolchain-inventory.md"
    with md_path.open("x", encoding="utf-8") as stream:
        stream.write("\n".join(lines))
    missing = [name for name, value in tools.items() if not value["available"]]
    audit_lines = [
        "# Phase 0 Repository and Environment Audit",
        "",
        f"- Commit: `{record['git_commit'] or 'unavailable'}`",
        f"- Branch: `{record['git_branch'] or 'unavailable'}`",
        f"- Tracked worktree changes: `{worktree_state}`.",
        f"- Git status scope: `{record['git_status_scope']}`.",
        *(
            [f"- Git status note: `{git_status_error}`."]
            if git_status_error else []
        ),
        f"- Host: `{host['platform']}`",
        f"- WSL: `{host['wsl']}`",
        "",
        "## Existing SPPIO implementation",
        "",
        f"- Image profile: `{record['source_implementation']['image_build']['configuration']}`; disk output is {record['source_implementation']['image_build']['declares_disk_output']}; configured bootloader is `{record['source_implementation']['image_build']['bootloader']}`.",
        f"- Signed UKI/Secure Boot declared in the active mkosi profile: `{record['source_implementation']['image_build']['declares_uki_or_secureboot']}`.",
        f"- dm-verity tooling: host artifact generation exists; `HOST_ARTIFACT_ONLY` marker is `{record['source_implementation']['dm_verity']['explicitly_host_artifact_only']}` and boot integration marker is `{record['source_implementation']['dm_verity']['descriptor_only_boot_integration']}`.",
        "- P3 source includes TPM enrollment, signed device/release registries, TPM quote verification, institution-bound registry work, and database attestation integration tests.",
        "",
        "## Current image artifacts and checksum status",
        "",
    ]
    for name, image in images.items():
        if not image["present"]:
            audit_lines.append(f"- `{name}`: unavailable.")
        else:
            audit_lines.append(
                f"- `{name}`: {image['size_bytes']} bytes; current SHA-256 `{image['sha256']}`."
            )
            if image.get("sidecar_matches") is False:
                audit_lines.append(
                    f"  **Finding:** recorded sidecar `{image['sidecar_sha256']}` does not match the current file."
                )
            for partition in image.get("partitions", []):
                audit_lines.append(
                    f"  Partition {partition['index']}: {partition['filesystem_magic']}."
                )
    audit_lines.extend(
        [
            "",
            "## Host and compatibility",
            "",
            f"- QEMU accelerators reported: `{', '.join(accelerators) or 'none'}`.",
            f"- KVM device present/readable/writable: `{kvm['present']}/{kvm['readable']}/{kvm['writable']}`; acceleration still requires an actual QEMU launch.",
            f"- Physical TPM device nodes detected (not accessed): `{hardware_devices}`.",
            "- WSL virtual UEFI and software TPM can validate software workflows only; they cannot establish physical TPM or host firmware behavior.",
            "",
            "## Missing tools",
            "",
        ]
    )
    audit_lines.extend(f"- `{name}`" for name in missing)
    if not missing:
        audit_lines.append("- None of the enumerated tools.")
    audit_lines.extend(
        [
            "",
            "## Safe implementation plan",
            "",
            "1. Keep all test keys, TPM state, UEFI variables, disk overlays, database files, and evidence isolated per run.",
            "2. Use QEMU KVM only after a real launch succeeds; otherwise select TCG.",
            "3. Execute software TPM quote/credential, signed-UKI artifact, dm-verity corruption, and disposable PostgreSQL tests.",
            "4. Mark firmware enforcement, event-log reconstruction, dm-verity boot integration, backend API integration, and physical hardware as BLOCKED unless actual evidence is produced.",
            "5. Hash evidence for later comparison, while explicitly avoiding claims of immutability or production readiness.",
            "",
            "This is a read-only source/environment audit. It did not install tools, start a VM, contact production services, access a physical TPM, or modify existing image/database data.",
            "",
        ]
    )
    phase0_md = output / "phase0-inventory.md"
    with phase0_md.open("x", encoding="utf-8") as stream:
        stream.write("\n".join(audit_lines))
    print(json.dumps({"json": str(json_path), "markdown": str(md_path)}))


if __name__ == "__main__":
    main()
