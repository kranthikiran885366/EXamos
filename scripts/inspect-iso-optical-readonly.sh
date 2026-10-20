#!/usr/bin/env bash
# Read-only inspection of the existing P0 ISO and historical optical-boot logs.
# Writes only to a unique evidence directory. Does not modify the ISO or old logs.
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/.." && pwd)"
EVIDENCE="${1:-}"
if [ -z "$EVIDENCE" ]; then
    echo "Usage: $0 <unique-evidence-dir>" >&2
    exit 2
fi
mkdir -p "$EVIDENCE"
ISO="$WORKSPACE/artifacts/p0/examos-p0.iso"
HIST_LOG="$WORKSPACE/artifacts/p0/iso-boot.log"
HIST_RESULT="$WORKSPACE/artifacts/p0/iso-boot-result.json"

{
    echo "=== provenance ==="
    echo "workspace=$WORKSPACE"
    echo "utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "source_commit=$(git -C "$WORKSPACE" rev-parse HEAD 2>/dev/null || echo UNKNOWN)"
    echo "source_tree_state=$(if [ -n "$(git -C "$WORKSPACE" status --porcelain --untracked-files=all 2>/dev/null)" ]; then echo DIRTY; else echo CLEAN; fi)"
    echo "dirty_path_count=$(git -C "$WORKSPACE" status --porcelain --untracked-files=all 2>/dev/null | wc -l | tr -d ' ')"
    echo "uname=$(uname -a)"
    echo "wsl=$(tr -d '\0' </proc/sys/kernel/osrelease 2>/dev/null || true)"
    echo "meminfo_available=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)"
    echo "meminfo_total=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
    echo "nproc=$(nproc)"
    echo "loadavg=$(cat /proc/loadavg)"
    qemu-system-x86_64 --version | head -n 1
    echo "=== iso ==="
    ls -l -- "$ISO" || true
    sha256sum -- "$ISO" || true
    echo "=== ovmf ==="
    for f in /usr/share/OVMF/OVMF_CODE_4M.fd /usr/share/OVMF/OVMF_VARS_4M.fd \
             /usr/share/OVMF/OVMF_CODE.fd /usr/share/OVMF/OVMF_CODE_4M.secboot.fd; do
        if [ -f "$f" ]; then
            echo "path=$f size=$(stat -c%s "$f") sha256=$(sha256sum "$f" | awk '{print $1}')"
        fi
    done
} > "$EVIDENCE/host-and-artifact-identity.txt" 2>&1

if [ -s "$ISO" ]; then
    xorriso -indev "$ISO" -report_el_torito plain > "$EVIDENCE/eltorito-report.txt" 2>&1 || true
    xorriso -indev "$ISO" -report_system_area plain > "$EVIDENCE/system-area-report.txt" 2>&1 || true
    xorriso -indev "$ISO" -ls / > "$EVIDENCE/iso-root-listing.txt" 2>&1 || true
    sfdisk --json "$ISO" > "$EVIDENCE/iso-gpt.json" 2>/dev/null || true
    isoinfo -d -i "$ISO" > "$EVIDENCE/isoinfo.txt" 2>&1 || true
    mkdir -p "$EVIDENCE/extract"
    xorriso -osirrox on -indev "$ISO" \
        -extract /EXAMOS-P0.txt "$EVIDENCE/extract/EXAMOS-P0.txt" \
        -extract /EXAMOS-P0.conf "$EVIDENCE/extract/EXAMOS-P0.conf" \
        >/dev/null 2>"$EVIDENCE/extract-metadata.err" || true
    # Extract EFI boot image and inspect BOOTX64.EFI without altering the ISO.
    if xorriso -osirrox on -indev "$ISO" -extract /efi-boot.img "$EVIDENCE/extract/efi-boot.img" >/dev/null 2>>"$EVIDENCE/extract-metadata.err"; then
        mdir -i "$EVIDENCE/extract/efi-boot.img" ::/EFI/BOOT > "$EVIDENCE/esp-boot-dir.txt" 2>&1 || true
        mcopy -i "$EVIDENCE/extract/efi-boot.img" ::/EFI/BOOT/BOOTX64.EFI "$EVIDENCE/extract/BOOTX64.EFI" 2>>"$EVIDENCE/extract-metadata.err" || true
        if [ -s "$EVIDENCE/extract/BOOTX64.EFI" ]; then
            sha256sum "$EVIDENCE/extract/BOOTX64.EFI" > "$EVIDENCE/uki.sha256"
            ls -l "$EVIDENCE/extract/BOOTX64.EFI" > "$EVIDENCE/uki-size.txt"
            objcopy --dump-section .cmdline="$EVIDENCE/extract/iso.cmdline" "$EVIDENCE/extract/BOOTX64.EFI" 2>"$EVIDENCE/objcopy.err" || true
            if [ -s "$EVIDENCE/extract/iso.cmdline" ]; then
                tr -d '\000' < "$EVIDENCE/extract/iso.cmdline" > "$EVIDENCE/iso-cmdline.txt"
            fi
            objcopy --dump-section .initrd="$EVIDENCE/extract/iso.initrd" "$EVIDENCE/extract/BOOTX64.EFI" 2>>"$EVIDENCE/objcopy.err" || true
            if [ -s "$EVIDENCE/extract/iso.initrd" ]; then
                sha256sum "$EVIDENCE/extract/iso.initrd" > "$EVIDENCE/initrd.sha256"
                ls -l "$EVIDENCE/extract/iso.initrd" > "$EVIDENCE/initrd-size.txt"
                mkdir -p "$EVIDENCE/initrd-inspect"
                # Last cpio archive is the optical overlay; inspect /init shebang and presence of bash/modules.
                python3 - <<'PY' "$EVIDENCE/extract/iso.initrd" "$EVIDENCE/initrd-inspect"
import io, os, sys, gzip, lzma, struct
path, outdir = sys.argv[1], sys.argv[2]
data = open(path, "rb").read()
# Unwrap possible compression of concatenated archives: Debian initrd is usually gzip members concatenated.
def try_decompress(blob):
    for opener in (gzip.decompress, lzma.decompress):
        try:
            return opener(blob)
        except Exception:
            pass
    return blob
raw = try_decompress(data)
open(os.path.join(outdir, "decompressed.note"), "w").write(f"input={len(data)} decompressed={len(raw)} gzip_magic={data[:2]==b'\\x1f\\x8b'}\n")
# Split newc cpio members named 'init' and list module presence heuristically.
names = []
off = 0
init_blobs = []
wanted_prefix = ("usr/lib/modules", "lib/modules", "usr/bin/bash", "bin/bash", "bin/sh", "init", "usr/sbin/switch_root", "sbin/switch_root")
hits = {k: 0 for k in wanted_prefix}
while off + 110 <= len(raw) and raw[off:off+6] == b"070701":
    namesize = int(raw[off+94:off+102], 16)
    filesize = int(raw[off+54:off+62], 16)
    name_start = off + 110
    name = raw[name_start:name_start+namesize-1].decode("utf-8", "replace")
    hdr_end = (name_start + namesize + 3) & ~3
    data_end = (hdr_end + filesize + 3) & ~3
    names.append(name)
    for k in hits:
        if name == k or name.startswith(k):
            hits[k] += 1
    if name == "init":
        init_blobs.append(raw[hdr_end:hdr_end+min(filesize, 4096)])
    if name == "TRAILER!!!":
        off = data_end
        # pad to next archive
        while off < len(raw) and raw[off] == 0:
            off += 1
        continue
    off = data_end
    if filesize == 0 and namesize == 0:
        break
open(os.path.join(outdir, "cpio-hits.txt"), "w").write("\n".join(f"{k}={v}" for k,v in hits.items()) + f"\ncpio_entries={len(names)}\ninit_copies={len(init_blobs)}\n")
open(os.path.join(outdir, "cpio-names-sample.txt"), "w").write("\n".join(names[:200] + ["..."] + names[-50:]))
for i, blob in enumerate(init_blobs):
    open(os.path.join(outdir, f"init-copy-{i}.head"), "wb").write(blob[:512])
PY
            fi
        fi
    fi
fi

if [ -s "$HIST_LOG" ]; then
    sha256sum -- "$HIST_LOG" > "$EVIDENCE/historical-iso-boot.log.sha256"
    python3 - <<'PY' "$HIST_LOG" "$EVIDENCE/historical-iso-boot.analysis.txt"
import sys, collections
src, dst = sys.argv[1], sys.argv[2]
data = open(src, "rb").read()
esc = data.count(b"\x1b")
nul = data.count(b"\x00")
cr = data.count(b"\r")
lf = data.count(b"\n")
text = data.decode("utf-8", "replace")
needles = [
    "Linux version", "systemd", "Reached target", "login:",
    "ExamOS ISO init", "Kernel command line", "examos.media=optical",
    "initramfs", "Failed to execute", "Kernel panic", "sr0", "iso9660",
]
found = {n: (n in text) for n in needles}
printable = sum(32 <= b <= 126 or b in (9,10,13) for b in data)
with open(dst, "w") as f:
    f.write(f"bytes={len(data)}\nesc={esc}\nnul={nul}\ncr={cr}\nlf={lf}\nprintable={printable}\n")
    f.write("markers:\n")
    for n,v in found.items():
        f.write(f"  {n}={v}\n")
    # first 400 printable-ish chars
    shown = "".join(chr(b) if 32 <= b <= 126 else "." for b in data[:400])
    f.write("head_ascii400=" + shown + "\n")
PY
    LC_ALL=C tr -d '\033' < "$HIST_LOG" | LC_ALL=C tr '\r' '\n' | head -c 20000 > "$EVIDENCE/historical-iso-boot.normalized.head.txt" || true
fi
cp --no-clobber -- "$HIST_RESULT" "$EVIDENCE/historical-iso-boot-result.json" 2>/dev/null || true
echo "Wrote $EVIDENCE"
