#!/usr/bin/env bash
set -euo pipefail
RAW="/home/krant/.local/share/examos-kiosk-build.k6ROOc/kiosk-readiness-crashpad-trace.raw"
LOOP=$(losetup -fP --show "$RAW")
MNT="/mnt/trace_inspect"
mkdir -p "$MNT"
mount "${LOOP}p2" "$MNT"

echo "=== /etc/chromium.d/ in raw image ==="
ls -la "$MNT/etc/chromium.d/" 2>/dev/null || echo "(directory does not exist)"
for f in "$MNT"/etc/chromium.d/*; do
    [ -f "$f" ] || continue
    echo "--- $(basename "$f") ---"
    cat "$f"
done

echo ""
echo "=== /usr/lib/chromium/ - chromium binary type ==="
file "$MNT/usr/lib/chromium/chromium" || true
echo ""
echo "=== strings: crash-dumps-dir, BREAKPAD_DUMP, DIR_CRASH in chromium binary ==="
strings "$MNT/usr/lib/chromium/chromium" | grep -iE 'crash.dumps.dir|BREAKPAD_DUMP|DIR_CRASH_DUMPS|GetCrashDumpLocation' | head -n 20 || true

echo ""
echo "=== strings: GetCollectStatsConsent in chromium binary ==="
strings "$MNT/usr/lib/chromium/chromium" | grep -i 'GetCollectStatsConsent\|collect_stats\|stats_consent' | head -n 10 || true

umount "$MNT"
losetup -d "$LOOP"
echo "=== DONE ==="
