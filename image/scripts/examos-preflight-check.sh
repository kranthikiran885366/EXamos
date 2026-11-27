#!/usr/bin/env bash
# ExamOS — 10-Second Pre-Flight Hardware Check
# Produces a green/red readiness report for webcam, microphone, network,
# TPM 2.0, and AC power before an examination session begins.
set -euo pipefail

OUT_JSON="${1:-/run/examos/preflight-check.json}"
mkdir -p "$(dirname "$OUT_JSON")"

check_webcam() {
    for dev in /dev/video*; do
        [ -c "$dev" ] && { echo "PASS|$dev"; return 0; }
    done
    echo "FAIL|No V4L2 camera device found"
    return 1
}

check_mic() {
    if ls /dev/snd/pcm*c >/dev/null 2>&1 || (command -v pactl >/dev/null 2>&1 && pactl list short sources 2>/dev/null | grep -qv monitor); then
        echo "PASS|Audio capture interface present"
        return 0
    fi
    echo "FAIL|No microphone capture device found"
    return 1
}

check_network() {
    if ip -o link show up 2>/dev/null | awk -F': ' '{print $2}' | grep -qv '^lo$'; then
        echo "PASS|Active network interface up"
        return 0
    fi
    echo "FAIL|No active non-loopback network link"
    return 1
}

check_tpm() {
    if [ -c /dev/tpmrm0 ] || [ -c /dev/tpm0 ]; then
        echo "PASS|TPM 2.0 device present"
        return 0
    fi
    echo "FAIL|TPM 2.0 (/dev/tpmrm0) missing"
    return 1
}

check_power() {
    for ps in /sys/class/power_supply/AC*/online /sys/class/power_supply/ACAD*/online /sys/class/power_supply/ADP*/online; do
        if [ -r "$ps" ] && [ "$(cat "$ps" 2>/dev/null)" = "1" ]; then
            echo "PASS|AC power connected"
            return 0
        fi
    done
    if [ -d /sys/class/power_supply ] && ! ls /sys/class/power_supply/BAT* >/dev/null 2>&1; then
        echo "PASS|Desktop AC workstation"
        return 0
    fi
    echo "WARN|Running on battery — connect AC adapter"
    return 0
}

CAM_RES=$(check_webcam || true)
MIC_RES=$(check_mic || true)
NET_RES=$(check_network || true)
TPM_RES=$(check_tpm || true)
PWR_RES=$(check_power || true)

OVERALL="PASS"
for r in "$CAM_RES" "$MIC_RES" "$NET_RES" "$TPM_RES"; do
    case "$r" in FAIL*) OVERALL="FAIL" ;; esac
done

printf '{"overall":"%s","webcam":"%s","microphone":"%s","network":"%s","tpm":"%s","power":"%s"}\n' \
    "$OVERALL" "${CAM_RES#*|}" "${MIC_RES#*|}" "${NET_RES#*|}" "${TPM_RES#*|}" "${PWR_RES#*|}" > "${OUT_JSON}.tmp"
mv -f "${OUT_JSON}.tmp" "$OUT_JSON"

printf "[Pre-Flight] Webcam:     %s\n" "$CAM_RES"
printf "[Pre-Flight] Microphone: %s\n" "$MIC_RES"
printf "[Pre-Flight] Network:    %s\n" "$NET_RES"
printf "[Pre-Flight] TPM 2.0:    %s\n" "$TPM_RES"
printf "[Pre-Flight] Power:      %s\n" "$PWR_RES"
printf "[Pre-Flight] Overall:    %s\n" "$OVERALL"

[ "$OVERALL" = "PASS" ]
