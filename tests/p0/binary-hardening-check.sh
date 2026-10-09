#!/usr/bin/env bash
# =============================================================================
# ExamOS P0 — Binary Hardening Verifier
# tests/p0/binary-hardening-check.sh
# Usage: ./binary-hardening-check.sh <path-to-elf-binary> [json|text]
# =============================================================================
set -euo pipefail

BINARY="${1:-}"
FORMAT="${2:-text}"

if [ -z "$BINARY" ] || [ ! -f "$BINARY" ]; then
    echo "Usage: $0 <path-to-elf-binary> [json|text]" >&2
    exit 1
fi

BINARY_NAME="$(basename "$BINARY")"
SCORE=0
TOTAL=6

# --- Check 1: PIE (Position Independent Executable) ---
PIE=false
PIE_DETAIL=""
ELF_TYPE=$(readelf -h "$BINARY" 2>/dev/null | grep -i 'Type:' | awk '{print $2}')
if [ "$ELF_TYPE" = "DYN" ]; then
    PIE=true
    PIE_DETAIL="ELF Type: DYN (shared object / PIE)"
    SCORE=$((SCORE + 1))
else
    PIE_DETAIL="ELF Type: $ELF_TYPE (not PIE)"
fi

# --- Check 2: Stack Canary ---
CANARY=false
CANARY_DETAIL=""
if readelf -s "$BINARY" 2>/dev/null | grep -q '__stack_chk_fail'; then
    CANARY=true
    CANARY_DETAIL="__stack_chk_fail symbol found"
    SCORE=$((SCORE + 1))
else
    CANARY_DETAIL="__stack_chk_fail symbol NOT found"
fi

# --- Check 3: RELRO (RELocation Read-Only) ---
RELRO="none"
RELRO_DETAIL=""
HAS_RELRO=$(readelf -l "$BINARY" 2>/dev/null | grep -c 'GNU_RELRO' || true)
HAS_BIND_NOW=$(readelf -d "$BINARY" 2>/dev/null | grep -c 'BIND_NOW' || true)
if [ "$HAS_RELRO" -gt 0 ] && [ "$HAS_BIND_NOW" -gt 0 ]; then
    RELRO="full"
    RELRO_DETAIL="GNU_RELRO + BIND_NOW (Full RELRO)"
    SCORE=$((SCORE + 1))
elif [ "$HAS_RELRO" -gt 0 ]; then
    RELRO="partial"
    RELRO_DETAIL="GNU_RELRO present but no BIND_NOW (Partial RELRO)"
    SCORE=$((SCORE + 1))
else
    RELRO_DETAIL="No GNU_RELRO segment found"
fi

# --- Check 4: NX (Non-Executable Stack) ---
NX=false
NX_DETAIL=""
STACK_LINE=$(readelf -l "$BINARY" 2>/dev/null | grep 'GNU_STACK' || true)
if [ -n "$STACK_LINE" ]; then
    STACK_FLAGS=$(echo "$STACK_LINE" | awk '{print $NF}')
    if echo "$STACK_FLAGS" | grep -q 'E'; then
        NX_DETAIL="GNU_STACK has Execute flag ($STACK_FLAGS) — stack is executable!"
    else
        NX=true
        NX_DETAIL="GNU_STACK flags: $STACK_FLAGS (no Execute — NX enabled)"
        SCORE=$((SCORE + 1))
    fi
else
    NX=true
    NX_DETAIL="No GNU_STACK segment (NX assumed by default on modern kernels)"
    SCORE=$((SCORE + 1))
fi

# --- Check 5: FORTIFY_SOURCE ---
FORTIFY=false
FORTIFY_DETAIL=""
FORTIFY_COUNT=$(readelf -s "$BINARY" 2>/dev/null | grep -cE '__[a-z]+_chk(@|$)' || true)
if [ "$FORTIFY_COUNT" -gt 0 ]; then
    FORTIFY=true
    FORTIFY_DETAIL="$FORTIFY_COUNT fortified function(s) detected"
    SCORE=$((SCORE + 1))
else
    FORTIFY_DETAIL="No fortified functions detected (_FORTIFY_SOURCE may not have triggered)"
fi

# --- Check 6: No RPATH/RUNPATH ---
RPATH=false
RPATH_DETAIL=""
RPATH_COUNT=$(readelf -d "$BINARY" 2>/dev/null | grep -cE 'RPATH|RUNPATH' || true)
if [ "$RPATH_COUNT" -eq 0 ]; then
    RPATH_DETAIL="No RPATH/RUNPATH set (clean)"
    SCORE=$((SCORE + 1))
else
    RPATH=true
    RPATH_VAL=$(readelf -d "$BINARY" 2>/dev/null | grep -E 'RPATH|RUNPATH' | head -1)
    RPATH_DETAIL="RPATH/RUNPATH found: $RPATH_VAL"
fi

# --- Grade ---
if [ "$SCORE" -eq 6 ]; then GRADE="A+";
elif [ "$SCORE" -eq 5 ]; then GRADE="A";
elif [ "$SCORE" -eq 4 ]; then GRADE="B";
elif [ "$SCORE" -eq 3 ]; then GRADE="C";
else GRADE="F"; fi

if [ "$FORMAT" = "json" ]; then
    cat <<JSONEOF
{"binary": "$BINARY", "name": "$BINARY_NAME", "pie": $PIE, "canary": $CANARY, "relro": "$RELRO", "nx": $NX, "fortify": $FORTIFY, "rpath": $RPATH, "score": "$SCORE/$TOTAL", "grade": "$GRADE", "details": {"pie": "$PIE_DETAIL", "canary": "$CANARY_DETAIL", "relro": "$RELRO_DETAIL", "nx": "$NX_DETAIL", "fortify": "$FORTIFY_DETAIL", "rpath": "$RPATH_DETAIL"}}
JSONEOF
else
    echo "╔══════════════════════════════════════════════════╗"
    echo "║  Binary Hardening Report: $BINARY_NAME"
    echo "╚══════════════════════════════════════════════════╝"
    printf "  %-20s %s\n" "PIE:" "$([ "$PIE" = true ] && echo "✓ PASS" || echo "✗ FAIL") — $PIE_DETAIL"
    printf "  %-20s %s\n" "Stack Canary:" "$([ "$CANARY" = true ] && echo "✓ PASS" || echo "✗ FAIL") — $CANARY_DETAIL"
    printf "  %-20s %s\n" "RELRO:" "$([ "$RELRO" != "none" ] && echo "✓ PASS ($RELRO)" || echo "✗ FAIL") — $RELRO_DETAIL"
    printf "  %-20s %s\n" "NX Stack:" "$([ "$NX" = true ] && echo "✓ PASS" || echo "✗ FAIL") — $NX_DETAIL"
    printf "  %-20s %s\n" "FORTIFY_SOURCE:" "$([ "$FORTIFY" = true ] && echo "✓ PASS" || echo "✗ WARN") — $FORTIFY_DETAIL"
    printf "  %-20s %s\n" "No RPATH:" "$([ "$RPATH" = false ] && echo "✓ PASS" || echo "✗ FAIL") — $RPATH_DETAIL"
    echo ""
    echo "  Score: $SCORE/$TOTAL  Grade: $GRADE"
fi
