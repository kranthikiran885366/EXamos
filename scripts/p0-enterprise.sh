#!/usr/bin/env bash
# =============================================================================
# ExamOS P0 — Enterprise Master Orchestrator
# scripts/p0-enterprise.sh
#
# Runs the complete P0 pipeline PLUS the enterprise certification suite.
# 1. Basic P0 build & boot pipeline (scripts/p0.sh)
# 2. Enterprise validation & certification (tests/p0/enterprise-validate.sh)
# 3. Final combined summary
# =============================================================================
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/.." && pwd)"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     ExamOS P0 — Enterprise Master Orchestrator              ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Phase 1: Basic P0 Pipeline (build + boot)                  ║"
echo "║  Phase 2: Enterprise Certification (60+ dynamic checks)     ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ── Phase 1: Basic P0 Pipeline ──
echo "═══════════════════════════════════════════════════════════════"
echo "  PHASE 1: Running P0 Build & Boot Pipeline"
echo "═══════════════════════════════════════════════════════════════"
echo ""

P0_EXIT=0
if bash "$WORKSPACE/scripts/p0.sh"; then
    echo ""
    echo "[P0-ENT] Phase 1 (Basic P0): PASS"
else
    P0_EXIT=$?
    echo ""
    echo "[P0-ENT] Phase 1 (Basic P0): FAIL (exit $P0_EXIT)"
    echo "[P0-ENT] Continuing with enterprise validation anyway..."
fi

echo ""

# ── Phase 2: Enterprise Certification ──
echo "═══════════════════════════════════════════════════════════════"
echo "  PHASE 2: Running Enterprise Certification Suite"
echo "═══════════════════════════════════════════════════════════════"
echo ""

ENT_EXIT=0
if bash "$WORKSPACE/tests/p0/enterprise-validate.sh"; then
    echo ""
    echo "[P0-ENT] Phase 2 (Enterprise): PASS"
else
    ENT_EXIT=$?
    echo ""
    echo "[P0-ENT] Phase 2 (Enterprise): FAIL (exit $ENT_EXIT)"
fi

echo ""

# ── Combined Summary ──
echo "═══════════════════════════════════════════════════════════════"
echo "  COMBINED P0 ENTERPRISE RESULT"
echo "═══════════════════════════════════════════════════════════════"
echo ""

if [ "$P0_EXIT" -eq 0 ] && [ "$ENT_EXIT" -eq 0 ]; then
    echo "  Basic P0 Pipeline:          PASS"
    echo "  Enterprise Certification:   PASS"
    echo ""
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║  P0 ENTERPRISE CERTIFICATION: PASS       ║"
    echo "  ╚══════════════════════════════════════════╝"

    # Tag commit
    GIT_HASH=$(git -C "$WORKSPACE" rev-parse --short HEAD 2>/dev/null || echo "UNKNOWN")
    TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
    echo ""
    echo "  Git: $GIT_HASH"
    echo "  Certification: artifacts/p0/enterprise/certification.json"
    echo ""
    exit 0
else
    echo "  Basic P0 Pipeline:          $([ $P0_EXIT -eq 0 ] && echo PASS || echo FAIL)"
    echo "  Enterprise Certification:   $([ $ENT_EXIT -eq 0 ] && echo PASS || echo FAIL)"
    echo ""
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║  P0 ENTERPRISE CERTIFICATION: FAIL       ║"
    echo "  ╚══════════════════════════════════════════╝"
    echo ""
    exit 1
fi
