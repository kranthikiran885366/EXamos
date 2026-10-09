#!/usr/bin/env bash
set -euo pipefail

# ExamOS P3 Test Secure Boot Key Generator
# FOR DEVELOPMENT AND CI TESTING ONLY - NEVER USE IN PRODUCTION

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TRUST_DIR="$SCRIPT_DIR"
mkdir -p "$TRUST_DIR"

echo "=== [ExamOS P3] Generating Test Secure Boot & UKI Keys ==="

# 1. Platform Key (PK)
if [ ! -f "$TRUST_DIR/PK.key" ]; then
    openssl req -new -x509 -newkey rsa:2048 -subj "/CN=ExamOS Test Platform Key (PK)/" \
        -keyout "$TRUST_DIR/PK.key" -out "$TRUST_DIR/PK.crt" -days 365 -nodes -sha256
    chmod 600 "$TRUST_DIR/PK.key"
fi

# 2. Key Exchange Key (KEK)
if [ ! -f "$TRUST_DIR/KEK.key" ]; then
    openssl req -new -x509 -newkey rsa:2048 -subj "/CN=ExamOS Test Key Exchange Key (KEK)/" \
        -keyout "$TRUST_DIR/KEK.key" -out "$TRUST_DIR/KEK.crt" -days 365 -nodes -sha256
    chmod 600 "$TRUST_DIR/KEK.key"
fi

# 3. Signature Database (db) & UKI Signing Key
if [ ! -f "$TRUST_DIR/db.key" ]; then
    openssl req -new -x509 -newkey rsa:2048 -subj "/CN=ExamOS Test Secure Boot Database (db)/" \
        -keyout "$TRUST_DIR/db.key" -out "$TRUST_DIR/db.crt" -days 365 -nodes -sha256
    chmod 600 "$TRUST_DIR/db.key"
fi

# 4. PCR Policy Signing Key
if [ ! -f "$TRUST_DIR/pcr-policy.key" ]; then
    openssl req -new -x509 -newkey rsa:2048 -subj "/CN=ExamOS Test PCR Policy Key/" \
        -keyout "$TRUST_DIR/pcr-policy.key" -out "$TRUST_DIR/pcr-policy.crt" -days 365 -nodes -sha256
    chmod 600 "$TRUST_DIR/pcr-policy.key"
fi

echo "=== [ExamOS P3] Test keys created in $TRUST_DIR ==="
