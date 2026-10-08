#!/usr/bin/env bash
set -euo pipefail

echo "=== [ExamOS Build] Setting up Admin Portal Credentials ==="

mkdir -p /etc/examos
mkdir -p /var/log/examos

# Compute SHA-256 of default admin password 'ExamOS@Admin2025!'
ADMIN_HASH=$(echo -n 'ExamOS@Admin2025!' | sha256sum | cut -d' ' -f1)

cat > /etc/examos/admin.conf << EOF
# ExamOS Admin Portal Credentials
# Default password: ExamOS@Admin2025!
ADMIN_PASSWORD_SHA256=${ADMIN_HASH}
EOF

if [ ! -f /etc/examos/exam.conf ]; then
cat > /etc/examos/exam.conf << 'EOF'
EXAM_URL=NOT_CONFIGURED
EXAM_NAME=ExamOS Final Examination
EXAM_DURATION_MINUTES=120
EOF
fi

chmod 0600 /etc/examos/admin.conf
chmod 0644 /etc/examos/exam.conf
chmod 0750 /var/log/examos

echo "=== [ExamOS Build] Admin credentials configured ==="
