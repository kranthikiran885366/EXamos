#!/usr/bin/env bash
set -euo pipefail

install -d -o root -g root -m 0750 /etc/examos
install -d -o root -g root -m 0750 /var/log/examos

# Production credentials are provisioned after installation by the approved
# deployment workflow. An unprovisioned image must deny administrator login.
temporary="$(mktemp /etc/examos/.admin.conf.XXXXXX)"
trap 'rm -f -- "$temporary"' EXIT
cat > "$temporary" <<'EOF'
ADMIN_USERNAME=NOT_PROVISIONED
ADMIN_PASSWORD_PBKDF2=NOT_PROVISIONED
EOF
chown root:root "$temporary"
chmod 0600 "$temporary"
mv -f -- "$temporary" /etc/examos/admin.conf
trap - EXIT
chmod 0750 /var/log/examos
