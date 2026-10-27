#!/usr/bin/env bash
# =============================================================================
# ExamOS — Oracle Cloud Infrastructure (OCI) Automated Deployment Script
# Supports: Ubuntu 22.04 / 24.04 LTS (x86_64)
# =============================================================================
set -euo pipefail

echo "======================================================================"
echo "    ExamOS Enterprise Cloud Server Deployment (Oracle Cloud)"
echo "======================================================================"

# 1. Update OS and Open Oracle Cloud Host Firewall
echo "--- 1. Configuring Host Firewall for Oracle Cloud ---"
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 80 -j ACCEPT
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 443 -j ACCEPT
sudo netfilter-persistent save 2>/dev/null || true

# 2. Install Prerequisites
echo "--- 2. Installing Packages (PostgreSQL, Nginx, Node.js, Build Tools) ---"
sudo apt-get update -y
sudo apt-get install -y \
    build-essential gcc make libssl-dev libpq-dev postgresql postgresql-contrib \
    nginx certbot python3-certbot-nginx curl git jq

# Install Node.js 20.x for building frontend
if ! command -v node >/dev/null 2>&1; then
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt-get install -y nodejs
fi

# 3. Setup PostgreSQL Database
echo "--- 3. Configuring PostgreSQL Database ---"
sudo systemctl enable --now postgresql

DB_NAME="examos"
DB_USER="examos_app"
DB_PASS="$(openssl rand -hex 16)"

sudo -u postgres psql -c "SELECT 1 FROM pg_database WHERE datname = '$DB_NAME'" | grep -q 1 || \
sudo -u postgres psql << EOF
CREATE DATABASE $DB_NAME;
CREATE USER $DB_USER WITH ENCRYPTED PASSWORD '$DB_PASS';
GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;
ALTER DATABASE $DB_NAME OWNER TO $DB_USER;
EOF

sudo -u postgres psql -d $DB_NAME -c "GRANT ALL ON SCHEMA public TO $DB_USER;"

# 4. Compile ExamOS Server
echo "--- 4. Compiling ExamOS Native Server ---"
cd /opt/examos/server
make clean || true
make all

# Run Database Migrations
echo "--- 5. Running Database Migrations ---"
PGPASSWORD="$DB_PASS" psql -h 127.0.0.1 -U "$DB_USER" -d "$DB_NAME" -f /opt/examos/server/migrations/001_initial_schema.sql 2>/dev/null || true
for mig in /opt/examos/server/migrations/*.sql; do
    PGPASSWORD="$DB_PASS" psql -h 127.0.0.1 -U "$DB_USER" -d "$DB_NAME" -f "$mig" 2>/dev/null || true
done

# 6. Build Frontend
echo "--- 6. Building React Frontend ---"
cd /opt/examos/frontend
npm install
npm run build
sudo mkdir -p /var/www/examos
sudo cp -r dist/* /var/www/examos/

# 7. Configure Environment Secrets
echo "--- 7. Configuring ExamOS Server Secrets ---"
sudo mkdir -p /etc/examos /var/log/examos /var/lib/examos
AGENT_TOKEN="$(openssl rand -hex 32)"
PROCTOR_TOKEN="$(openssl rand -hex 32)"
HMAC_KEY="$(openssl rand -hex 32)"

sudo tee /etc/examos/examos-cloud.env > /dev/null << EOF
EXAMOS_BIND_ADDR=127.0.0.1
EXAMOS_PORT=8000
EXAMOS_SERVER_PORT=8000
EXAMOS_TPM_MODE=production
EXAMOS_DATABASE_URL=postgresql://${DB_USER}:${DB_PASS}@127.0.0.1:5432/${DB_NAME}
PGHOST=127.0.0.1
PGPORT=5432
PGDATABASE=${DB_NAME}
PGUSER=${DB_USER}
PGPASSWORD=${DB_PASS}
EXAMOS_AGENT_API_TOKEN=${AGENT_TOKEN}
EXAMOS_PROCTOR_API_TOKEN=${PROCTOR_TOKEN}
EXAMOS_LEDGER_HMAC_KEY=${HMAC_KEY}
EXAMOS_LEDGER_PATH=/var/log/examos/event_ledger.log
EXAMOS_SESSION_JOURNAL=/var/log/examos/session_journal.log
EXAMOS_EVENT_CHAIN_PATH=/var/log/examos/proctoring_events.log
EXAMOS_DATA_DIR=/var/lib/examos
EXAMOS_ADMIN_COOKIE_SECURE=1
EOF

sudo chmod 600 /etc/examos/examos-cloud.env

# 8. Setup Systemd Service
echo "--- 8. Registering systemd Service ---"
sudo tee /etc/systemd/system/examos-server.service > /dev/null << 'EOF'
[Unit]
Description=ExamOS Cloud Central Security Server
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=root
EnvironmentFile=/etc/examos/examos-cloud.env
ExecStart=/opt/examos/server/examos-server
Restart=always
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now examos-server

# 9. Configure Nginx
echo "--- 9. Configuring Nginx Reverse Proxy & Dashboard ---"
sudo tee /etc/nginx/sites-available/examos > /dev/null << 'EOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    root /var/www/examos;
    index index.html;

    # Static Frontend SPA
    location / {
        try_files $uri $uri/ /index.html;
    }

    # Proxy ExamOS Server APIs
    location ~ ^/(api|admin|candidate)/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF

sudo ln -sf /etc/nginx/sites-available/examos /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl restart nginx

echo
echo "======================================================================"
echo "    ExamOS Successfully Deployed on Oracle Cloud!"
echo "======================================================================"
echo "1. Public Dashboard: http://$(curl -s ifconfig.me)"
echo "2. Backend API:      http://$(curl -s ifconfig.me)/api/v1/health"
echo "3. For HTTPS:        Run 'sudo certbot --nginx -d your-domain.com'"
echo "======================================================================"
