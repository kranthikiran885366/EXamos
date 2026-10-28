# ==============================================================================
# SPPIO-Core Server Dockerfile (Optimized for Render Cloud & Container Deployments)
# ==============================================================================

# -----------------
# Stage 1: Builder
# -----------------
FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libpq-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy common headers and implementations
COPY common ./common

# Copy server code
COPY server ./server

# Build the native C binaries
WORKDIR /app/server
RUN make all

# -----------------
# Stage 2: Runtime
# -----------------
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    libpq5 \
    ca-certificates \
    curl \
    openssl \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy compiled native binaries
COPY --from=builder /app/server/examos-server /usr/local/bin/sppio-server
COPY --from=builder /app/server/examos-db-migrate /usr/local/bin/sppio-db-migrate
COPY --from=builder /app/server/examos-admin-provision /usr/local/bin/sppio-admin-provision

# Copy database schema migrations and seed scripts
COPY server/migrations /opt/sppio/migrations
COPY scripts/seed_admin_users.sql /opt/sppio/seed_admin_users.sql

# Copy server configuration and browser policy catalog
COPY server/config /opt/sppio/config
COPY server/config /usr/local/bin/config
COPY server/config /etc/examos

# Setup runtime storage directories
RUN mkdir -p /var/lib/examos /opt/sppio /var/log/examos /etc/examos

# Setup Render entrypoint
COPY docker/render-entrypoint.sh /usr/local/bin/render-entrypoint.sh
RUN chmod +x /usr/local/bin/render-entrypoint.sh

# Default port exposed by Render
EXPOSE 10000 8000

ENTRYPOINT ["/usr/local/bin/render-entrypoint.sh"]
