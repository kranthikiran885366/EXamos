# Event Pipeline Production Deployment Guide

## Overview

The ExamOS Event Pipeline is a production-grade, durable event management system for security and operational events. It features dynamic configuration, memory-efficient operations, and comprehensive event tracking.

## Key Features

- **Dynamic Memory Allocation**: All data structures are dynamically allocated based on configuration
- **Flexible Configuration**: Configure via file or environment variables
- **Durable Storage**: Write-ahead log with automatic rotation
- **Thread-Safe Operations**: Pthread mutex protection for all operations
- **Production-Ready**: No hardcoded values, proper error handling, and resource cleanup

## Configuration

### Configuration File

Create `/etc/examos/event_pipeline.conf`:

```ini
# Journal Settings
journal_path=/var/log/examos/event_pipeline.log
journal_max_size_mb=100
journal_rotation_count=5

# Cache Settings
event_cache_size=10000
cache_eviction_policy=0

# Alert Settings
max_alert_rules=128
default_dedup_window_sec=300

# Deduplication Settings
deduplication_enabled=1
dedup_hash_table_size=1024

# Performance Settings
flush_interval_ms=1000
batch_write_size=10
async_writes_enabled=0

# Security Settings
validate_sensitive_data=1
sanitize_details=1

# Runtime Limits
max_event_details_len=512
max_evidence_refs_len=256
max_concurrent_searches=10
```

### Environment Variables

Alternatively, configure via environment variables:

```bash
export EXAMOS_EVENT_JOURNAL="/var/log/examos/event_pipeline.log"
export EXAMOS_EVENT_JOURNAL_MAX_SIZE_MB="100"
export EXAMOS_EVENT_JOURNAL_ROTATION="5"
export EXAMOS_EVENT_CACHE_SIZE="10000"
export EXAMOS_EVENT_CACHE_POLICY="0"
export EXAMOS_EVENT_MAX_ALERT_RULES="128"
export EXAMOS_EVENT_DEDUP_WINDOW="300"
export EXAMOS_EVENT_DEDUP_ENABLED="1"
export EXAMOS_EVENT_DEDUP_HASH_SIZE="1024"
export EXAMOS_EVENT_FLUSH_INTERVAL_MS="1000"
export EXAMOS_EVENT_BATCH_WRITE_SIZE="10"
export EXAMOS_EVENT_ASYNC_WRITES="0"
export EXAMOS_EVENT_VALIDATE_SENSITIVE="1"
export EXAMOS_EVENT_SANITIZE_DETAILS="1"
export EXAMOS_EVENT_MAX_DETAILS_LEN="512"
export EXAMOS_EVENT_MAX_EVIDENCE_LEN="256"
export EXAMOS_EVENT_MAX_CONCURRENT_SEARCHES="10"
export EXAMOS_EVENT_CONFIG_PATH="/etc/examos/event_pipeline.conf"
```

## Deployment Steps

### 1. System Preparation

```bash
# Create required directories
sudo mkdir -p /var/log/examos
sudo mkdir -p /etc/examos

# Set permissions
sudo chown examos:examos /var/log/examos
sudo chmod 750 /var/log/examos
```

### 2. Install Configuration

```bash
# Copy configuration file
sudo cp event_pipeline.conf /etc/examos/event_pipeline.conf

# Set permissions
sudo chmod 640 /etc/examos/event_pipeline.conf
sudo chown root:examos /etc/examos/event_pipeline.conf
```

### 3. Build and Install

```bash
cd server
make clean
make

# Install binary
sudo make install
```

### 4. Configure Systemd Service

Create `/etc/systemd/system/examos-server.service`:

```ini
[Unit]
Description=ExamOS Server with Event Pipeline
After=network.target postgresql.service

[Service]
Type=simple
User=examos
Group=examos
WorkingDirectory=/opt/examos
Environment="EXAMOS_EVENT_CONFIG_PATH=/etc/examos/event_pipeline.conf"
Environment="EXAMOS_DATA_DIR=/var/lib/examos"
Environment="EXAMOS_DATABASE_URL_FILE=/etc/examos/secrets/db_url"
ExecStart=/usr/local/bin/examos-server
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/examos /var/lib/examos

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable examos-server
sudo systemctl start examos-server
```

### 5. Verify Installation

```bash
# Check service status
sudo systemctl status examos-server

# View logs
sudo journalctl -u examos-server -f

# Check journal file
ls -la /var/log/examos/event_pipeline.log
```

## Configuration Tuning

### High-Volume Environments

For systems with high event throughput:

```ini
event_cache_size=50000
journal_max_size_mb=500
journal_rotation_count=10
batch_write_size=50
flush_interval_ms=500
dedup_hash_table_size=4096
```

### Low-Memory Environments

For systems with limited memory:

```ini
event_cache_size=1000
journal_max_size_mb=50
journal_rotation_count=3
batch_write_size=5
flush_interval_ms=2000
dedup_hash_table_size=256
```

### Security-Critical Environments

For maximum security:

```ini
validate_sensitive_data=1
sanitize_details=1
deduplication_enabled=1
default_dedup_window_sec=600
```

## Monitoring

### Check Event Pipeline Status

```bash
# Get statistics via API
curl -X GET http://localhost:8080/api/v1/events/stats \
  -H "Cookie: admin_session=<valid_session>"

# Expected response:
{
  "total_events": 12345,
  "events_by_severity": [1000, 5000, 4000, 2000, 345],
  "events_by_classification": [8000, 3000, 1345],
  "events_last_hour": 150,
  "events_last_24h": 3500,
  "open_alerts": 5,
  "unresolved_incidents": 2,
  "last_event_time": 1697845200
}
```

### Log Monitoring

Monitor journal file size and rotation:

```bash
# Check journal file size
du -h /var/log/examos/event_pipeline.log*

# Monitor rotation
watch -n 60 'ls -la /var/log/examos/event_pipeline.log*'
```

## Troubleshooting

### Initialization Failure

If event pipeline fails to initialize:

1. Check journal directory exists and is writable
2. Verify configuration file syntax
3. Check environment variables are set
4. Review system logs: `journalctl -u examos-server`

### Memory Issues

If experiencing memory pressure:

1. Reduce `event_cache_size`
2. Reduce `dedup_hash_table_size`
3. Reduce `journal_max_size_mb`
4. Monitor with: `top -p $(pgrep examos-server)`

### Performance Issues

If experiencing slow event ingestion:

1. Increase `batch_write_size`
2. Decrease `flush_interval_ms`
3. Enable `async_writes_enabled` (experimental)
4. Monitor disk I/O: `iostat -x 1`

## Security Considerations

- **Sensitive Data Validation**: Events are validated for passwords, keys, and secrets
- **Sanitization**: Automatic sanitization removes sensitive information from event details
- **File Permissions**: Configuration files should be readable only by authorized users
- **Journal Security**: Journal files contain event data and should be protected

## Backup and Recovery

### Backup Configuration

```bash
# Backup configuration
sudo cp /etc/examos/event_pipeline.conf /backup/event_pipeline.conf.$(date +%Y%m%d)
```

### Backup Journal Files

```bash
# Backup journal files
sudo tar -czf /backup/event_pipeline_journal_$(date +%Y%m%d).tar.gz /var/log/examos/event_pipeline.log*
```

### Recovery

```bash
# Restore configuration
sudo cp /backup/event_pipeline.conf.YYYYMMDD /etc/examos/event_pipeline.conf

# Restore journal files
sudo tar -xzf /backup/event_pipeline_journal_YYYYMMDD.tar.gz -C /
```

## API Endpoints

### Event Ingestion

```bash
# Generic event ingestion
curl -X POST http://localhost:8080/api/v1/events/ingest \
  -H "Authorization: Bearer EXAMOS_AGENT_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": 1000,
    "event_type_str": "AUTH_FAILURE",
    "device_id": "dev001",
    "candidate_id": "cand123",
    "severity": 2,
    "classification": 0,
    "details": "Authentication failed for user"
  }'

# Specific event types
curl -X POST http://localhost:8080/api/v1/events/auth-failure \
  -H "Authorization: Bearer EXAMOS_AGENT_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "device_id": "dev001",
    "candidate_id": "cand123",
    "username": "testuser",
    "reason": "Invalid password",
    "severity": 2
  }'
```

### Event Search

```bash
curl -X GET "http://localhost:8080/api/v1/events/search?min_severity=2&limit=10" \
  -H "Cookie: admin_session=<valid_session>"
```

### Event Statistics

```bash
curl -X GET http://localhost:8080/api/v1/events/stats \
  -H "Cookie: admin_session=<valid_session>"
```

## Maintenance

### Regular Maintenance Tasks

1. **Daily**: Monitor journal file size and rotation
2. **Weekly**: Review event statistics and alert patterns
3. **Monthly**: Archive old journal files
4. **Quarterly**: Review and update configuration based on usage patterns

### Journal Rotation

Automatic rotation is configured via `journal_max_size_mb` and `journal_rotation_count`. Manual rotation:

```bash
# Force rotation
sudo mv /var/log/examos/event_pipeline.log /var/log/examos/event_pipeline.log.1
sudo systemctl restart examos-server
```

## Upgrade Procedure

1. Stop the service: `sudo systemctl stop examos-server`
2. Backup configuration and journals
3. Install new binary: `sudo make install`
4. Review new configuration options
5. Update configuration if needed
6. Start the service: `sudo systemctl start examos-server`
7. Verify operation: `sudo systemctl status examos-server`

## Support

For issues or questions:
1. Check system logs: `journalctl -u examos-server -n 100`
2. Review configuration: `cat /etc/examos/event_pipeline.conf`
3. Check journal files: `tail -f /var/log/examos/event_pipeline.log`
4. Verify API endpoints are responding
