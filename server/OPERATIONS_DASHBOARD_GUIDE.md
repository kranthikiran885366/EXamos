# ExamOS Operations Dashboard Guide

## Overview

The ExamOS Operations Dashboard is a production-grade web interface for monitoring and managing exam operations in real-time. It provides centralized visibility into devices, candidates, incidents, and security events with proper authentication, authorization, and audit logging.

## Features

### Dynamic Configuration
- **Server-side configuration**: Loads from `/api/v1/operations/config`
- **Client-side fallback**: Uses localStorage with prompts for required values
- **Configurable parameters**:
  - `examId`: Target exam identifier
  - `operatorId`: Current operator identifier for audit logging
  - `stalenessThresholdSec`: Device staleness threshold (default: 300s)
  - `refreshIntervalMs`: Auto-refresh interval (default: 10000ms)
  - `apiTimeoutMs`: API request timeout (default: 30000ms)

### Authentication & Authorization
- **Session-based authentication**: Uses `admin_session` cookie
- **Token extraction**: Automatically extracts session token from cookies
- **Authorization**: All API calls include session token
- **Error handling**: Proper HTTP error handling with user feedback

### Two-Step Confirmation for Critical Actions
- **Exam state changes**: Requires confirmation token + explicit "CONFIRM" text
- **Device failures**: Requires confirmation token + explicit "CONFIRM" text
- **Incident resolution**: Requires reason for audit logging
- **Audit trail**: All critical actions logged with operator ID and reason

### Real-Time Monitoring
- **Auto-refresh**: Configurable interval (default 10 seconds)
- **Network health**: Latency, heartbeat failures, attestation failures
- **Device telemetry**: Staleness detection, compliance status
- **Candidate sessions**: Activity tracking, security event counts
- **Security events**: Event pipeline integration with search and filtering

## Tabs

### Overview Tab
Displays aggregate statistics:
- **Exam Status**: Current state with state change controls
- **Candidates**: Total, checked in, in exam, submitted
- **Devices**: Total, online, compliant, stale
- **Incidents**: Open and critical count
- **Network Health**: Average latency, heartbeat failures, attestation failures, proctoring streams

### Devices Tab
Shows device telemetry:
- **Device ID**: Unique device identifier
- **Status**: Current session state
- **Compliance**: Device compliance status
- **Last Heartbeat**: Timestamp of last heartbeat
- **Latency**: Network latency (if available)
- **Staleness**: FRESH/STALE indicator based on threshold
- **Actions**: Mark device as failed

### Candidates Tab
Shows candidate sessions:
- **Candidate ID**: Unique candidate identifier
- **Name**: Candidate full name
- **Status**: Current session status
- **Device**: Assigned device ID
- **Last Activity**: Timestamp of last activity
- **Security Events**: Count of security events (NOT cheating flags)

### Incidents Tab
Shows security incidents:
- **Incident ID**: Unique incident identifier
- **Severity**: CRITICAL, HIGH, MEDIUM, LOW, INFO
- **Status**: OPEN, INVESTIGATING, RESOLVED
- **Summary**: Incident description
- **Created**: Creation timestamp
- **Actions**: Acknowledge, Resolve

### Security Events Tab (NEW)
Event pipeline integration:
- **Statistics**: Total events, events last hour, events last 24h, open alerts
- **Search Filters**:
  - Severity: INFO, LOW, MEDIUM, HIGH, CRITICAL
  - Classification: OBSERVED_FACT, INFERRED_RISK, UNVERIFIED_SUSPICION
  - Device ID: Filter by specific device
  - Candidate ID: Filter by specific candidate
- **Event Table**:
  - Event ID (truncated)
  - Timestamp
  - Event Type
  - Severity
  - Classification
  - Device ID
  - Candidate ID
  - Details

### Reports Tab
Generate operational reports:
- **Submission Report**: Exam submission data
- **Incident Report**: Security incident summary
- **Device Health Report**: Fleet device health status

## API Endpoints Used

### Operations Service
- `GET /api/v1/operations/summary?exam_id={id}` - Get overview statistics
- `GET /api/v1/operations/network-health` - Get network health metrics
- `GET /api/v1/operations/devices/telemetry` - Get device telemetry
- `GET /api/v1/operations/incidents` - Get security incidents
- `POST /api/v1/operations/incidents/acknowledge` - Acknowledge incident
- `POST /api/v1/operations/incidents/resolve` - Resolve incident
- `POST /api/v1/operations/exam/state-change` - Request exam state change
- `POST /api/v1/operations/confirm` - Confirm critical action
- `POST /api/v1/operations/device/failed` - Mark device as failed
- `GET /api/v1/operations/reports/{type}?exam_id={id}` - Generate report

### Event Pipeline
- `GET /api/v1/events/stats` - Get event pipeline statistics
- `GET /api/v1/events/search?{filters}` - Search security events

### Platform Service
- `GET /api/v1/platform/roster?exam_id={id}` - Get candidate roster
- `GET /api/v1/platform/fleet` - Get device fleet data

## Configuration

### Server-Side Configuration (Recommended)
Create `/api/v1/operations/config` endpoint returning:
```json
{
  "examId": "EXAM-001",
  "operatorId": "admin",
  "stalenessThresholdSec": 300,
  "refreshIntervalMs": 10000,
  "apiTimeoutMs": 30000
}
```

### Client-Side Configuration (Fallback)
Configuration is stored in `localStorage` under key `examos_dashboard_config`. If server config is unavailable, the dashboard will prompt for required values.

## Security Features

### Authentication
- All API calls include `admin_session` cookie
- Session token extracted automatically from cookies
- Unauthorized requests return 401 errors

### Authorization
- Critical actions require operator ID
- RBAC checks performed server-side
- Permission verification before action execution

### Audit Logging
- All critical actions logged with:
  - Action type
  - Operator ID
  - Target ID
  - Reason/notes
  - Confirmation token
- Audit trail stored in tamper-evident ledger

### Two-Step Confirmation
1. **Request phase**: User provides reason, receives confirmation token
2. **Confirm phase**: User must type "CONFIRM" to execute action
- Prevents accidental critical actions
- Provides explicit confirmation step
- Token-based verification

## Deployment

### File Location
- `server/operations_dashboard.html` - Dashboard HTML file
- Served via `/admin` route in main.c

### Serving the Dashboard
The dashboard is served through the existing admin route:
```c
/* Route: GET /admin and nested admin paths -> authenticated admin console */
else if ((strcmp(path, "/admin") == 0 || strncmp(path, "/admin/", 7) == 0) && 
        (strcmp(method, "GET") == 0 || strcmp(method, "HEAD") == 0)) {
    if (!admin_check_auth(auth_header)) {
        send_http_response(client_fd, 200, "text/html; charset=utf-8", admin_login_html());
    }
    // Serve operations_dashboard.html for /admin/operations
}
```

### Required API Routes
Ensure the following routes are implemented in main.c:
- Operations service routes (already implemented)
- Event pipeline routes (already implemented)
- Platform service routes (already implemented)

## Usage

### Initial Setup
1. Access dashboard at `http://server:port/admin/operations`
2. Authenticate with admin credentials
3. Enter Exam ID and Operator ID if prompted
4. Configuration is saved to localStorage

### Monitoring
- Dashboard auto-refreshes every 10 seconds (configurable)
- Switch between tabs to view different data
- Use filters in Security Events tab to search events

### Critical Actions
1. Click action button (e.g., "Open Exam", "Mark Failed")
2. Provide reason for audit logging
3. Receive confirmation token
4. Type "CONFIRM" in second dialog to execute
5. Action is logged to audit trail

### Event Search
1. Navigate to Security Events tab
2. Apply filters (severity, classification, device, candidate)
3. Click "Search" to filter events
4. Click "Clear" to reset filters

## Troubleshooting

### Configuration Not Loading
- Check `/api/v1/operations/config` endpoint exists
- Verify server is running
- Check browser console for errors
- Fallback to localStorage will prompt for values

### API Errors
- Verify `admin_session` cookie is set
- Check network connectivity
- Verify API routes are implemented
- Check server logs for errors

### Events Not Loading
- Verify event pipeline is initialized
- Check `/api/v1/events/stats` endpoint
- Verify event journal file exists
- Check event pipeline configuration

### Stale Devices
- Check staleness threshold configuration
- Verify devices are sending heartbeats
- Check network connectivity
- Review device telemetry

## Best Practices

### Security
- Always use HTTPS in production
- Rotate admin session tokens regularly
- Review audit logs periodically
- Use strong operator IDs (not "admin")
- Enable two-factor authentication if available

### Operations
- Monitor network health metrics
- Review security events regularly
- Investigate critical incidents promptly
- Keep device firmware updated
- Document all critical actions

### Performance
- Adjust refresh interval based on load
- Use appropriate staleness thresholds
- Limit event search results
- Archive old events periodically
- Monitor server resources

## Integration Notes

### Event Pipeline
The dashboard integrates with the event pipeline for:
- Real-time event statistics
- Event search and filtering
- Severity and classification display
- Alert monitoring

### Operations Service
The dashboard uses operations service for:
- Device telemetry with staleness detection
- Incident management
- Exam lifecycle operations
- Network health monitoring

### Platform Service
The dashboard uses platform service for:
- Candidate roster data
- Device fleet information
- Exam configuration

## Future Enhancements

Potential improvements:
- WebSocket support for real-time updates
- Advanced event correlation visualization
- Custom alert rule configuration
- Export event data to CSV/JSON
- Incident timeline visualization
- Device location mapping
- Performance analytics dashboard
- Custom dashboard layouts
- Multi-exam support
- Role-based UI customization
