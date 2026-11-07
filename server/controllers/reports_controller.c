/*
 * reports_controller.c — server-enforced reporting API for SPPIO / ExamOS.
 *
 * All report values are computed by PostgreSQL from authoritative records.
 * Nothing is hardcoded or synthesised in this file. Tenant scope, report
 * permission, export permission and export auditing are enforced here, not in
 * the browser.
 *
 * Routes:
 *   GET  /api/v1/reports/catalog
 *   GET  /api/v1/reports/hub
 *   GET  /api/v1/reports/exams
 *   GET  /api/v1/reports/devices
 *   GET  /api/v1/reports/security
 *   GET  /api/v1/reports/business
 *   GET  /api/v1/reports/history
 *   POST /api/v1/reports/export
 */

#include "reports_controller.h"
#include "reports_queries.h"
#include "controller.h"
#include "../db/db.h"
#include "../include/enterprise_platform.h"
#include "../security/security.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ------------------------------------------------------------------ buffer */

typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} rbuf;

static int rb_init(rbuf *b, size_t cap) {
    if (!b) return -1;
    if (cap < 1024) cap = 1024;
    b->data = (char *)malloc(cap);
    if (!b->data) return -1;
    b->cap = cap;
    b->len = 0;
    b->data[0] = '\0';
    return 0;
}

static void rb_free(rbuf *b) {
    if (!b) return;
    free(b->data);
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

static int rb_reserve(rbuf *b, size_t extra) {
    if (!b || !b->data) return -1;
    if (b->len + extra + 1 <= b->cap) return 0;
    size_t cap = b->cap;
    while (cap < b->len + extra + 1) {
        if (cap > (size_t)128 * 1024 * 1024) return -1;
        cap *= 2;
    }
    char *p = (char *)realloc(b->data, cap);
    if (!p) return -1;
    b->data = p;
    b->cap = cap;
    return 0;
}

static int rb_putn(rbuf *b, const char *s, size_t n) {
    if (!b || !s || n == 0) return 0;
    if (rb_reserve(b, n) != 0) return -1;
    memcpy(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = '\0';
    return 0;
}

static int rb_puts(rbuf *b, const char *s) {
    return rb_putn(b, s, s ? strlen(s) : 0);
}

static int rb_putc(rbuf *b, char c) {
    return rb_putn(b, &c, 1);
}

static int rb_printf(rbuf *b, const char *fmt, ...) {
    if (!b || !fmt) return -1;
    va_list ap, copy;
    va_start(ap, fmt);
    va_copy(copy, ap);
    int need = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (need < 0) { va_end(copy); return -1; }
    if (rb_reserve(b, (size_t)need) != 0) { va_end(copy); return -1; }
    vsnprintf(b->data + b->len, b->cap - b->len, fmt, copy);
    va_end(copy);
    b->len += (size_t)need;
    return 0;
}

/* Append a JSON string literal, escaping all control characters. */
static int rb_json(rbuf *b, const char *s) {
    if (rb_putc(b, '"') != 0) return -1;
    if (s) {
        for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
            char tmp[8];
            switch (*p) {
                case '"':  if (rb_puts(b, "\\\"")) return -1; break;
                case '\\': if (rb_puts(b, "\\\\")) return -1; break;
                case '\b': if (rb_puts(b, "\\b")) return -1; break;
                case '\f': if (rb_puts(b, "\\f")) return -1; break;
                case '\n': if (rb_puts(b, "\\n")) return -1; break;
                case '\r': if (rb_puts(b, "\\r")) return -1; break;
                case '\t': if (rb_puts(b, "\\t")) return -1; break;
                default:
                    if (*p < 0x20) {
                        snprintf(tmp, sizeof(tmp), "\\u%04x", (unsigned)*p);
                        if (rb_puts(b, tmp)) return -1;
                    } else if (rb_putc(b, (char)*p)) {
                        return -1;
                    }
            }
        }
    }
    return rb_putc(b, '"');
}

/* ----------------------------------------------------------------- helpers */

static void reports_send(int fd, int status, const char *body, const char *origin,
                         char *extra, size_t extra_len) {
    ctrl_set_cors(extra, extra_len, origin, ctrl_cors_origin_allowed(origin));
    ctrl_send_json(fd, status, body, extra);
}

static void reports_error(int fd, int status, const char *message, const char *origin,
                          char *extra, size_t extra_len) {
    char escaped[512];
    char body[640];
    ctrl_json_escape(message ? message : "Request failed", escaped, sizeof(escaped));
    snprintf(body, sizeof(body), "{\"error\":\"%s\"}", escaped);
    reports_send(fd, status, body, origin, extra, extra_len);
}

static char *dup_string(const char *s) {
    if (!s) s = "";
    size_t n = strlen(s) + 1;
    char *p = (char *)malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (long long)ts.tv_sec * 1000LL + (long long)(ts.tv_nsec / 1000000L);
}

static int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void url_decode(const char *src, size_t len, char *out, size_t out_len) {
    size_t o = 0;
    if (!out || out_len == 0) return;
    for (size_t i = 0; i < len && o + 1 < out_len; i++) {
        char c = src[i];
        if (c == '+') {
            c = ' ';
        } else if (c == '%' && i + 2 < len) {
            int hi = hex_digit(src[i + 1]);
            int lo = hex_digit(src[i + 2]);
            if (hi >= 0 && lo >= 0) {
                c = (char)((hi << 4) | lo);
                i += 2;
            }
        }
        out[o++] = c;
    }
    out[o] = '\0';
}

static int query_get(const char *query, const char *key, char *out, size_t out_len) {
    if (!query || !key || !out || out_len == 0) return 0;
    out[0] = '\0';
    size_t klen = strlen(key);
    const char *p = query;
    while (*p) {
        const char *amp = strchr(p, '&');
        const char *end = amp ? amp : p + strlen(p);
        const char *eq = (const char *)memchr(p, '=', (size_t)(end - p));
        if (eq && (size_t)(eq - p) == klen && strncmp(p, key, klen) == 0) {
            url_decode(eq + 1, (size_t)(end - (eq + 1)), out, out_len);
            return 1;
        }
        if (!amp) break;
        p = amp + 1;
    }
    return 0;
}

/* Read a JSON value that may be either a quoted string or a bare number. */
static int json_scalar(const char *body, const char *key, char *out, size_t out_len) {
    if (!body || !key || !out || out_len == 0) return 0;
    out[0] = '\0';
    if (ctrl_json_string(body, key, out, out_len)) return 1;
    char search[96];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(body, search);
    if (!p) return 0;
    p += strlen(search);
    while (isspace((unsigned char)*p)) p++;
    if (*p != ':') return 0;
    p++;
    while (isspace((unsigned char)*p)) p++;
    if (*p == '"') return ctrl_json_string(body, key, out, out_len);
    size_t o = 0;
    while (*p && *p != ',' && *p != '}' && !isspace((unsigned char)*p)) {
        if (o + 1 < out_len) out[o++] = *p;
        p++;
    }
    out[o] = '\0';
    return o > 0;
}

static void strip_controls(char *s, size_t max_len) {
    if (!s) return;
    size_t n = strlen(s);
    if (n > max_len) { s[max_len] = '\0'; n = max_len; }
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 || c == 0x7f) s[i] = ' ';
    }
}

static int safe_token(const char *v, size_t max_len) {
    if (!v || !v[0]) return 0;
    size_t n = strlen(v);
    if (n > max_len) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)v[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' || c == ':'))
            return 0;
    }
    return 1;
}

static int epoch_valid(const char *v) {
    if (!v || !v[0] || strlen(v) > 17) return 0;
    for (const char *p = v; *p; p++) if (!isdigit((unsigned char)*p)) return 0;
    return 1;
}

/* ------------------------------------------------------------ report models */

typedef struct {
    const char *key;
    const char *label;
    const char *type; /* text | number | percent | bool | epoch */
} report_col_t;

typedef struct {
    const char *key;
    const char *group;
    const char *label;
    const char *desc;
    const char *sql;
    const report_col_t *cols;
    int col_count;
    const char *source;
    const char *calculation;
    const char *inclusion;
    const char *exclusion;
    const char *status_label;
} report_def_t;

#define NCOLS(a) ((int)(sizeof(a) / sizeof((a)[0])))

static const report_col_t COLS_EXAM_SUMMARY[] = {
    {"code", "Code", "text"},
    {"title", "Exam", "text"},
    {"status", "Status", "text"},
    {"startAt", "Starts at", "epoch"},
    {"durationMin", "Duration (min)", "number"},
    {"centerCount", "Centers", "number"},
    {"assigned", "Assigned candidates", "number"},
    {"policyId", "Policy", "text"},
    {"totalMarks", "Total marks", "number"},
    {"passingMarks", "Passing marks", "number"},
    {"createdAt", "Created at", "epoch"}
};

static const report_col_t COLS_ATTENDANCE[] = {
    {"code", "Code", "text"},
    {"title", "Exam", "text"},
    {"status", "Status", "text"},
    {"startAt", "Starts at", "epoch"},
    {"assigned", "Assigned", "number"},
    {"started", "Started", "number"},
    {"submitted", "Submitted", "number"},
    {"attendancePct", "Attendance %", "percent"},
    {"completionPct", "Completion %", "percent"}
};

static const report_col_t COLS_RESULTS[] = {
    {"receipt", "Receipt", "text"},
    {"examCode", "Exam code", "text"},
    {"examTitle", "Exam", "text"},
    {"rollNo", "Roll number", "text"},
    {"candidateName", "Candidate", "text"},
    {"score", "Score", "number"},
    {"maxScore", "Max score", "number"},
    {"percentage", "Percentage", "percent"},
    {"passed", "Passed", "bool"},
    {"submittedAt", "Submitted at", "epoch"}
};

static const report_col_t COLS_READINESS[] = {
    {"rollNo", "Roll number", "text"},
    {"name", "Candidate", "text"},
    {"examCode", "Exam code", "text"},
    {"examTitle", "Exam", "text"},
    {"centerId", "Center", "text"},
    {"seat", "Seat", "text"},
    {"identity", "Identity", "text"},
    {"status", "Assignment status", "text"},
    {"deviceHostname", "Device", "text"},
    {"deviceTrust", "Device trust", "text"},
    {"deviceStatus", "Device status", "text"},
    {"ready", "Ready", "bool"}
};

static const report_col_t COLS_FLEET[] = {
    {"centerCode", "Center code", "text"},
    {"centerName", "Center", "text"},
    {"devices", "Devices", "number"},
    {"compliant", "Compliant", "number"},
    {"isolated", "Isolated", "number"},
    {"attested", "Attested", "number"},
    {"online", "Online (60 s)", "number"},
    {"compliancePct", "Compliance %", "percent"}
};

static const report_col_t COLS_ATTESTATION[] = {
    {"deviceId", "Device id", "text"},
    {"hostname", "Hostname", "text"},
    {"result", "Result", "text"},
    {"reason", "Reason", "text"},
    {"verifiedAt", "Verified at", "epoch"},
    {"source", "Source", "text"}
};

static const report_col_t COLS_COMPATIBILITY[] = {
    {"id", "Device id", "text"},
    {"hostname", "Hostname", "text"},
    {"centerId", "Center", "text"},
    {"seat", "Seat", "text"},
    {"profile", "Profile", "text"},
    {"compatStatus", "Compatibility", "text"},
    {"lastCompatAt", "Last checked", "epoch"},
    {"releaseId", "Release", "text"}
};

static const report_col_t COLS_USB[] = {
    {"assetId", "Asset id", "text"},
    {"serial", "Serial", "text"},
    {"status", "Status", "text"},
    {"releaseId", "Release", "text"},
    {"holder", "Holder", "text"},
    {"location", "Location", "text"},
    {"lastCheckAt", "Last check", "epoch"}
};

static const report_col_t COLS_INCIDENTS[] = {
    {"id", "Incident id", "text"},
    {"no", "Number", "number"},
    {"title", "Title", "text"},
    {"severity", "Severity", "text"},
    {"kind", "Kind", "text"},
    {"status", "Status", "text"},
    {"owner", "Owner", "text"},
    {"deviceId", "Device", "text"},
    {"createdAt", "Created at", "epoch"}
};

static const report_col_t COLS_SECURITY_EVENTS[] = {
    {"id", "Event id", "text"},
    {"type", "Type", "text"},
    {"severity", "Severity", "text"},
    {"title", "Title", "text"},
    {"status", "Status", "text"},
    {"actor", "Actor", "text"},
    {"deviceId", "Device", "text"},
    {"incidentId", "Incident", "text"},
    {"at", "Occurred at", "epoch"}
};

static const report_col_t COLS_VULNERABILITIES[] = {
    {"id", "Finding id", "text"},
    {"cve", "CVE", "text"},
    {"component", "Component", "text"},
    {"title", "Title", "text"},
    {"severity", "Severity", "text"},
    {"cvss", "CVSS", "number"},
    {"status", "Status", "text"},
    {"owner", "Owner", "text"},
    {"fixedIn", "Fixed in", "text"},
    {"createdAt", "Recorded at", "epoch"}
};

static const report_col_t COLS_RELEASES[] = {
    {"id", "Release id", "text"},
    {"version", "Version", "text"},
    {"status", "Status", "text"},
    {"rollout", "Rollout", "number"},
    {"criticalCves", "Critical CVEs", "number"},
    {"findings", "Findings", "number"},
    {"evidence", "Evidence records", "number"},
    {"createdAt", "Created at", "epoch"}
};

static const report_col_t COLS_AUDIT[] = {
    {"actor", "Actor", "text"},
    {"event", "Event", "text"},
    {"events", "Events", "number"},
    {"lastAt", "Last occurred", "epoch"}
};

static const report_col_t COLS_SUPPORT[] = {
    {"id", "Ticket id", "text"},
    {"no", "Ticket", "text"},
    {"subject", "Subject", "text"},
    {"category", "Category", "text"},
    {"priority", "Priority", "text"},
    {"status", "Status", "text"},
    {"requesterName", "Requester", "text"},
    {"assigneeId", "Assignee", "text"},
    {"slaDueAt", "SLA due", "epoch"},
    {"firstResponseAt", "First response", "epoch"},
    {"resolvedAt", "Resolved at", "epoch"},
    {"satisfactionScore", "Satisfaction (1-5)", "number"},
    {"breached", "SLA breached", "bool"},
    {"createdAt", "Created at", "epoch"}
};

static const report_col_t COLS_BILLING[] = {
    {"id", "Invoice id", "text"},
    {"number", "Number", "text"},
    {"status", "Status", "text"},
    {"subtotal", "Subtotal", "number"},
    {"tax", "Tax", "number"},
    {"total", "Total", "number"},
    {"issuedAt", "Issued at", "epoch"},
    {"dueAt", "Due at", "epoch"},
    {"paidAt", "Paid at", "epoch"}
};

static const report_def_t REPORTS[] = {
    {
        "exam-summary", "exams", "Exam register",
        "One row per examination with lifecycle status, schedule, assignment and policy state.",
        REPORT_SQL_EXAM_SUMMARY, COLS_EXAM_SUMMARY, NCOLS(COLS_EXAM_SUMMARY),
        "console_records(collection='exams') merged with examinations; assignments from console_records(collection='candidates') and exam_student_assignments.",
        "One row per distinct exam id. The console record wins for the same id. startAt falls back to the earliest exam_schedules.start_time. assigned uses the console candidate count when present, otherwise the normalized assignment count.",
        "Every exam visible in the caller's tenant scope, including draft and cancelled exams.",
        "Exams without a tenant identifier are excluded unless the caller has global scope. Duplicate rows with the same id collapse to the console copy.",
        "Exam lifecycle status"
    },
    {
        "attendance", "exams", "Attendance by exam",
        "Assignment, start and submission counts with attendance and completion rates.",
        REPORT_SQL_ATTENDANCE, COLS_ATTENDANCE, NCOLS(COLS_ATTENDANCE),
        "Exams from console_records and examinations; assignments from console_records(candidates) and exam_student_assignments; activity from console_records(sessions) and exam_attempts.",
        "attendancePct = started / assigned * 100. completionPct = submitted / assigned * 100. started counts in_progress, submitted and terminated console sessions plus in_progress, submitted, interrupted and completed attempts. submitted counts submitted console sessions and submitted/completed attempts.",
        "Every exam in scope, including exams with zero assignments.",
        "Sessions or attempts whose exam cannot be resolved inside the same institution are not attributed.",
        "Exam lifecycle status"
    },
    {
        "results", "exams", "Exam results",
        "Submitted candidate results with score, percentage, pass outcome and receipt number.",
        REPORT_SQL_RESULTS, COLS_RESULTS, NCOLS(COLS_RESULTS),
        "console_records(collection='sessions', status='submitted') and exam_attempts(status in submitted/completed).",
        "percentage = score / maxScore * 100, where maxScore is totalMarks and falls back to the question count. passed = score >= passingMarks, falling back to 40% of maxScore. Console results take precedence for an exam whenever any console submission exists for that exam.",
        "Submitted or completed attempts only.",
        "In-progress, interrupted and terminated sessions. Normalized attempts for an exam already represented by console submissions.",
        "Outcome"
    },
    {
        "candidate-readiness", "exams", "Candidate readiness",
        "Per-candidate identity, seating and device readiness before an exam.",
        REPORT_SQL_CANDIDATE_READINESS, COLS_READINESS, NCOLS(COLS_READINESS),
        "console_records(collection='candidates') merged with exam_student_assignments/students; console devices merged with devices.",
        "ready = identity='verified' AND seat is non-empty AND the matched device has status='enrolled' AND trust='attested'. A device is matched on institution, center and seat.",
        "All assigned candidates in scope, ready or not.",
        "Candidates not assigned to an exam. Normalized assignments are skipped when a console candidate exists for the same exam and institution.",
        "Assignment status"
    },
    {
        "fleet", "devices", "Fleet compliance by center",
        "Device counts, attestation, isolation, online freshness and compliance per center.",
        REPORT_SQL_FLEET, COLS_FLEET, NCOLS(COLS_FLEET),
        "console_records(collection='devices') merged with devices; console centers merged with centers.",
        "compliancePct = compliant / devices * 100. compliant = enrolled AND attested AND not isolated AND not tampered. online means last_seen is within 60 seconds of server time.",
        "All devices in scope, grouped by institution and center.",
        "No devices are invented for empty centers. Devices without a center id are grouped under an empty center key.",
        "Device status"
    },
    {
        "attestation", "devices", "Attestation outcomes",
        "Recorded device attestation evidence with result, reason and timestamp.",
        REPORT_SQL_ATTESTATION, COLS_ATTESTATION, NCOLS(COLS_ATTESTATION),
        "console_records(collection='attestations') merged with device_attestation_evidence joined to devices.",
        "One row per attestation evidence id. result is lower-cased. passRate counts trusted/pass/passed results.",
        "All recorded attestation attempts in scope.",
        "Evidence whose device cannot be resolved is withheld because tenant scope cannot be proven.",
        "Attestation result"
    },
    {
        "compatibility", "devices", "Hardware compatibility",
        "Last recorded OS compatibility outcome for every device.",
        REPORT_SQL_COMPATIBILITY, COLS_COMPATIBILITY, NCOLS(COLS_COMPATIBILITY),
        "console_records(collection='devices') merged with devices.",
        "One row per device. compatStatus is the device's last recorded compatibility outcome.",
        "All devices in scope, including NOT_RUN.",
        "None beyond tenant scope.",
        "Compatibility status"
    },
    {
        "usb-custody", "devices", "USB custody",
        "Current custody, holder and last known location of registered USB media.",
        REPORT_SQL_USB_CUSTODY, COLS_USB, NCOLS(COLS_USB),
        "console_records(collection='usbs').",
        "One row per USB asset. holder is data.holder.name. location prefers lastLocation, then station.",
        "Every registered USB asset in scope.",
        "Custody events are not fabricated; only the current asset record is reported.",
        "Custody status"
    },
    {
        "incidents", "security", "Incident register",
        "Security incidents with severity, ownership and open/resolved state.",
        REPORT_SQL_INCIDENTS, COLS_INCIDENTS, NCOLS(COLS_INCIDENTS),
        "console_records(collection='incidents') merged with incidents.",
        "One row per incident id. open counts open, investigating and contained. critical counts critical-severity incidents that are still open.",
        "All incidents in scope.",
        "Duplicate console/normalized rows collapse to the console record.",
        "Incident status"
    },
    {
        "security-events", "security", "Security event register",
        "Security events with type, severity, actor and acknowledgement state.",
        REPORT_SQL_SECURITY_EVENTS, COLS_SECURITY_EVENTS, NCOLS(COLS_SECURITY_EVENTS),
        "console_records(collection='securityEvents') merged with security_events.",
        "One row per event id. open counts open, acknowledged and escalated.",
        "All events in scope.",
        "Events without a resolvable tenant are excluded unless the caller has global scope.",
        "Event status"
    },
    {
        "vulnerabilities", "security", "Vulnerability findings",
        "Recorded vulnerability findings with CVSS, severity and remediation state.",
        REPORT_SQL_VULNERABILITIES, COLS_VULNERABILITIES, NCOLS(COLS_VULNERABILITIES),
        "console_records(collection='vulnerabilities') merged with the normalized vulnerabilities table.",
        "One row per finding id. critical/high counts exclude fixed and false-positive findings.",
        "All findings in scope.",
        "No CVE enrichment is invented; only recorded fields are reported.",
        "Finding status"
    },
    {
        "release-validation", "security", "Release validation",
        "OS releases with recorded validation findings and evidence counts.",
        REPORT_SQL_RELEASE_VALIDATION, COLS_RELEASES, NCOLS(COLS_RELEASES),
        "console_records(collection='releases') with evidence counted from console_records(collection='releaseEvidence').",
        "evidence counts releaseEvidence records whose releaseId matches the release. criticalCves and findings are the recorded release fields.",
        "All releases in scope.",
        "No validation is re-run by this report; it reports recorded evidence only. Normalized os_releases rows are not included because the console release record is the authoritative artifact.",
        "Release status"
    },
    {
        "audit-summary", "security", "Audit activity summary",
        "Tenant-scoped audit activity grouped by actor and event type.",
        REPORT_SQL_AUDIT_SUMMARY, COLS_AUDIT, NCOLS(COLS_AUDIT),
        "Tenant-scoped module audit tables: exam_audit_logs, registration_audit_logs, device_audit_events and support_events.",
        "Grouped by actor and event type. events = number of audit rows. lastAt = newest timestamp.",
        "Audit records for the caller's institution.",
        "The global audit chain is not read here to prevent cross-tenant leakage. Export history is available from /api/v1/reports/history.",
        "Event type"
    },
    {
        "support", "business", "Support ticket register",
        "Support tickets with SLA, response, resolution and satisfaction state.",
        REPORT_SQL_SUPPORT, COLS_SUPPORT, NCOLS(COLS_SUPPORT),
        "support_requests.",
        "breached = SLA deadline passed before first response while the ticket is still open. satisfaction is the average 1-5 score.",
        "All tickets in scope.",
        "Comments and internal notes are not exposed.",
        "Ticket status"
    },
    {
        "billing", "business", "Invoice register",
        "Invoices with subtotal, tax, total, payment state and overdue ageing.",
        REPORT_SQL_BILLING, COLS_BILLING, NCOLS(COLS_BILLING),
        "console_records(collection='invoices').",
        "invoiced = sum(total). paid = sum(total) where status is paid or settled. outstanding = sum(total) for unpaid, non-void invoices. overdue counts outstanding invoices past dueAt.",
        "All invoices in scope.",
        "The normalized invoices table is not included because it stores only an amount and status, so tax and invoice number would have to be fabricated.",
        "Invoice status"
    }
};

static const char *const GROUPS[] = {"exams", "devices", "security", "business"};

static const char *group_label(const char *group) {
    if (!strcmp(group, "exams")) return "Exams & candidates";
    if (!strcmp(group, "devices")) return "Devices & OS";
    if (!strcmp(group, "security")) return "Security & audit";
    if (!strcmp(group, "business")) return "Business & support";
    return "Reports";
}

static const report_def_t *find_report(const char *key) {
    if (!key) return NULL;
    for (size_t i = 0; i < sizeof(REPORTS) / sizeof(REPORTS[0]); i++)
        if (!strcmp(REPORTS[i].key, key)) return &REPORTS[i];
    return NULL;
}

static const report_def_t *first_in_group(const char *group) {
    for (size_t i = 0; i < sizeof(REPORTS) / sizeof(REPORTS[0]); i++)
        if (!strcmp(REPORTS[i].group, group)) return &REPORTS[i];
    return NULL;
}

/* ---------------------------------------------------------- authorization */

static int group_allowed(user_role_t role, const char *group) {
    if (role == ROLE_PLATFORM_OWNER) return 1;
    if (!strcmp(group, "exams"))
        return security_role_has_permission(role, AUTH_PERM_EXAM_READ) ||
               security_role_has_permission(role, AUTH_PERM_EXAM_MUTATION);
    if (!strcmp(group, "devices"))
        return security_role_has_permission(role, AUTH_PERM_READ);
    if (!strcmp(group, "security"))
        return security_role_has_permission(role, AUTH_PERM_INCIDENT_READ) ||
               security_role_has_permission(role, AUTH_PERM_SECURITY_ADMIN);
    if (!strcmp(group, "business"))
        return role == ROLE_INSTITUTION_ADMIN || role == ROLE_READONLY_AUDITOR ||
               role == ROLE_SUPPORT_ENGINEER;
    return 0;
}

static int export_allowed(user_role_t role) {
    return role != ROLE_INVIGILATOR && role != ROLE_SUPPORT_ENGINEER;
}

/* --------------------------------------------------------------- filtering */

typedef struct {
    char from[24];
    char to[24];
    char q[160];
    char status[64];
    char exam_id[80];
    int  page;
    int  page_size;
} report_filters_t;

static void filters_default(report_filters_t *f) {
    memset(f, 0, sizeof(*f));
    f->page = 1;
    f->page_size = 25;
}

static int parse_common_number(const char *value, int *out, int lo, int hi) {
    if (!value || !value[0]) return 0;
    for (const char *p = value; *p; p++) if (!isdigit((unsigned char)*p)) return 0;
    long v = atol(value);
    if (v < lo) v = lo;
    if (v > hi) v = hi;
    *out = (int)v;
    return 1;
}

static int read_filter_pair(const char *query, const char *body, const char *key,
                            char *out, size_t out_len, int *invalid) {
    if (out && out_len) out[0] = '\0';
    char tmp[256];
    tmp[0] = '\0';
    int found = 0;
    if (query) found = query_get(query, key, tmp, sizeof(tmp));
    if (!found && body) found = json_scalar(body, key, tmp, sizeof(tmp));
    if (found && tmp[0]) {
        strip_controls(tmp, out_len - 1);
        snprintf(out, out_len, "%s", tmp);
    }
    (void)invalid;
    return found;
}

static int parse_filters(const char *query, const char *body, report_filters_t *f) {
    filters_default(f);
    int invalid = 0;
    char tmp[256] = {0};

    read_filter_pair(query, body, "from", tmp, sizeof(tmp), &invalid);
    if (tmp[0]) {
        if (!epoch_valid(tmp)) return -1;
        /* epoch_valid guarantees at most 17 characters, well inside from[24]. */
        size_t n = strlen(tmp);
        memcpy(f->from, tmp, n);
        f->from[n] = '\0';
    }
    read_filter_pair(query, body, "to", tmp, sizeof(tmp), &invalid);
    if (tmp[0]) {
        if (!epoch_valid(tmp)) return -1;
        size_t n = strlen(tmp);
        memcpy(f->to, tmp, n);
        f->to[n] = '\0';
    }
    read_filter_pair(query, body, "q", f->q, sizeof(f->q), &invalid);
    read_filter_pair(query, body, "status", f->status, sizeof(f->status), &invalid);
    read_filter_pair(query, body, "examId", f->exam_id, sizeof(f->exam_id), &invalid);

    if (query_get(query, "page", tmp, sizeof(tmp))) parse_common_number(tmp, &f->page, 1, 100000);
    if (query_get(query, "pageSize", tmp, sizeof(tmp))) parse_common_number(tmp, &f->page_size, 1, 500);
    return 0;
}

/* --------------------------------------------------------------- scope */

typedef struct {
    char inst[65];
    int  global;
} report_scope_t;

static int resolve_scope(const auth_session_t *sess, const char *query, report_scope_t *out) {
    memset(out, 0, sizeof(*out));
    if (sess->role == ROLE_PLATFORM_OWNER) {
        char requested[65] = {0};
        if (query) query_get(query, "institutionId", requested, sizeof(requested));
        if (requested[0]) {
            if (!safe_token(requested, 64)) return -1;
            const char *p[1] = {requested};
            PGresult *r = db_query("SELECT 1 FROM examos_institutions WHERE institution_id=$1", 1, p);
            int ok = r && PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1;
            if (r) PQclear(r);
            if (!ok) return -2;
            snprintf(out->inst, sizeof(out->inst), "%s", requested);
            out->global = 0;
            return 0;
        }
        out->global = 1;
        return 0;
    }
    if (!sess->institution_id[0]) return -3;
    if (!safe_token(sess->institution_id, 64)) return -1;
    snprintf(out->inst, sizeof(out->inst), "%s", sess->institution_id);
    out->global = 0;
    return 0;
}

/* ---------------------------------------------------------------- queries */

static PGresult *run_report(const report_def_t *d, const report_scope_t *scope,
                            const report_filters_t *f, int page_size, int offset) {
    char ps[16], off[16];
    snprintf(ps, sizeof(ps), "%d", page_size);
    snprintf(off, sizeof(off), "%d", offset);
    const char *params[9] = {
        scope->inst,
        scope->global ? "true" : "false",
        f->from,
        f->to,
        f->q,
        f->status,
        f->exam_id,
        ps,
        off
    };
    /* Some reports cannot be filtered by exam, so $7 is deliberately unused
     * there. Declaring its type keeps PostgreSQL from rejecting the parameter
     * as untyped instead of silently changing every report's parameter list. */
    Oid types[9] = {0, 0, 0, 0, 0, 0, 25 /* text */, 0, 0};
    PGconn *conn = db_acquire();
    if (!conn) return NULL;
    PGresult *res = PQexecParams(conn, d->sql, 9, types, params, NULL, NULL, 0);
    db_release(conn, res && PQresultStatus(res) != PGRES_TUPLES_OK &&
                     PQresultStatus(res) != PGRES_COMMAND_OK);
    return res;
}

static int result_ok(const PGresult *r) {
    return r && PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1;
}

static const char *cell(const PGresult *r, int row, const char *name) {
    int col = PQfnumber(r, name);
    if (col < 0) return "[]";
    const char *v = PQgetvalue(r, row, col);
    return (v && v[0]) ? v : "[]";
}

/* -------------------------------------------------------------- metadata */

static int append_columns(rbuf *b, const report_def_t *d) {
    if (rb_putc(b, '[')) return -1;
    for (int i = 0; i < d->col_count; i++) {
        if (i && rb_putc(b, ',')) return -1;
        if (rb_puts(b, "{\"key\":") || rb_json(b, d->cols[i].key) ||
            rb_puts(b, ",\"label\":") || rb_json(b, d->cols[i].label) ||
            rb_puts(b, ",\"type\":") || rb_json(b, d->cols[i].type) ||
            rb_putc(b, '}'))
            return -1;
    }
    return rb_putc(b, ']');
}

static int append_definitions(rbuf *b, const report_def_t *d) {
    if (rb_puts(b, "{\"source\":")) return -1;
    if (rb_json(b, d->source)) return -1;
    if (rb_puts(b, ",\"calculation\":")) return -1;
    if (rb_json(b, d->calculation)) return -1;
    if (rb_puts(b, ",\"inclusion\":")) return -1;
    if (rb_json(b, d->inclusion)) return -1;
    if (rb_puts(b, ",\"exclusion\":")) return -1;
    if (rb_json(b, d->exclusion)) return -1;
    return rb_putc(b, '}');
}

static int append_filters_json(rbuf *b, const report_filters_t *f) {
    if (rb_puts(b, "{\"from\":")) return -1;
    if (rb_json(b, f->from)) return -1;
    if (rb_puts(b, ",\"to\":")) return -1;
    if (rb_json(b, f->to)) return -1;
    if (rb_puts(b, ",\"q\":")) return -1;
    if (rb_json(b, f->q)) return -1;
    if (rb_puts(b, ",\"status\":")) return -1;
    if (rb_json(b, f->status)) return -1;
    if (rb_puts(b, ",\"examId\":")) return -1;
    if (rb_json(b, f->exam_id)) return -1;
    return rb_putc(b, '}');
}

/* -------------------------------------------------------------- catalog */

static int build_catalog(rbuf *b, const auth_session_t *sess) {
    if (rb_printf(b, "{\"generatedAt\":%lld,\"capabilities\":{\"serverSide\":true,"
                     "\"scheduled\":false,\"formats\":[\"csv\",\"json\"],\"maxExportRows\":10000,"
                     "\"exportAllowed\":%s},\"groups\":[",
                  now_ms(), export_allowed(sess->role) ? "true" : "false"))
        return -1;

    int first_group = 1;
    for (size_t g = 0; g < sizeof(GROUPS) / sizeof(GROUPS[0]); g++) {
        const char *group = GROUPS[g];
        if (!group_allowed(sess->role, group)) continue;
        if (!first_group && rb_putc(b, ',')) return -1;
        first_group = 0;
        if (rb_puts(b, "{\"key\":")) return -1;
        if (rb_json(b, group)) return -1;
        if (rb_puts(b, ",\"label\":")) return -1;
        if (rb_json(b, group_label(group))) return -1;
        if (rb_puts(b, ",\"reports\":[")) return -1;

        int first_report = 1;
        for (size_t r = 0; r < sizeof(REPORTS) / sizeof(REPORTS[0]); r++) {
            const report_def_t *d = &REPORTS[r];
            if (strcmp(d->group, group)) continue;
            if (!first_report && rb_putc(b, ',')) return -1;
            first_report = 0;
            if (rb_puts(b, "{\"key\":")) return -1;
            if (rb_json(b, d->key)) return -1;
            if (rb_puts(b, ",\"group\":")) return -1;
            if (rb_json(b, d->group)) return -1;
            if (rb_puts(b, ",\"label\":")) return -1;
            if (rb_json(b, d->label)) return -1;
            if (rb_puts(b, ",\"desc\":")) return -1;
            if (rb_json(b, d->desc)) return -1;
            if (rb_puts(b, ",\"statusLabel\":")) return -1;
            if (rb_json(b, d->status_label)) return -1;
            if (rb_puts(b, ",\"columns\":")) return -1;
            if (append_columns(b, d)) return -1;
            if (rb_puts(b, ",\"definitions\":")) return -1;
            if (append_definitions(b, d)) return -1;
            if (rb_puts(b, ",\"exportable\":")) return -1;
            if (rb_puts(b, export_allowed(sess->role) ? "true" : "false")) return -1;
            if (rb_putc(b, '}')) return -1;
        }
        if (rb_puts(b, "]}")) return -1;
    }
    return rb_puts(b, "]}");
}

/* ---------------------------------------------------------------- payload */

static int append_payload(rbuf *b, const report_def_t *d, const report_scope_t *scope,
                          const report_filters_t *f, const PGresult *res) {
    int total_col = PQfnumber(res, "total");
    long total = total_col >= 0 ? atol(PQgetvalue(res, 0, total_col)) : 0;

    if (rb_puts(b, "{\"report\":")) return -1;
    if (rb_json(b, d->key)) return -1;
    if (rb_puts(b, ",\"group\":")) return -1;
    if (rb_json(b, d->group)) return -1;
    if (rb_puts(b, ",\"label\":")) return -1;
    if (rb_json(b, d->label)) return -1;
    if (rb_printf(b, ",\"generatedAt\":%lld", now_ms())) return -1;
    if (rb_puts(b, ",\"scope\":{\"institutionId\":")) return -1;
    if (rb_json(b, scope->inst)) return -1;
    if (rb_printf(b, ",\"global\":%s}", scope->global ? "true" : "false")) return -1;
    if (rb_puts(b, ",\"filters\":")) return -1;
    if (append_filters_json(b, f)) return -1;
    if (rb_printf(b, ",\"page\":%d,\"pageSize\":%d,\"total\":%ld", f->page, f->page_size, total)) return -1;
    if (rb_puts(b, ",\"rows\":")) return -1;
    if (rb_puts(b, cell(res, 0, "rows"))) return -1;
    if (rb_puts(b, ",\"breakdown\":")) return -1;
    if (rb_puts(b, cell(res, 0, "breakdown"))) return -1;
    if (rb_puts(b, ",\"summary\":")) return -1;
    if (rb_puts(b, cell(res, 0, "summary"))) return -1;
    if (rb_puts(b, ",\"columns\":")) return -1;
    if (append_columns(b, d)) return -1;
    if (rb_puts(b, ",\"definitions\":")) return -1;
    if (append_definitions(b, d)) return -1;
    return rb_putc(b, '}');
}

static void reports_group(int fd, const char *group, const char *query,
                          const auth_session_t *sess, const char *origin,
                          char *extra, size_t extra_len) {
    if (!group_allowed(sess->role, group)) {
        reports_error(fd, 403, "Your role cannot view this report group", origin, extra, extra_len);
        return;
    }
    report_scope_t scope;
    if (resolve_scope(sess, query, &scope) != 0) {
        reports_error(fd, 403, "No valid institution scope for this request", origin, extra, extra_len);
        return;
    }
    report_filters_t f;
    if (parse_filters(query, NULL, &f) != 0) {
        reports_error(fd, 400, "from/to must be epoch milliseconds", origin, extra, extra_len);
        return;
    }
    char key[64] = {0};
    if (query) query_get(query, "report", key, sizeof(key));
    const report_def_t *d = key[0] ? find_report(key) : first_in_group(group);
    if (!d || strcmp(d->group, group)) {
        reports_error(fd, 400, "Unknown report for this group", origin, extra, extra_len);
        return;
    }
    PGresult *res = run_report(d, &scope, &f, f.page_size, (f.page - 1) * f.page_size);
    if (!result_ok(res)) {
        if (res) PQclear(res);
        reports_error(fd, 500, "Report query failed", origin, extra, extra_len);
        return;
    }
    rbuf b;
    if (rb_init(&b, 8192) != 0) { PQclear(res); reports_error(fd, 500, "Out of memory", origin, extra, extra_len); return; }
    int ok = append_payload(&b, d, &scope, &f, res) == 0;
    PQclear(res);
    if (!ok) { rb_free(&b); reports_error(fd, 500, "Out of memory", origin, extra, extra_len); return; }
    reports_send(fd, 200, b.data, origin, extra, extra_len);
    rb_free(&b);
}

static int build_hub(rbuf *b, const report_scope_t *scope, const report_filters_t *f,
                     const auth_session_t *sess) {
    if (rb_printf(b, "{\"generatedAt\":%lld,\"scope\":{\"institutionId\":", now_ms())) return -1;
    if (rb_json(b, scope->inst)) return -1;
    if (rb_printf(b, ",\"global\":%s},\"filters\":", scope->global ? "true" : "false")) return -1;
    if (append_filters_json(b, f)) return -1;
    if (rb_puts(b, ",\"groups\":[")) return -1;

    int first = 1;
    for (size_t g = 0; g < sizeof(GROUPS) / sizeof(GROUPS[0]); g++) {
        const char *group = GROUPS[g];
        if (!group_allowed(sess->role, group)) continue;
        const report_def_t *d = first_in_group(group);
        if (!d) continue;
        if (!first && rb_putc(b, ',')) return -1;
        first = 0;
        if (rb_puts(b, "{\"key\":")) return -1;
        if (rb_json(b, group)) return -1;
        if (rb_puts(b, ",\"label\":")) return -1;
        if (rb_json(b, group_label(group))) return -1;
        if (rb_puts(b, ",\"report\":")) return -1;
        if (rb_json(b, d->key)) return -1;
        PGresult *res = run_report(d, scope, f, 1, 0);
        if (result_ok(res)) {
            if (rb_puts(b, ",\"summary\":")) { PQclear(res); return -1; }
            if (rb_puts(b, cell(res, 0, "summary"))) { PQclear(res); return -1; }
            PQclear(res);
        } else {
            if (res) PQclear(res);
            if (rb_puts(b, ",\"summary\":null,\"error\":\"Report data unavailable\"")) return -1;
        }
        if (rb_putc(b, '}')) return -1;
    }
    return rb_puts(b, "]}");
}

static void reports_hub(int fd, const char *query, const auth_session_t *sess,
                        const char *origin, char *extra, size_t extra_len) {
    report_scope_t scope;
    if (resolve_scope(sess, query, &scope) != 0) {
        reports_error(fd, 403, "No valid institution scope for this request", origin, extra, extra_len);
        return;
    }
    report_filters_t f;
    if (parse_filters(query, NULL, &f) != 0) {
        reports_error(fd, 400, "from/to must be epoch milliseconds", origin, extra, extra_len);
        return;
    }
    rbuf b;
    if (rb_init(&b, 8192) != 0) { reports_error(fd, 500, "Out of memory", origin, extra, extra_len); return; }
    if (build_hub(&b, &scope, &f, sess) != 0) {
        rb_free(&b);
        reports_error(fd, 500, "Out of memory", origin, extra, extra_len);
        return;
    }
    reports_send(fd, 200, b.data, origin, extra, extra_len);
    rb_free(&b);
}

/* --------------------------------------------------------------- history */

static void reports_history(int fd, const char *query, const auth_session_t *sess,
                            const char *origin, char *extra, size_t extra_len) {
    report_scope_t scope;
    if (resolve_scope(sess, query, &scope) != 0) {
        reports_error(fd, 403, "No valid institution scope for this request", origin, extra, extra_len);
        return;
    }
    const char *params[2] = {scope.inst, scope.global ? "true" : "false"};
    PGresult *res = db_query(
        "SELECT id, report_key, report_group, export_format, filters::text AS filters, "
        "row_count, content_sha256, generated_by, generated_at, status, detail "
        "FROM report_exports WHERE ($2::boolean OR institution_id=$1) "
        "ORDER BY generated_at DESC LIMIT 200", 2, params);
    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
        if (res) PQclear(res);
        reports_error(fd, 500, "Export history unavailable", origin, extra, extra_len);
        return;
    }
    rbuf b;
    if (rb_init(&b, 8192) != 0) { PQclear(res); reports_error(fd, 500, "Out of memory", origin, extra, extra_len); return; }
    int ok = 1;
    if (rb_printf(&b, "{\"generatedAt\":%lld,\"scope\":{\"institutionId\":", now_ms()) ||
        rb_json(&b, scope.inst) ||
        rb_printf(&b, ",\"global\":%s},\"items\":[", scope.global ? "true" : "false"))
        ok = 0;

    int cols = PQnfields(res);
    for (int i = 0; ok && i < PQntuples(res); i++) {
        if (i && rb_putc(&b, ',')) { ok = 0; break; }
        if (rb_putc(&b, '{')) { ok = 0; break; }
        for (int c = 0; c < cols; c++) {
            const char *name = PQfname(res, c);
            const char *value = PQgetvalue(res, i, c);
            if (c && rb_putc(&b, ',')) { ok = 0; break; }
            if (rb_json(&b, name) || rb_putc(&b, ':')) { ok = 0; break; }
            if (!strcmp(name, "filters")) {
                if (rb_puts(&b, value && value[0] ? value : "{}")) { ok = 0; break; }
            } else if (!strcmp(name, "row_count") || !strcmp(name, "generated_at")) {
                if (rb_puts(&b, value && value[0] ? value : "0")) { ok = 0; break; }
            } else if (PQgetisnull(res, i, c)) {
                if (rb_puts(&b, "null")) { ok = 0; break; }
            } else if (rb_json(&b, value)) {
                ok = 0; break;
            }
        }
        if (!ok) break;
        if (rb_putc(&b, '}')) { ok = 0; break; }
    }
    PQclear(res);
    if (ok && rb_puts(&b, "]}")) ok = 0;
    if (!ok) { rb_free(&b); reports_error(fd, 500, "Out of memory", origin, extra, extra_len); return; }
    reports_send(fd, 200, b.data, origin, extra, extra_len);
    rb_free(&b);
}

/* ---------------------------------------------------------------- export */

static int gen_id(char *out, size_t out_len, const char *prefix) {
    unsigned char random[16];
    static const char hex[] = "0123456789abcdef";
    size_t prefix_len = strlen(prefix);
    if (out_len < prefix_len + sizeof(random) * 2 + 1) return -1;
    if (RAND_bytes(random, sizeof(random)) != 1) return -1;
    memcpy(out, prefix, prefix_len);
    for (size_t i = 0; i < sizeof(random); i++) {
        out[prefix_len + i * 2] = hex[random[i] >> 4];
        out[prefix_len + i * 2 + 1] = hex[random[i] & 15];
    }
    out[prefix_len + sizeof(random) * 2] = '\0';
    return 0;
}

static int sha256_hex(const char *data, size_t len, char out[65]) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
             EVP_DigestUpdate(ctx, data, len) == 1 &&
             EVP_DigestFinal_ex(ctx, digest, &digest_len) == 1 &&
             digest_len == 32;
    EVP_MD_CTX_free(ctx);
    if (!ok) return -1;
    static const char hex[] = "0123456789abcdef";
    for (unsigned int i = 0; i < digest_len; i++) {
        out[i * 2] = hex[digest[i] >> 4];
        out[i * 2 + 1] = hex[digest[i] & 15];
    }
    out[64] = '\0';
    return 0;
}

static void filename_timestamp(char *out, size_t out_len) {
    time_t t = time(NULL);
    struct tm tmv;
    gmtime_r(&t, &tmv);
    strftime(out, out_len, "%Y%m%d-%H%M%S", &tmv);
}

static void reports_export(int fd, const char *query, const char *body,
                           const auth_session_t *sess, const char *origin,
                           char *extra, size_t extra_len) {
    if (!export_allowed(sess->role)) {
        reports_error(fd, 403, "Your role cannot export reports", origin, extra, extra_len);
        return;
    }
    if (!body || body[0] != '{') {
        reports_error(fd, 400, "A JSON body is required", origin, extra, extra_len);
        return;
    }
    char report_key[64] = {0}, group[24] = {0}, format[16] = {0};
    json_scalar(body, "report", report_key, sizeof(report_key));
    json_scalar(body, "group", group, sizeof(group));
    json_scalar(body, "format", format, sizeof(format));
    if (!report_key[0]) {
        reports_error(fd, 400, "A report key is required", origin, extra, extra_len);
        return;
    }
    const report_def_t *d = find_report(report_key);
    if (!d) {
        reports_error(fd, 400, "Unknown report", origin, extra, extra_len);
        return;
    }
    if (!group[0]) snprintf(group, sizeof(group), "%s", d->group);
    if (strcmp(group, d->group)) {
        reports_error(fd, 400, "Report does not belong to that group", origin, extra, extra_len);
        return;
    }
    if (!group_allowed(sess->role, d->group)) {
        reports_error(fd, 403, "Your role cannot view this report group", origin, extra, extra_len);
        return;
    }
    for (char *p = format; *p; p++) *p = (char)tolower((unsigned char)*p);
    if (strcmp(format, "csv") && strcmp(format, "json")) {
        reports_error(fd, 415, "Only csv and json exports are supported", origin, extra, extra_len);
        return;
    }
    report_scope_t scope;
    if (resolve_scope(sess, query, &scope) != 0) {
        reports_error(fd, 403, "No valid institution scope for this request", origin, extra, extra_len);
        return;
    }
    report_filters_t f;
    if (parse_filters(query, body, &f) != 0) {
        reports_error(fd, 400, "from/to must be epoch milliseconds", origin, extra, extra_len);
        return;
    }

    PGresult *res = run_report(d, &scope, &f, 10000, 0);
    if (!result_ok(res)) {
        if (res) PQclear(res);
        reports_error(fd, 500, "Report query failed", origin, extra, extra_len);
        return;
    }
    int total_col = PQfnumber(res, "total");
    long total = total_col >= 0 ? atol(PQgetvalue(res, 0, total_col)) : 0;
    if (total < 0) total = 0;
    int row_count = total > 10000 ? 10000 : (int)total;
    const char *rows_text = cell(res, 0, "rows");

    rbuf coljson;
    if (rb_init(&coljson, 1024) != 0) { PQclear(res); reports_error(fd, 500, "Out of memory", origin, extra, extra_len); return; }
    int col_ok = rb_putc(&coljson, '[');
    for (int i = 0; col_ok == 0 && i < d->col_count; i++) {
        if (i && rb_putc(&coljson, ',')) { col_ok = -1; break; }
        if (rb_puts(&coljson, "{\"key\":")) { col_ok = -1; break; }
        if (rb_json(&coljson, d->cols[i].key)) { col_ok = -1; break; }
        if (rb_puts(&coljson, ",\"label\":")) { col_ok = -1; break; }
        if (rb_json(&coljson, d->cols[i].label)) { col_ok = -1; break; }
        if (rb_putc(&coljson, '}')) { col_ok = -1; break; }
    }
    if (col_ok == 0) col_ok = rb_putc(&coljson, ']');
    if (col_ok != 0) {
        rb_free(&coljson);
        PQclear(res);
        reports_error(fd, 500, "Out of memory", origin, extra, extra_len);
        return;
    }

    char *content = NULL;
    const char *content_type = strcmp(format, "csv") ? "application/json" : "text/csv;charset=utf-8";
    if (!strcmp(format, "csv")) {
        const char *cp[2] = {rows_text, coljson.data};
        PGresult *csv = db_query("SELECT report_rows_csv($1::jsonb, $2::jsonb)", 2, cp);
        if (!csv || PQresultStatus(csv) != PGRES_TUPLES_OK || PQntuples(csv) != 1) {
            if (csv) PQclear(csv);
            rb_free(&coljson);
            PQclear(res);
            reports_error(fd, 500, "CSV rendering failed", origin, extra, extra_len);
            return;
        }
        const char *rendered = PQgetvalue(csv, 0, 0);
        content = dup_string(rendered ? rendered : "");
        PQclear(csv);
    } else {
        content = dup_string(rows_text ? rows_text : "[]");
    }
    rb_free(&coljson);
    PQclear(res);
    if (!content) {
        reports_error(fd, 500, "Out of memory", origin, extra, extra_len);
        return;
    }

    char digest[65];
    if (sha256_hex(content, strlen(content), digest) != 0) {
        free(content);
        reports_error(fd, 500, "Could not hash export", origin, extra, extra_len);
        return;
    }

    rbuf filters_json;
    if (rb_init(&filters_json, 512) != 0) {
        free(content);
        reports_error(fd, 500, "Out of memory", origin, extra, extra_len);
        return;
    }
    if (append_filters_json(&filters_json, &f) != 0) {
        rb_free(&filters_json);
        free(content);
        reports_error(fd, 500, "Out of memory", origin, extra, extra_len);
        return;
    }

    char export_id[64];
    char generated_at[32];
    char row_count_text[16];
    char timestamp[32];
    snprintf(generated_at, sizeof(generated_at), "%lld", now_ms());
    snprintf(row_count_text, sizeof(row_count_text), "%d", row_count);
    filename_timestamp(timestamp, sizeof(timestamp));
    if (gen_id(export_id, sizeof(export_id), "rex_") != 0) {
        rb_free(&filters_json);
        free(content);
        reports_error(fd, 500, "Could not allocate export id", origin, extra, extra_len);
        return;
    }

    const char *ip[11] = {
        export_id,
        scope.global ? NULL : scope.inst,
        d->key,
        d->group,
        format,
        filters_json.data,
        row_count_text,
        digest,
        sess->user_id,
        generated_at,
        "server-generated export"
    };
    PGresult *ins = db_query(
        "INSERT INTO report_exports (id, institution_id, report_key, report_group, export_format, "
        "filters, row_count, content_sha256, generated_by, generated_at, status, detail) "
        "VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7::int,$8,$9,$10::bigint,'completed',$11)", 11, ip);
    int insert_ok = ins && PQresultStatus(ins) == PGRES_COMMAND_OK;
    if (ins) PQclear(ins);
    if (!insert_ok) {
        rb_free(&filters_json);
        free(content);
        reports_error(fd, 500, "Export history could not be recorded; export aborted", origin, extra, extra_len);
        return;
    }
    rb_free(&filters_json);

    char filename[160];
    snprintf(filename, sizeof(filename), "sppio-%s-%s.%s", d->key, timestamp,
             strcmp(format, "csv") ? "json" : "csv");

    rbuf b;
    if (rb_init(&b, strlen(content) + 1024) != 0) {
        free(content);
        reports_error(fd, 500, "Out of memory", origin, extra, extra_len);
        return;
    }
    int ok = rb_puts(&b, "{\"report\":") == 0 &&
             rb_json(&b, d->key) == 0 &&
             rb_puts(&b, ",\"group\":") == 0 && rb_json(&b, d->group) == 0 &&
             rb_puts(&b, ",\"format\":") == 0 && rb_json(&b, format) == 0 &&
             rb_puts(&b, ",\"filename\":") == 0 && rb_json(&b, filename) == 0 &&
             rb_puts(&b, ",\"contentType\":") == 0 && rb_json(&b, content_type) == 0 &&
             rb_puts(&b, ",\"content\":") == 0 && rb_json(&b, content) == 0 &&
             rb_printf(&b, ",\"rowCount\":%d,\"total\":%ld,\"truncated\":%s",
                       row_count, total, total > row_count ? "true" : "false") == 0 &&
             rb_puts(&b, ",\"sha256\":") == 0 && rb_json(&b, digest) == 0 &&
             rb_printf(&b, ",\"exportId\":") == 0 && rb_json(&b, export_id) == 0 &&
             rb_printf(&b, ",\"generatedAt\":%lld}", now_ms()) == 0;
    free(content);
    if (!ok) { rb_free(&b); reports_error(fd, 500, "Out of memory", origin, extra, extra_len); return; }
    reports_send(fd, 200, b.data, origin, extra, extra_len);
    rb_free(&b);
}

/* --------------------------------------------------------------- dispatch */

void reports_handle(int client_fd, const char *method, const char *path,
                    const char *body, const char *auth_header,
                    const char *origin, char *extra_headers, size_t extra_len) {
    auth_session_t sess;
    if (ctrl_authorize(auth_header, AUTH_PERM_READ, &sess) != 0) {
        reports_error(client_fd, 401, "Admin credentials required", origin, extra_headers, extra_len);
        return;
    }
    if (!method || !path) {
        reports_error(client_fd, 400, "Bad request", origin, extra_headers, extra_len);
        return;
    }

    char route[256];
    snprintf(route, sizeof(route), "%s", path);
    char *query = strchr(route, '?');
    if (query) { *query = '\0'; query++; }

    if (strcmp(method, "GET") == 0) {
        if (!strcmp(route, "/api/v1/reports/catalog")) {
            rbuf b;
            if (rb_init(&b, 8192) != 0 || build_catalog(&b, &sess) != 0) {
                rb_free(&b);
                reports_error(client_fd, 500, "Out of memory", origin, extra_headers, extra_len);
                return;
            }
            reports_send(client_fd, 200, b.data, origin, extra_headers, extra_len);
            rb_free(&b);
            return;
        }
        if (!strcmp(route, "/api/v1/reports/hub")) {
            reports_hub(client_fd, query, &sess, origin, extra_headers, extra_len);
            return;
        }
        if (!strcmp(route, "/api/v1/reports/history")) {
            reports_history(client_fd, query, &sess, origin, extra_headers, extra_len);
            return;
        }
        if (!strcmp(route, "/api/v1/reports/exams")) {
            reports_group(client_fd, "exams", query, &sess, origin, extra_headers, extra_len);
            return;
        }
        if (!strcmp(route, "/api/v1/reports/devices")) {
            reports_group(client_fd, "devices", query, &sess, origin, extra_headers, extra_len);
            return;
        }
        if (!strcmp(route, "/api/v1/reports/security")) {
            reports_group(client_fd, "security", query, &sess, origin, extra_headers, extra_len);
            return;
        }
        if (!strcmp(route, "/api/v1/reports/business")) {
            reports_group(client_fd, "business", query, &sess, origin, extra_headers, extra_len);
            return;
        }
        reports_error(client_fd, 404, "Unknown report endpoint", origin, extra_headers, extra_len);
        return;
    }

    if (strcmp(method, "POST") == 0 && !strcmp(route, "/api/v1/reports/export")) {
        reports_export(client_fd, query, body, &sess, origin, extra_headers, extra_len);
        return;
    }

    reports_error(client_fd, 405, "Method not allowed", origin, extra_headers, extra_len);
}
