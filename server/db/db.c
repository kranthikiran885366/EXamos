/*
 * db.c — PostgreSQL connection pool and schema for ExamOS server.
 *
 * All frontend IndexedDB collections are mirrored as durable PostgreSQL
 * tables. The C server is the source of truth; the React console reads
 * from and writes to these tables over the REST API.
 */

#include "db.h"
#include "../include/config_manager.h"
#include "../include/secure_token.h"
#include "../security/security.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>

static pthread_once_t db_init_once = PTHREAD_ONCE_INIT;

db_pool_t g_db_pool;
int g_db_pool_count = 0;

static void db_pool_init_once(void) {
    memset(&g_db_pool, 0, sizeof(g_db_pool));
    pthread_mutex_init(&g_db_pool.lock, NULL);
}

int db_init(const char *conninfo) {
    pthread_once(&db_init_once, db_pool_init_once);

    const char *ci = conninfo;
    if (!ci || !ci[0]) ci = getenv("EXAMOS_DATABASE_URL");
    char file_buf[1024] = {0};
    if (!ci || !ci[0]) {
        const char *fpath = getenv("EXAMOS_DATABASE_URL_FILE");
        if (fpath && fpath[0]) {
            FILE *fp = fopen(fpath, "r");
            if (fp) {
                if (fgets(file_buf, sizeof(file_buf) - 1, fp)) {
                    size_t flen = strlen(file_buf);
                    while (flen > 0 && (file_buf[flen - 1] == '\n' || file_buf[flen - 1] == '\r')) {
                        file_buf[--flen] = '\0';
                    }
                    if (file_buf[0]) ci = file_buf;
                }
                fclose(fp);
            }
        }
    }
    if (!ci || !ci[0]) ci = "host=localhost port=5432 dbname=examos user=examos password=examos";

    int count = 8;
    const char *ec = getenv("EXAMOS_DB_MAX_CONNECTIONS");
    if (ec && ec[0]) count = atoi(ec);
    if (count < 1) count = 8;
    if (count > EXAMOS_DB_MAX_CONNECTIONS) count = EXAMOS_DB_MAX_CONNECTIONS;

    g_db_pool_count = count;
    for (int i = 0; i < count; i++) {
        PGconn *c = PQconnectdb(ci);
        if (PQstatus(c) != CONNECTION_OK) {
            fprintf(stderr, "[DB] Connection %d failed: %s\n", i, PQerrorMessage(c));
            PQfinish(c);
            g_db_pool.conns[i].conn = NULL;
            continue;
        }
        g_db_pool.conns[i].conn = c;
        g_db_pool.conns[i].in_use = 0;
        g_db_pool.conns[i].checked_out_at = 0;
    }
    int ready = 0;
    for (int i = 0; i < count; i++)
        if (g_db_pool.conns[i].conn) ready++;
    if (ready == 0) return -1;
    fprintf(stderr, "[DB] Pool ready: %d/%d connections\n", ready, count);
    return 0;
}

void db_shutdown(void) {
    pthread_mutex_lock(&g_db_pool.lock);
    for (int i = 0; i < g_db_pool_count; i++) {
        if (g_db_pool.conns[i].conn) {
            PQfinish(g_db_pool.conns[i].conn);
            g_db_pool.conns[i].conn = NULL;
        }
    }
    g_db_pool_count = 0;
    pthread_mutex_unlock(&g_db_pool.lock);
}

PGconn *db_acquire(void) {
    pthread_mutex_lock(&g_db_pool.lock);
    for (;;) {
        for (int i = 0; i < g_db_pool_count; i++) {
            if (!g_db_pool.conns[i].conn) continue;
            if (!g_db_pool.conns[i].in_use) {
                if (PQstatus(g_db_pool.conns[i].conn) != CONNECTION_OK) {
                    PQfinish(g_db_pool.conns[i].conn);
                    const char *ci = getenv("EXAMOS_DATABASE_URL");
                    if (!ci) ci = "host=localhost port=5432 dbname=examos user=examos password=examos";
                    PGconn *nc = PQconnectdb(ci);
                    if (PQstatus(nc) != CONNECTION_OK) {
                        PQfinish(nc);
                        continue;
                    }
                    g_db_pool.conns[i].conn = nc;
                }
                g_db_pool.conns[i].in_use = 1;
                g_db_pool.conns[i].checked_out_at = time(NULL);
                PGconn *c = g_db_pool.conns[i].conn;
                pthread_mutex_unlock(&g_db_pool.lock);
                return c;
            }
        }
        pthread_mutex_unlock(&g_db_pool.lock);
        struct timespec ts = { 0, 1000000L };
        nanosleep(&ts, NULL);
        pthread_mutex_lock(&g_db_pool.lock);
    }
}

void db_release(PGconn *conn, int broken) {
    pthread_mutex_lock(&g_db_pool.lock);
    for (int i = 0; i < g_db_pool_count; i++) {
        if (g_db_pool.conns[i].conn == conn) {
            if (broken || PQstatus(conn) != CONNECTION_OK) {
                PQfinish(conn);
                const char *ci = getenv("EXAMOS_DATABASE_URL");
                if (!ci) ci = "host=localhost port=5432 dbname=examos user=examos password=examos";
                PGconn *nc = PQconnectdb(ci);
                if (PQstatus(nc) == CONNECTION_OK) {
                    g_db_pool.conns[i].conn = nc;
                } else {
                    PQfinish(nc);
                    g_db_pool.conns[i].conn = NULL;
                }
            }
            g_db_pool.conns[i].in_use = 0;
            g_db_pool.conns[i].checked_out_at = 0;
            break;
        }
    }
    pthread_mutex_unlock(&g_db_pool.lock);
}

PGresult *db_exec(PGconn *conn, const char *sql, int n_params, const char **params,
                  const int *param_lengths, const int *param_formats, int result_format) {
    if (!conn || PQstatus(conn) != CONNECTION_OK) return NULL;
    return PQexecParams(conn, sql, n_params, NULL, params,
                        param_lengths, param_formats, result_format);
}

PGresult *db_query(const char *sql, int n_params, const char **params) {
    PGconn *conn = db_acquire();
    PGresult *res = db_exec(conn, sql, n_params, params, NULL, NULL, 0);
    db_release(conn, res && PQresultStatus(res) != PGRES_TUPLES_OK &&
                      PQresultStatus(res) != PGRES_COMMAND_OK);
    return res;
}

PGresult *db_simple(PGconn *conn, const char *sql,
                    int n_params, const char **params, const int *lens) {
    if (!conn || PQstatus(conn) != CONNECTION_OK) return NULL;
    return PQexecParams(conn, sql, n_params, (const Oid *)NULL,
                        params, lens, NULL, 0);
}

int db_health(void) {
    PGconn *conn = db_acquire();
    int ok = 0;
    if (conn && PQstatus(conn) == CONNECTION_OK) {
        PGresult *res = PQexec(conn, "SELECT 1");
        if (res && PQresultStatus(res) == PGRES_TUPLES_OK) ok = 0;
        else ok = -1;
        if (res) PQclear(res);
    } else ok = -1;
    db_release(conn, ok != 0);
    return ok;
}

/* =========================================================================
 * Schema (single SQL string with all CREATE TABLE statements)
 * ========================================================================= */
static const char *migration_sql =
"CREATE TABLE IF NOT EXISTS examos_schema_migrations ("
"  version VARCHAR(32) PRIMARY KEY,"
"  applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()"
");"

"CREATE TABLE IF NOT EXISTS tenants ("
"  id VARCHAR(64) PRIMARY KEY,"
"  name VARCHAR(128) NOT NULL,"
"  code VARCHAR(32) NOT NULL UNIQUE,"
"  domains JSONB NOT NULL DEFAULT '[]'::jsonb,"
"  contact_email VARCHAR(120),"
"  contact_phone VARCHAR(30),"
"  region VARCHAR(40) DEFAULT 'India · Mumbai',"
"  timezone VARCHAR(40) DEFAULT 'Asia/Kolkata',"
"  plan VARCHAR(40) DEFAULT 'pilot',"
"  status VARCHAR(20) DEFAULT 'active',"
"  max_centers INTEGER DEFAULT 5,"
"  max_candidates INTEGER DEFAULT 500,"
"  deployment_model VARCHAR(20) DEFAULT 'usb-boot',"
"  branding JSONB NOT NULL DEFAULT '{}'::jsonb,"
"  notification_prefs JSONB NOT NULL DEFAULT '{}'::jsonb,"
"  exam_defaults JSONB NOT NULL DEFAULT '{}'::jsonb,"
"  security JSONB NOT NULL DEFAULT '{}'::jsonb,"
"  history JSONB NOT NULL DEFAULT '[]'::jsonb,"
"  created_at BIGINT NOT NULL,"
"  created_by VARCHAR(64)"
");"

"CREATE TABLE IF NOT EXISTS campuses ("
"  id VARCHAR(64) PRIMARY KEY,"
"  tenant_id VARCHAR(64) NOT NULL,"
"  name VARCHAR(80) NOT NULL,"
"  code VARCHAR(10) NOT NULL,"
"  city VARCHAR(40),"
"  address VARCHAR(160),"
"  capacity INTEGER DEFAULT 0,"
"  status VARCHAR(20) DEFAULT 'active',"
"  admin_ids JSONB NOT NULL DEFAULT '[]'::jsonb,"
"  created_at BIGINT NOT NULL,"
"  CONSTRAINT fk_campus_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)"
");"

"CREATE TABLE IF NOT EXISTS departments ("
"  id VARCHAR(64) PRIMARY KEY,"
"  tenant_id VARCHAR(64) NOT NULL,"
"  name VARCHAR(80) NOT NULL,"
"  code VARCHAR(12) NOT NULL,"
"  type VARCHAR(20) DEFAULT 'academic',"
"  campus_id VARCHAR(64),"
"  status VARCHAR(20) DEFAULT 'active',"
"  created_at BIGINT NOT NULL,"
"  CONSTRAINT fk_dept_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)"
");"

"CREATE TABLE IF NOT EXISTS centers ("
"  id VARCHAR(64) PRIMARY KEY,"
"  tenant_id VARCHAR(64) NOT NULL,"
"  campus_id VARCHAR(64),"
"  code VARCHAR(10) NOT NULL,"
"  name VARCHAR(80) NOT NULL,"
"  city VARCHAR(40),"
"  labs INTEGER DEFAULT 1,"
"  seats_per_lab INTEGER DEFAULT 24,"
"  capacity INTEGER DEFAULT 24,"
"  status VARCHAR(20) DEFAULT 'active',"
"  created_at BIGINT NOT NULL,"
"  CONSTRAINT fk_center_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)"
");"

"CREATE TABLE IF NOT EXISTS users ("
"  id VARCHAR(64) PRIMARY KEY,"
"  username VARCHAR(64) NOT NULL UNIQUE,"
"  name VARCHAR(128) NOT NULL,"
"  role VARCHAR(40) NOT NULL,"
"  title VARCHAR(120),"
"  email VARCHAR(120),"
"  tenant_id VARCHAR(64),"
"  password_hash VARCHAR(256),"
"  salt VARCHAR(64),"
"  totp_secret VARCHAR(64),"
"  recovery_codes JSONB NOT NULL DEFAULT '[]'::jsonb,"
"  mfa_enabled INTEGER DEFAULT 1,"
"  status VARCHAR(20) DEFAULT 'active',"
"  status_reason TEXT,"
"  status_at BIGINT,"
"  status_by VARCHAR(64),"
"  password_changed_at BIGINT,"
"  last_login BIGINT,"
"  created_at BIGINT NOT NULL,"
"  CONSTRAINT fk_user_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)"
");"

"CREATE TABLE IF NOT EXISTS exams ("
"  id VARCHAR(64) PRIMARY KEY,"
"  tenant_id VARCHAR(64) NOT NULL,"
"  code VARCHAR(20) NOT NULL,"
"  title VARCHAR(100) NOT NULL,"
"  description TEXT,"
"  course VARCHAR(80),"
"  department_id VARCHAR(64),"
"  academic_year VARCHAR(20),"
"  type VARCHAR(20) DEFAULT 'internal',"
"  center_ids JSONB NOT NULL DEFAULT '[]'::jsonb,"
"  start_at BIGINT NOT NULL,"
"  duration_min INTEGER DEFAULT 60,"
"  timezone VARCHAR(40) DEFAULT 'Asia/Kolkata',"
"  late_entry_min INTEGER DEFAULT 0,"
"  capacity INTEGER DEFAULT 0,"
"  instructions TEXT,"
"  resources TEXT,"
"  accommodations TEXT,"
"  auth_mode VARCHAR(20) DEFAULT 'candidate-login',"
"  identity_required INTEGER DEFAULT 1,"
"  origins JSONB NOT NULL DEFAULT '[]'::jsonb,"
"  navigation VARCHAR(10) DEFAULT 'locked',"
"  allowed_destinations JSONB NOT NULL DEFAULT '[]'::jsonb,"
"  compatibility_profile VARCHAR(40) DEFAULT 'standard-uefi',"
"  attestation_level VARCHAR(20) DEFAULT 'tpm',"
"  session_timeout_min INTEGER DEFAULT 15,"
"  reconnect_policy VARCHAR(20) DEFAULT 'allow-reconnect',"
"  submission_mode VARCHAR(10) DEFAULT 'either',"
"  required_checks JSONB NOT NULL DEFAULT '[]'::jsonb,"
"  policy_id VARCHAR(64),"
"  questions JSONB NOT NULL DEFAULT '[]'::jsonb,"
"  status VARCHAR(20) DEFAULT 'draft',"
"  created_by VARCHAR(64),"
"  created_at BIGINT NOT NULL,"
"  updated_at BIGINT NOT NULL,"
"  version INTEGER DEFAULT 1,"
"  locked INTEGER DEFAULT 0,"
"  published_at BIGINT,"
"  published_by VARCHAR(64),"
"  approved_by VARCHAR(64),"
"  live_at BIGINT,"
"  closed_at BIGINT,"
"  cancelled_at BIGINT,"
"  cancel_reason TEXT,"
"  early_reason TEXT,"
"  summary JSONB,"
"  history JSONB NOT NULL DEFAULT '[]'::jsonb,"
"  CONSTRAINT fk_exam_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)"
");"

"CREATE TABLE IF NOT EXISTS candidates ("
"  id VARCHAR(64) PRIMARY KEY,"
"  tenant_id VARCHAR(64) NOT NULL,"
"  roll_no VARCHAR(20) NOT NULL,"
"  name VARCHAR(80) NOT NULL,"
"  email VARCHAR(120),"
"  exam_id VARCHAR(64),"
"  center_id VARCHAR(64),"
"  seat VARCHAR(8),"
"  pin_hash VARCHAR(256),"
"  identity VARCHAR(20) DEFAULT 'pending',"
"  identity_by VARCHAR(64),"
"  identity_at BIGINT,"
"  identity_note TEXT,"
"  status VARCHAR(20) DEFAULT 'registered',"
"  exceptions JSONB NOT NULL DEFAULT '[]'::jsonb,"
"  corrections JSONB NOT NULL DEFAULT '[]'::jsonb,"
"  assigned_at BIGINT,"
"  created_at BIGINT NOT NULL,"
"  CONSTRAINT fk_candidate_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)"
");"

"CREATE TABLE IF NOT EXISTS sessions ("
"  id VARCHAR(64) PRIMARY KEY,"
"  tenant_id VARCHAR(64) NOT NULL,"
"  exam_id VARCHAR(64) NOT NULL,"
"  candidate_id VARCHAR(64) NOT NULL,"
"  device_id VARCHAR(64),"
"  status VARCHAR(20) DEFAULT 'in_progress',"
"  started_at BIGINT NOT NULL,"
"  deadline BIGINT NOT NULL,"
"  submitted_at BIGINT,"
"  answers JSONB NOT NULL DEFAULT '{}'::jsonb,"
"  last_saved_at BIGINT NOT NULL,"
"  score INTEGER,"
"  auto INTEGER DEFAULT 0,"
"  why TEXT,"
"  terminated_by VARCHAR(64),"
"  terminated_reason TEXT,"
"  extensions JSONB NOT NULL DEFAULT '[]'::jsonb,"
"  receipt_payload JSONB,"
"  receipt_sig TEXT,"
"  receipt TEXT,"
"  receipt_payload_hash TEXT,"
"  history JSONB NOT NULL DEFAULT '[]'::jsonb,"
"  CONSTRAINT fk_session_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)"
");"

"CREATE TABLE IF NOT EXISTS devices ("
"  id VARCHAR(64) PRIMARY KEY,"
"  tenant_id VARCHAR(64) NOT NULL,"
"  center_id VARCHAR(64),"
"  seat VARCHAR(8),"
"  hostname VARCHAR(64),"
"  serial VARCHAR(40),"
"  release_id VARCHAR(64),"
"  policy_id VARCHAR(64),"
"  status VARCHAR(20) DEFAULT 'enrolled',"
"  trust VARCHAR(20) DEFAULT 'unknown',"
"  isolated INTEGER DEFAULT 0,"
"  tampered INTEGER DEFAULT 0,"
"  last_seen BIGINT,"
"  last_attested BIGINT,"
"  silent_until BIGINT,"
"  enrolled_at BIGINT NOT NULL,"
"  enrolled_by VARCHAR(64),"
"  profile VARCHAR(40) DEFAULT 'standard-uefi',"
"  hardware JSONB NOT NULL DEFAULT '{}'::jsonb,"
"  compat_status VARCHAR(20) DEFAULT 'NOT_RUN',"
"  last_compat_at BIGINT,"
"  compat_fail JSONB NOT NULL DEFAULT '[]'::jsonb,"
"  compat_unknown JSONB NOT NULL DEFAULT '[]'::jsonb,"
"  exceptions JSONB NOT NULL DEFAULT '[]'::jsonb,"
"  kiosk_id VARCHAR(64),"
"  status_reason TEXT,"
"  status_at BIGINT,"
"  history JSONB NOT NULL DEFAULT '[]'::jsonb,"
"  CONSTRAINT fk_device_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)"
");"

"CREATE TABLE IF NOT EXISTS attestations ("
"  id VARCHAR(64) PRIMARY KEY,"
"  tenant_id VARCHAR(64) NOT NULL,"
"  device_id VARCHAR(64) NOT NULL,"
"  hostname VARCHAR(64),"
"  nonce VARCHAR(64) NOT NULL,"
"  issued_at BIGINT NOT NULL,"
"  status VARCHAR(20) DEFAULT 'issued',"
"  used_at BIGINT,"
"  result VARCHAR(20),"
"  reason TEXT,"
"  verified_at BIGINT,"
"  quote JSONB,"
"  pcr_digest TEXT,"
"  release_id VARCHAR(64),"
"  CONSTRAINT fk_attestation_device FOREIGN KEY (device_id) REFERENCES devices(id)"
");"

"CREATE TABLE IF NOT EXISTS policies ("
"  id VARCHAR(64) PRIMARY KEY,"
"  tenant_id VARCHAR(64) NOT NULL,"
"  name VARCHAR(60) NOT NULL,"
"  version INTEGER DEFAULT 1,"
"  status VARCHAR(20) DEFAULT 'draft',"
"  created_by VARCHAR(64),"
"  created_at BIGINT NOT NULL,"
"  published_by VARCHAR(64),"
"  published_at BIGINT,"
"  hash TEXT,"
"  sig TEXT,"
"  rolled_back_from INTEGER,"
"  config JSONB NOT NULL DEFAULT '{}'::jsonb,"
"  history JSONB NOT NULL DEFAULT '[]'::jsonb,"
"  CONSTRAINT fk_policy_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)"
");"

"CREATE TABLE IF NOT EXISTS releases ("
"  id VARCHAR(64) PRIMARY KEY,"
"  version VARCHAR(30) NOT NULL,"
"  manifest JSONB NOT NULL DEFAULT '{}'::jsonb,"
"  digest TEXT,"
"  sig TEXT,"
"  findings JSONB NOT NULL DEFAULT '[]'::jsonb,"
"  critical_cves INTEGER DEFAULT 0,"
"  status VARCHAR(20) DEFAULT 'candidate',"
"  rollout INTEGER DEFAULT 0,"
"  created_by VARCHAR(64),"
"  created_at BIGINT NOT NULL,"
"  approved_by VARCHAR(64),"
"  approved_at BIGINT,"
"  submitted_at BIGINT,"
"  approval_id VARCHAR(64),"
"  revoked_reason TEXT,"
"  revoked_at BIGINT,"
"  rolled_back_to VARCHAR(64),"
"  paused_at BIGINT,"
"  paused_by VARCHAR(64),"
"  pause_reason TEXT,"
"  resumed_at BIGINT,"
"  resumed_by VARCHAR(64),"
"  CONSTRAINT fk_release_rollback FOREIGN KEY (rolled_back_to) REFERENCES releases(id)"
");"

"CREATE TABLE IF NOT EXISTS release_evidence ("
"  id VARCHAR(64) PRIMARY KEY,"
"  release_id VARCHAR(64) NOT NULL,"
"  version VARCHAR(30),"
"  title VARCHAR(120) NOT NULL,"
"  kind VARCHAR(40) NOT NULL,"
"  classification VARCHAR(20) DEFAULT 'internal',"
"  content TEXT,"
"  link VARCHAR(300),"
"  hash TEXT,"
"  size INTEGER DEFAULT 0,"
"  status VARCHAR(20) DEFAULT 'sealed',"
"  verification VARCHAR(20) DEFAULT 'sealed',"
"  created_by VARCHAR(64),"
"  created_at BIGINT NOT NULL,"
"  verified_at BIGINT,"
"  CONSTRAINT fk_release_evidence_release FOREIGN KEY (release_id) REFERENCES releases(id)"
");"

"CREATE TABLE IF NOT EXISTS usbs ("
"  id VARCHAR(64) PRIMARY KEY,"
"  tenant_id VARCHAR(64) NOT NULL,"
"  asset_id VARCHAR(40) NOT NULL,"
"  serial VARCHAR(40) NOT NULL,"
"  model VARCHAR(60),"
"  capacity_gb INTEGER DEFAULT 64,"
"  status VARCHAR(20) DEFAULT 'prepared',"
"  release_id VARCHAR(64),"
"  image_digest TEXT,"
"  written_hash TEXT,"
"  station VARCHAR(60),"
"  prepared_at BIGINT,"
"  prepared_by VARCHAR(64),"
"  assigned JSONB,"
"  holder JSONB,"
"  custody JSONB NOT NULL DEFAULT '[]'::jsonb,"
"  notes TEXT,"
"  last_check_at BIGINT,"
"  created_at BIGINT NOT NULL,"
"  created_by VARCHAR(64),"
"  status_reason TEXT,"
"  CONSTRAINT fk_usb_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)"
");"

"CREATE TABLE IF NOT EXISTS kiosks ("
"  id VARCHAR(64) PRIMARY KEY,"
"  tenant_id VARCHAR(64) NOT NULL,"
"  name VARCHAR(60) NOT NULL,"
"  release_id VARCHAR(64),"
"  lockdown JSONB,"
"  block_clipboard INTEGER DEFAULT 0,"
"  block_capture INTEGER DEFAULT 0,"
"  status VARCHAR(20) DEFAULT 'canary',"
"  created_by VARCHAR(64),"
"  created_at BIGINT NOT NULL,"
"  CONSTRAINT fk_kiosk_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)"
");"

"CREATE TABLE IF NOT EXISTS incidents ("
"  id VARCHAR(64) PRIMARY KEY,"
"  no INTEGER NOT NULL,"
"  tenant_id VARCHAR(64) NOT NULL,"
"  key VARCHAR(128),"
"  title VARCHAR(200) NOT NULL,"
"  severity VARCHAR(20) DEFAULT 'medium',"
"  source VARCHAR(80),"
"  device_id VARCHAR(64),"
"  kind VARCHAR(20) DEFAULT 'alert',"
"  status VARCHAR(20) DEFAULT 'open',"
"  owner VARCHAR(64),"
"  notes JSONB NOT NULL DEFAULT '[]'::jsonb,"
"  created_at BIGINT NOT NULL,"
"  CONSTRAINT fk_incident_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)"
");"

"CREATE TABLE IF NOT EXISTS security_events ("
"  id VARCHAR(64) PRIMARY KEY,"
"  tenant_id VARCHAR(64) NOT NULL,"
"  type VARCHAR(60) NOT NULL,"
"  severity VARCHAR(20) DEFAULT 'medium',"
"  title VARCHAR(140) NOT NULL,"
"  detail TEXT,"
"  device_id VARCHAR(64),"
"  source VARCHAR(40) DEFAULT 'console',"
"  status VARCHAR(20) DEFAULT 'open',"
"  actor VARCHAR(64),"
"  at BIGINT NOT NULL,"
"  ack_by VARCHAR(64),"
"  ack_at BIGINT,"
"  note TEXT,"
"  resolved_by VARCHAR(64),"
"  resolved_at BIGINT,"
"  resolution TEXT,"
"  escalated_by VARCHAR(64),"
"  escalated_at BIGINT,"
"  escalation_reason TEXT,"
"  incident_id VARCHAR(64)"
");"

"CREATE TABLE IF NOT EXISTS vulnerabilities ("
"  id VARCHAR(64) PRIMARY KEY,"
"  tenant_id VARCHAR(64) NOT NULL,"
"  cve VARCHAR(30),"
"  component VARCHAR(60) NOT NULL,"
"  title VARCHAR(120) NOT NULL,"
"  severity VARCHAR(20) DEFAULT 'medium',"
"  cvss NUMERIC(3,1) DEFAULT 5.0,"
"  affected VARCHAR(120),"
"  fixed_in VARCHAR(40),"
"  source VARCHAR(40) DEFAULT 'manual',"
"  owner VARCHAR(40),"
"  status VARCHAR(20) DEFAULT 'open',"
"  accept_reason TEXT,"
"  fixed_at BIGINT,"
"  created_at BIGINT NOT NULL,"
"  created_by VARCHAR(64),"
"  history JSONB NOT NULL DEFAULT '[]'::jsonb,"
"  CONSTRAINT fk_vuln_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)"
");"

"CREATE TABLE IF NOT EXISTS evidence ("
"  id VARCHAR(64) PRIMARY KEY,"
"  tenant_id VARCHAR(64) NOT NULL,"
"  title VARCHAR(120) NOT NULL,"
"  kind VARCHAR(40) NOT NULL,"
"  classification VARCHAR(20) DEFAULT 'internal',"
"  body TEXT,"
"  link VARCHAR(300),"
"  release_id VARCHAR(64),"
"  incident_id VARCHAR(64),"
"  tags JSONB NOT NULL DEFAULT '[]'::jsonb,"
"  hash TEXT,"
"  size INTEGER DEFAULT 0,"
"  status VARCHAR(20) DEFAULT 'sealed',"
"  verification VARCHAR(20) DEFAULT 'sealed',"
"  created_by VARCHAR(64),"
"  created_at BIGINT NOT NULL,"
"  verified_at BIGINT,"
"  deleted_at BIGINT,"
"  deleted_by VARCHAR(64),"
"  delete_reason TEXT"
");"

"CREATE TABLE IF NOT EXISTS staff ("
"  id VARCHAR(64) PRIMARY KEY,"
"  tenant_id VARCHAR(64) NOT NULL,"
"  user_id VARCHAR(64) NOT NULL,"
"  name VARCHAR(128),"
"  role_title VARCHAR(60),"
"  campus_id VARCHAR(64),"
"  department_id VARCHAR(64),"
"  status VARCHAR(20) DEFAULT 'active',"
"  status_reason TEXT,"
"  created_at BIGINT NOT NULL,"
"  updated_at BIGINT NOT NULL"
");"

"CREATE TABLE IF NOT EXISTS approvals ("
"  id VARCHAR(64) PRIMARY KEY,"
"  kind VARCHAR(40) NOT NULL,"
"  label VARCHAR(200) NOT NULL,"
"  target_id VARCHAR(64),"
"  tenant_id VARCHAR(64),"
"  reason TEXT,"
"  data JSONB,"
"  requested_by VARCHAR(64),"
"  status VARCHAR(20) DEFAULT 'pending',"
"  decided_by VARCHAR(64),"
"  decided_at BIGINT,"
"  created_at BIGINT NOT NULL"
");"

"CREATE TABLE IF NOT EXISTS keys ("
"  id VARCHAR(64) PRIMARY KEY,"
"  private_key TEXT,"
"  public_jwk JSONB,"
"  created_at BIGINT NOT NULL"
");"

"CREATE TABLE IF NOT EXISTS auth_sessions ("
"  id VARCHAR(64) PRIMARY KEY,"
"  user_id VARCHAR(64),"
"  username VARCHAR(64),"
"  institution_id VARCHAR(64),"
"  role VARCHAR(40),"
"  session_token VARCHAR(65) NOT NULL UNIQUE,"
"  created_at BIGINT NOT NULL,"
"  expires_at BIGINT NOT NULL,"
"  status VARCHAR(20) DEFAULT 'active'"
");"

"CREATE TABLE IF NOT EXISTS configs ("
"  id VARCHAR(64) PRIMARY KEY,"
"  value JSONB NOT NULL DEFAULT '{}'::jsonb,"
"  updated_at BIGINT NOT NULL,"
"  updated_by VARCHAR(64)"
");"

"CREATE TABLE IF NOT EXISTS meta ("
"  id VARCHAR(64) PRIMARY KEY,"
"  value JSONB NOT NULL DEFAULT '{}'::jsonb,"
"  updated_at BIGINT NOT NULL"
");"

"CREATE TABLE IF NOT EXISTS integrations ("
"  id VARCHAR(64) PRIMARY KEY,"
"  name VARCHAR(60) NOT NULL,"
"  kind VARCHAR(20) NOT NULL,"
"  url VARCHAR(300),"
"  secret_set INTEGER DEFAULT 0,"
"  enabled INTEGER DEFAULT 1,"
"  notes TEXT,"
"  last_check_at BIGINT,"
"  status VARCHAR(20) DEFAULT 'not-tested',"
"  created_at BIGINT NOT NULL,"
"  updated_at BIGINT NOT NULL,"
"  updated_by VARCHAR(64)"
");"

"CREATE TABLE IF NOT EXISTS features ("
"  id VARCHAR(64) PRIMARY KEY,"
"  key VARCHAR(40) NOT NULL,"
"  label VARCHAR(120),"
"  description TEXT,"
"  group_name VARCHAR(40),"
"  enabled INTEGER DEFAULT 1,"
"  rollout INTEGER DEFAULT 100,"
"  updated_at BIGINT NOT NULL,"
"  updated_by VARCHAR(64)"
");"

"CREATE TABLE IF NOT EXISTS services ("
"  id VARCHAR(64) PRIMARY KEY,"
"  name VARCHAR(80) NOT NULL,"
"  status VARCHAR(20) DEFAULT 'healthy',"
"  updated_at BIGINT NOT NULL"
");"

"CREATE TABLE IF NOT EXISTS alerts ("
"  id VARCHAR(64) PRIMARY KEY,"
"  title VARCHAR(120) NOT NULL,"
"  severity VARCHAR(20) DEFAULT 'medium',"
"  status VARCHAR(20) DEFAULT 'open',"
"  created_at BIGINT NOT NULL"
");"

"CREATE TABLE IF NOT EXISTS jobs ("
"  id VARCHAR(64) PRIMARY KEY,"
"  name VARCHAR(80) NOT NULL,"
"  status VARCHAR(20) DEFAULT 'pending',"
"  updated_at BIGINT NOT NULL"
");"

"CREATE TABLE IF NOT EXISTS backups ("
"  id VARCHAR(64) PRIMARY KEY,"
"  at BIGINT NOT NULL,"
"  status VARCHAR(20) DEFAULT 'completed',"
"  path TEXT"
");"

"CREATE TABLE IF NOT EXISTS audit ("
"  id VARCHAR(64) PRIMARY KEY,"
"  seq INTEGER NOT NULL UNIQUE,"
"  ts TIMESTAMPTZ NOT NULL,"
"  actor VARCHAR(64),"
"  event VARCHAR(120) NOT NULL,"
"  detail TEXT,"
"  prev TEXT,"
"  hash TEXT NOT NULL"
");"

"CREATE TABLE IF NOT EXISTS api_audit ("
"  id VARCHAR(64) PRIMARY KEY,"
"  actor VARCHAR(64),"
"  method VARCHAR(10),"
"  path TEXT,"
"  status INTEGER,"
"  duration_ms BIGINT,"
"  request_id VARCHAR(64),"
"  error TEXT,"
"  created_at BIGINT NOT NULL"
");"

"CREATE TABLE IF NOT EXISTS support ("
"  id VARCHAR(64) PRIMARY KEY,"
"  no INTEGER NOT NULL,"
"  tenant_id VARCHAR(64),"
"  subject VARCHAR(120) NOT NULL,"
"  description TEXT,"
"  category VARCHAR(40) DEFAULT 'exam',"
"  priority VARCHAR(20) DEFAULT 'medium',"
"  status VARCHAR(20) DEFAULT 'open',"
"  requester_name VARCHAR(120),"
"  requester_email VARCHAR(120),"
"  assigned_to VARCHAR(64),"
"  created_at BIGINT NOT NULL"
");"

"CREATE TABLE IF NOT EXISTS notifications ("
"  id VARCHAR(64) PRIMARY KEY,"
"  tenant_id VARCHAR(64),"
"  user_id VARCHAR(64),"
"  title VARCHAR(120) NOT NULL,"
"  body TEXT,"
"  link VARCHAR(300),"
"  role VARCHAR(40),"
"  tone VARCHAR(20) DEFAULT 'info',"
"  read_by JSONB NOT NULL DEFAULT '[]'::jsonb,"
"  created_at BIGINT NOT NULL"
");"

"CREATE TABLE IF NOT EXISTS reports ("
"  id VARCHAR(64) PRIMARY KEY,"
"  title VARCHAR(120) NOT NULL,"
"  kind VARCHAR(40) NOT NULL,"
"  tenant_id VARCHAR(64),"
"  content JSONB,"
"  created_at BIGINT NOT NULL"
");"

"CREATE TABLE IF NOT EXISTS plans ("
"  id VARCHAR(64) PRIMARY KEY,"
"  name VARCHAR(80) NOT NULL,"
"  price_cents INTEGER DEFAULT 0,"
"  currency VARCHAR(10) DEFAULT 'INR',"
"  active INTEGER DEFAULT 1"
");"

"CREATE TABLE IF NOT EXISTS subscriptions ("
"  id VARCHAR(64) PRIMARY KEY,"
"  tenant_id VARCHAR(64),"
"  plan_id VARCHAR(64),"
"  status VARCHAR(20) DEFAULT 'active',"
"  started_at BIGINT,"
"  expires_at BIGINT"
");"

"CREATE TABLE IF NOT EXISTS invoices ("
"  id VARCHAR(64) PRIMARY KEY,"
"  tenant_id VARCHAR(64),"
"  amount_cents INTEGER DEFAULT 0,"
"  status VARCHAR(20) DEFAULT 'unpaid',"
"  issued_at BIGINT NOT NULL"
");"

"CREATE TABLE IF NOT EXISTS privacy ("
"  id VARCHAR(64) PRIMARY KEY,"
"  tenant_id VARCHAR(64),"
"  key VARCHAR(80) NOT NULL,"
"  value JSONB,"
"  updated_at BIGINT NOT NULL"
");"

"CREATE TABLE IF NOT EXISTS retention ("
"  id VARCHAR(64) PRIMARY KEY,"
"  collection VARCHAR(80) NOT NULL,"
"  days INTEGER DEFAULT 365,"
"  updated_at BIGINT NOT NULL"
");";

static void db_seed_bootstrap(PGconn *conn) {
    if (!conn) return;
    PGresult *cnt = PQexec(conn, "SELECT COUNT(*) FROM users");
    int empty = 0;
    if (cnt && PQresultStatus(cnt) == PGRES_TUPLES_OK && PQntuples(cnt) > 0) {
        if (atoi(PQgetvalue(cnt, 0, 0)) == 0) empty = 1;
    }
    if (cnt) PQclear(cnt);
    if (!empty) return;

    /* Create initial tenant */
    PGresult *t_res = PQexec(conn,
        "INSERT INTO tenants (id, name, code, contact_email, plan, status, created_at) "
        "VALUES ('T1', 'Primary Institution', 'T1', 'admin@examos.example', 'enterprise', 'active', 1700000000) "
        "ON CONFLICT (id) DO NOTHING");
    if (t_res) PQclear(t_res);

    /* Create bootstrap users with PBKDF2 hashed passwords and TOTP */
    struct {
        const char *id;
        const char *username;
        const char *name;
        const char *role;
        const char *tenant_id;
        const char *email;
        const char *password;
        const char *salt;
        const char *totp_secret;
    } seeds[] = {
        { "usr_root", "root", "Platform Root", "superadmin", NULL, "root@examos.example", "Exam0S!Root#2026", "s1_salt_root_001", "JBSWY3DPEHPK3PXP" },
        { "usr_ananya", "ananya", "Ananya Kumar", "ops_admin", NULL, "ananya@examos.example", "Exam0S!Ops#2026", "s2_salt_ananya_02", "JBSWY3DPEHPK3PXP" },
        { "usr_instadmin", "instadmin", "Priya Menon", "inst_admin", "T1", "priya.menon@tcsion.example", "Exam0S!Inst#2026", "s3_salt_instadmin", "JBSWY3DPEHPK3PXP" },
        { "usr_controller", "controller", "Arjun Nair", "exam_controller", "T1", "arjun.nair@tcsion.example", "Exam0S!Ctrl#2026", "s4_salt_controller", "JBSWY3DPEHPK3PXP" },
        { "usr_security", "security", "Kabir Bose", "security_engineer", "T1", "kabir.bose@tcsion.example", "Exam0S!Sec#2026", "s5_salt_security_0", "JBSWY3DPEHPK3PXP" },
        { "usr_auditor", "auditor", "Meera Rao", "auditor", NULL, "meera.rao@audit.example", "Exam0S!Audit#2026", "s6_salt_auditor_00", "JBSWY3DPEHPK3PXP" }
    };

    long now = (long)time(NULL);
    for (size_t i = 0; i < sizeof(seeds)/sizeof(seeds[0]); i++) {
        char hash[256] = {0};
        security_pbkdf2_hash(seeds[i].password, seeds[i].salt, hash, sizeof(hash));
        char now_str[32]; snprintf(now_str, sizeof(now_str), "%ld", now);

        const char *pvals[12] = {
            seeds[i].id, seeds[i].username, seeds[i].name, seeds[i].role,
            seeds[i].tenant_id, seeds[i].email, hash, seeds[i].salt,
            seeds[i].totp_secret, "active", now_str, "1"
        };
        int lens[12];
        for (int k = 0; k < 12; k++) lens[k] = pvals[k] ? (int)strlen(pvals[k]) : 0;

        PGresult *r = db_simple(conn,
            "INSERT INTO users (id, username, name, role, tenant_id, email, password_hash, salt, totp_secret, status, created_at, mfa_enabled) "
            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::bigint, $12::integer) "
            "ON CONFLICT (username) DO NOTHING",
            12, pvals, lens);
        if (r) PQclear(r);
    }

    /* Seed default candidate */
    char cand_hash[256] = {0};
    security_pbkdf2_hash("123456", "CAND-001", cand_hash, sizeof(cand_hash));
    char now_str[32]; snprintf(now_str, sizeof(now_str), "%ld", now);
    const char *cpvals[10] = {
        "cnd_001", "T1", "CAND-001", "Aarav Sharma", "aarav@examos.example",
        "EXAM-DEMO-01", "S-01", cand_hash, "registered", now_str
    };
    int clens[10];
    for (int k = 0; k < 10; k++) clens[k] = (int)strlen(cpvals[k]);
    PGresult *cr = db_simple(conn,
        "INSERT INTO candidates (id, tenant_id, roll_no, name, email, exam_id, seat, pin_hash, status, created_at) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::bigint) "
        "ON CONFLICT (id) DO NOTHING",
        10, cpvals, clens);
    if (cr) PQclear(cr);

    fprintf(stderr, "[DB] Bootstrap users and candidate seeded successfully.\n");
}

int db_create_schema(void) {
    PGconn *conn = db_acquire();
    int rc = -1;
    PGresult *res = PQexec(conn, migration_sql);
    if (res && PQresultStatus(res) == PGRES_COMMAND_OK) {
        rc = 0;
        fprintf(stderr, "[DB] Schema created/verified.\n");
        db_seed_bootstrap(conn);
    } else {
        fprintf(stderr, "[DB] Schema creation failed: %s\n",
                res ? PQresultErrorMessage(res) : PQerrorMessage(conn));
    }
    if (res) PQclear(res);
    db_release(conn, rc != 0);
    return rc;
}

int db_run_migration_file(const char *path) {
    (void)path;
    return 0;
}
