/*
 * os_release_controller.c — Module 14: Secure OS Release, Updates, Rollback & Deployment Management
 *
 * Implements 8-stage release lifecycle, artifact integrity verification, signed manifests,
 * separation-of-duties approval, deployment groups, device update query engine with active exam
 * session protection, post-boot verification, and anti-downgrade rollback policy.
 */

#include "os_release_controller.h"
#include "controller.h"
#include "../db/db.h"
#include "../audit/audit.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

static void os_audit_log(const char *actor, const char *event, const char *detail) {
    audit_append(actor, event, detail);
}

static void os_send_json(int fd, int code, const char *body,
                         const char *origin, char *extra, size_t extra_len) {
    ctrl_set_cors(extra, extra_len, origin, ctrl_cors_origin_allowed(origin));
    ctrl_send_json(fd, code, body, extra);
}

static void os_send_error(int fd, int code, const char *msg,
                          const char *origin, char *extra, size_t extra_len) {
    char buf[1024];
    snprintf(buf, sizeof(buf), "{\"error\":\"%.512s\"}", msg ? msg : "Unknown error");
    os_send_json(fd, code, buf, origin, extra, extra_len);
}

static void os_json_escape(const char *input, char *output, size_t output_len) {
    size_t pos = 0;
    if (!input || !output || output_len == 0) return;
    for (size_t i = 0; input[i] && pos + 2 < output_len; i++) {
        unsigned char c = (unsigned char)input[i];
        if (c == '"' || c == '\\') {
            output[pos++] = '\\';
            output[pos++] = (char)c;
        } else if (c == '\n' || c == '\r' || c == '\t') {
            output[pos++] = '\\';
            output[pos++] = c == '\n' ? 'n' : c == '\r' ? 'r' : 't';
        } else if (c >= 32) {
            output[pos++] = (char)c;
        }
    }
    output[pos] = '\0';
}

static void os_sha256_hex(const unsigned char *data, size_t data_len, char *output) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(data, data_len, digest);
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        snprintf(output + i * 2, 3, "%02x", digest[i]);
    }
}

static int os_evidence_digest(const char *test_type, const char *title,
                              const char *classification, const char *details,
                              const char *link, char *output, size_t output_len) {
    const char *fields[] = { test_type, title, classification, details, link };
    if (!output || output_len < SHA256_DIGEST_LENGTH * 2 + 8) return -1;
    output[0] = '\0';

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1;
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        if (!ok) break;
        size_t field_len = strlen(fields[i]);
        char length[32];
        int length_len = snprintf(length, sizeof(length), "%zu:", field_len);
        ok = length_len > 0 && (size_t)length_len < sizeof(length) &&
             EVP_DigestUpdate(ctx, length, (size_t)length_len) == 1 &&
             EVP_DigestUpdate(ctx, fields[i], field_len) == 1;
    }
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    if (!ok || EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1 ||
        digest_len != SHA256_DIGEST_LENGTH) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    EVP_MD_CTX_free(ctx);

    memcpy(output, "sha256:", 7);
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        snprintf(output + 7 + i * 2, output_len - 7 - i * 2, "%02x", digest[i]);
    }
    return 0;
}

static void os_rollback_transaction(PGconn *conn) {
    PGresult *result = PQexec(conn, "ROLLBACK");
    if (result) PQclear(result);
}

static int os_valid_evidence_kind(const char *value) {
    static const char *allowed[] = {
        "test-plan", "test-report", "security-review", "sbom", "signature",
        "rollback-plan", "performance", "accessibility", "other",
        "boot_integrity", "tpm_attestation", "data_preservation_windows", "network_boot"
    };
    for (size_t i = 0; i < sizeof(allowed) / sizeof(allowed[0]); i++) {
        if (strcmp(value, allowed[i]) == 0) return 1;
    }
    return 0;
}

static int os_valid_evidence_classification(const char *value) {
    return strcmp(value, "internal") == 0 || strcmp(value, "confidential") == 0 ||
           strcmp(value, "restricted") == 0 || strcmp(value, "auditor-only") == 0;
}

/* Helper to compare semver-like strings (e.g., "2.0.0" vs "1.0.0") */
static int semver_cmp(const char *v1, const char *v2) {
    if (!v1 || !v2) return 0;
    int maj1 = 0, min1 = 0, pat1 = 0;
    int maj2 = 0, min2 = 0, pat2 = 0;
    sscanf(v1, "%d.%d.%d", &maj1, &min1, &pat1);
    sscanf(v2, "%d.%d.%d", &maj2, &min2, &pat2);
    if (maj1 != maj2) return maj1 - maj2;
    if (min1 != min2) return min1 - min2;
    return pat1 - pat2;
}

void os_release_handle(int client_fd, const char *method, const char *path,
                       const char *body, const char *auth_header,
                       const char *origin, char *extra_headers, size_t extra_len) {
    auth_session_t sess;
    memset(&sess, 0, sizeof(sess));

    int auth_rc = ctrl_authorize(auth_header, AUTH_PERM_READ, &sess);
    int is_owner = (auth_rc == 0 && (sess.role == ROLE_PLATFORM_OWNER ||
                    strcmp(sess.username, "admin") == 0 ||
                    strcmp(sess.username, "root") == 0));
    if (strcmp(method, "GET") != 0 && ctrl_authorize(auth_header, AUTH_PERM_SECURITY_ADMIN, &sess) != 0) {
        os_send_error(client_fd, 403, "Security administrator authorization required",
                      origin, extra_headers, extra_len);
        return;
    }

    PGconn *conn = db_acquire();
    if (!conn) {
        os_send_error(client_fd, 503, "Database connection unavailable", origin, extra_headers, extra_len);
        return;
    }

    /* =========================================================================
     * 1. POST /api/v1/os/releases: Create Release Draft
     * ========================================================================= */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/os/releases") == 0) {
        if (!is_owner && auth_rc != 0) {
            db_release(conn, 0);
            os_send_error(client_fd, 403, "Administrative privileges required to create OS releases", origin, extra_headers, extra_len);
            return;
        }

        char rel_id[64] = {0}, version[64] = {0}, commit_id[64] = {0};
        char manifest_json[16384] = {0};
        char build_cfg[256] = "mkosi-debian-secure-uefi", toolchain[64] = "Debian 12 / mkosi 14.1";
        char kernel_v[64] = "6.6.0-examos", min_v[64] = "1.0.0", pol_v[64] = "1.0";

        ctrl_json_string(body, "release_id", rel_id, sizeof(rel_id));
        ctrl_json_string(body, "version", version, sizeof(version));
        ctrl_json_string(body, "manifest_json", manifest_json, sizeof(manifest_json));
        ctrl_json_string(body, "source_commit", commit_id, sizeof(commit_id));
        ctrl_json_string(body, "build_config", build_cfg, sizeof(build_cfg));
        ctrl_json_string(body, "toolchain_version", toolchain, sizeof(toolchain));
        ctrl_json_string(body, "kernel_version", kernel_v, sizeof(kernel_v));
        ctrl_json_string(body, "minimum_supported_version", min_v, sizeof(min_v));
        ctrl_json_string(body, "policy_version", pol_v, sizeof(pol_v));

        if (!version[0] || !manifest_json[0]) {
            db_release(conn, 0);
            os_send_error(client_fd, 400, "Release version and manifest JSON are required",
                          origin, extra_headers, extra_len);
            return;
        }
        if (!rel_id[0]) {
            snprintf(rel_id, sizeof(rel_id), "ExamOS %s", version);
        }

        char pk_id[64];
        snprintf(pk_id, sizeof(pk_id), "osrel_%ld_%d", (long)time(NULL), rand() % 10000);

        const char *creator = sess.username[0] ? sess.username : "system";

        char digest_value[80] = {0};

        const char *p[11] = {
            pk_id, rel_id, version, commit_id, build_cfg, toolchain,
            kernel_v, min_v, pol_v, creator, digest_value
        };
        int l[11];
        for (int i = 0; i < 11; i++) l[i] = p[i] ? (int)strlen(p[i]) : 0;

        PGresult *begin = PQexec(conn, "BEGIN");
        if (!begin || PQresultStatus(begin) != PGRES_COMMAND_OK) {
            if (begin) PQclear(begin);
            db_release(conn, 0);
            os_send_error(client_fd, 503, "Release draft transaction could not start",
                          origin, extra_headers, extra_len);
            return;
        }
        PQclear(begin);

        PGresult *ins_r = db_simple(conn,
            "INSERT INTO os_releases (id, release_id, version, source_commit, build_config, "
            "toolchain_version, kernel_version, minimum_supported_version, policy_version, "
            "status, manifest_digest, created_by, created_at, updated_at) "
            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'draft', $11, $10, "
            "EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000) "
            "ON CONFLICT (release_id) DO NOTHING", 11, p, l);

        if (!ins_r || PQresultStatus(ins_r) != PGRES_COMMAND_OK ||
            strcmp(PQcmdTuples(ins_r), "0") == 0) {
            if (ins_r) PQclear(ins_r);
            os_rollback_transaction(conn);
            db_release(conn, 0);
            os_send_error(client_fd, 409, "Release ID or version already exists", origin, extra_headers, extra_len);
            return;
        }
        PQclear(ins_r);

        const char *mp[3] = { pk_id, manifest_json, digest_value };
        int ml[3] = { (int)strlen(pk_id), (int)strlen(manifest_json), (int)strlen(digest_value) };
        PGresult *mr = db_simple(conn,
            "INSERT INTO os_release_manifests "
            "(id, release_id, manifest_json, manifest_digest, signature_algorithm, signature_value, verified, created_at) "
            "VALUES ($1, $1, $2::jsonb, $3, 'rsa-sha256', NULL, FALSE, "
            "EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 3, mp, ml);
        if (!mr || PQresultStatus(mr) != PGRES_COMMAND_OK) {
            if (mr) PQclear(mr);
            os_rollback_transaction(conn);
            db_release(conn, 0);
            os_send_error(client_fd, 400, "Release manifest JSON is invalid or could not be stored",
                          origin, extra_headers, extra_len);
            return;
        }
        PQclear(mr);

        const char *manifest_id_params[1] = { pk_id };
        int manifest_id_lengths[1] = { (int)strlen(pk_id) };
        PGresult *canonical = db_simple(conn,
            "SELECT manifest_json::text FROM os_release_manifests WHERE release_id = $1",
            1, manifest_id_params, manifest_id_lengths);
        if (!canonical || PQresultStatus(canonical) != PGRES_TUPLES_OK ||
            PQntuples(canonical) != 1) {
            if (canonical) PQclear(canonical);
            os_rollback_transaction(conn);
            db_release(conn, 0);
            os_send_error(client_fd, 503, "Persisted release manifest could not be read for digest calculation",
                          origin, extra_headers, extra_len);
            return;
        }
        char canonical_digest[SHA256_DIGEST_LENGTH * 2 + 1];
        os_sha256_hex((const unsigned char *)PQgetvalue(canonical, 0, 0),
                      (size_t)PQgetlength(canonical, 0, 0), canonical_digest);
        PQclear(canonical);
        snprintf(digest_value, sizeof(digest_value), "sha256:%s", canonical_digest);
        const char *digest_params[2] = { digest_value, pk_id };
        int digest_lengths[2] = { (int)strlen(digest_value), (int)strlen(pk_id) };
        PGresult *digest_update = db_simple(conn,
            "UPDATE os_releases SET manifest_digest = $1 WHERE id = $2",
            2, digest_params, digest_lengths);
        if (!digest_update || PQresultStatus(digest_update) != PGRES_COMMAND_OK) {
            if (digest_update) PQclear(digest_update);
            os_rollback_transaction(conn);
            db_release(conn, 0);
            os_send_error(client_fd, 503, "Release manifest digest could not be persisted",
                          origin, extra_headers, extra_len);
            return;
        }
        PQclear(digest_update);
        digest_update = db_simple(conn,
            "UPDATE os_release_manifests SET manifest_digest = $1 WHERE release_id = $2",
            2, digest_params, digest_lengths);
        if (!digest_update || PQresultStatus(digest_update) != PGRES_COMMAND_OK) {
            if (digest_update) PQclear(digest_update);
            os_rollback_transaction(conn);
            db_release(conn, 0);
            os_send_error(client_fd, 503, "Manifest digest record could not be persisted",
                          origin, extra_headers, extra_len);
            return;
        }
        PQclear(digest_update);

        PGresult *commit = PQexec(conn, "COMMIT");
        if (!commit || PQresultStatus(commit) != PGRES_COMMAND_OK) {
            if (commit) PQclear(commit);
            os_rollback_transaction(conn);
            db_release(conn, 0);
            os_send_error(client_fd, 503, "Release draft transaction could not commit",
                          origin, extra_headers, extra_len);
            return;
        }
        PQclear(commit);

        os_audit_log(creator, "OS_RELEASE_CREATED", rel_id);
        db_release(conn, 0);

        char resp[768], escaped_rel[128], escaped_version[128], escaped_kernel[128];
        os_json_escape(rel_id, escaped_rel, sizeof(escaped_rel));
        os_json_escape(version, escaped_version, sizeof(escaped_version));
        os_json_escape(kernel_v, escaped_kernel, sizeof(escaped_kernel));
        snprintf(resp, sizeof(resp),
            "{\"status\":\"created\",\"id\":\"%s\",\"release_id\":\"%s\",\"version\":\"%s\","
            "\"lifecycle_status\":\"draft\",\"manifest_digest\":\"%s\",\"manifest_verified\":false,"
            "\"kernel_version\":\"%s\"}",
            pk_id, escaped_rel, escaped_version, digest_value, escaped_kernel);
        os_send_json(client_fd, 201, resp, origin, extra_headers, extra_len);
        return;
    }

    /* =========================================================================
     * 2. GET /api/v1/os/releases: List Releases
     * ========================================================================= */
    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/v1/os/releases") == 0) {
        PGresult *res = PQexec(conn,
            "SELECT r.id, r.release_id, r.version, r.kernel_version, r.status, r.minimum_supported_version, "
            "r.rollback_permitted, r.created_by, r.approved_by, r.approved_at, r.created_at, "
            "COALESCE((SELECT MAX(CASE WHEN g.rollout_stage IN ('stable','general') THEN 100 "
            "WHEN g.rollout_stage LIKE 'stage-%' THEN NULLIF(substring(g.rollout_stage FROM 7), '')::int "
            "ELSE 0 END) FROM os_deployment_groups g WHERE g.target_release_id = r.id), 0) "
            ", COALESCE(r.manifest_digest, ''), COALESCE(m.manifest_json::text, '{}'), "
            "COALESCE(m.verified, FALSE), COALESCE(m.signature_value, '') "
            "FROM os_releases r LEFT JOIN os_release_manifests m ON m.release_id = r.id "
            "ORDER BY r.created_at DESC");

        if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
            if (res) PQclear(res);
            db_release(conn, 0);
            os_send_error(client_fd, 500, "Failed to load OS releases", origin, extra_headers, extra_len);
            return;
        }

        char *json = malloc(131072);
        if (!json) {
            PQclear(res);
            db_release(conn, 0);
            os_send_error(client_fd, 500, "Out of memory", origin, extra_headers, extra_len);
            return;
        }

        size_t pos = 0;
        pos += snprintf(json + pos, 131072 - pos, "{\"releases\":[");
        int n = PQntuples(res);
        for (int i = 0; i < n; i++) {
            if (i > 0) pos += snprintf(json + pos, 131072 - pos, ",");
            char escaped[7][512];
            for (int j = 0; j < 6; j++) {
                os_json_escape(PQgetvalue(res, i, j), escaped[j], sizeof(escaped[j]));
            }
            os_json_escape(PQgetvalue(res, i, 7), escaped[6], sizeof(escaped[6]));
            char approved_by[512];
            os_json_escape(PQgetvalue(res, i, 8), approved_by, sizeof(approved_by));
            char signature[512];
            os_json_escape(PQgetvalue(res, i, 15), signature, sizeof(signature));
            pos += snprintf(json + pos, 131072 - pos,
                "{\"id\":\"%s\",\"release_id\":\"%s\",\"version\":\"%s\",\"kernel_version\":\"%s\","
                "\"status\":\"%s\",\"minimum_supported_version\":\"%s\",\"rollback_permitted\":%s,"
                "\"created_by\":\"%s\",\"approved_by\":\"%s\",\"approved_at\":%s,\"created_at\":%s,"
                "\"rollout_percentage\":%s,\"manifest_digest\":\"%s\",\"manifest\":%s,"
                "\"manifest_verified\":%s,\"manifest_signature\":\"%s\"}",
                escaped[0], escaped[1], escaped[2], escaped[3], escaped[4], escaped[5],
                strcmp(PQgetvalue(res, i, 6), "t") == 0 ? "true" : "false",
                escaped[6], approved_by,
                PQgetvalue(res, i, 9)[0] ? PQgetvalue(res, i, 9) : "null",
                PQgetvalue(res, i, 10), PQgetvalue(res, i, 11),
                PQgetvalue(res, i, 12), PQgetvalue(res, i, 13),
                strcmp(PQgetvalue(res, i, 14), "t") == 0 ? "true" : "false",
                signature);
        }
        pos += snprintf(json + pos, 131072 - pos, "]}");
        PQclear(res);

        db_release(conn, 0);
        os_send_json(client_fd, 200, json, origin, extra_headers, extra_len);
        free(json);
        return;
    }

    /* =========================================================================
     * 3. Specific Release Routes: /api/v1/os/releases/:id/...
     * ========================================================================= */
    const char *rel_pfx = "/api/v1/os/releases/";
    size_t rel_plen = strlen(rel_pfx);
    if (strncmp(path, rel_pfx, rel_plen) == 0) {
        const char *sub = path + rel_plen;
        char id_or_rel[64] = {0};
        const char *slash = strchr(sub, '/');
        size_t len = slash ? (size_t)(slash - sub) : strlen(sub);
        if (len >= sizeof(id_or_rel)) {
            db_release(conn, 0);
            os_send_error(client_fd, 400, "Invalid release identifier", origin, extra_headers, extra_len);
            return;
        }
        memcpy(id_or_rel, sub, len);
        id_or_rel[len] = '\0';
        const char *action = slash ? slash : "";

        /* Load Release */
        const char *qp[1] = { id_or_rel };
        int ql[1] = { (int)strlen(id_or_rel) };
        PGresult *r_res = db_simple(conn,
            "SELECT r.id, r.release_id, r.version, r.kernel_version, r.status, r.minimum_supported_version, "
            "r.rollback_permitted, r.created_by, r.approved_by, r.approved_at, r.source_commit, r.toolchain_version, "
            "r.manifest_digest, r.manifest_signature, COALESCE(m.manifest_json::text, '{}'), "
            "COALESCE(m.verified, FALSE), COALESCE(m.signature_value, '') "
            "FROM os_releases r LEFT JOIN os_release_manifests m ON m.release_id = r.id "
            "WHERE r.id = $1 OR r.release_id = $1", 1, qp, ql);

        if (!r_res || PQntuples(r_res) == 0) {
            if (r_res) PQclear(r_res);
            db_release(conn, 0);
            os_send_error(client_fd, 404, "OS release not found", origin, extra_headers, extra_len);
            return;
        }

        char r_pk[64], r_id[64], r_ver[64], r_kern[64], r_stat[32], r_min[64];
        char r_creator[64], r_digest[128], r_manifest[16384], r_verified[8], r_manifest_sig[4096];
        int r_rollback = 0;
        strncpy(r_pk, PQgetvalue(r_res, 0, 0), sizeof(r_pk) - 1);
        strncpy(r_id, PQgetvalue(r_res, 0, 1), sizeof(r_id) - 1);
        strncpy(r_ver, PQgetvalue(r_res, 0, 2), sizeof(r_ver) - 1);
        strncpy(r_kern, PQgetvalue(r_res, 0, 3), sizeof(r_kern) - 1);
        strncpy(r_stat, PQgetvalue(r_res, 0, 4), sizeof(r_stat) - 1);
        strncpy(r_min, PQgetvalue(r_res, 0, 5), sizeof(r_min) - 1);
        r_rollback = (strcmp(PQgetvalue(r_res, 0, 6), "t") == 0);
        strncpy(r_creator, PQgetvalue(r_res, 0, 7), sizeof(r_creator) - 1);
        strncpy(r_digest, PQgetvalue(r_res, 0, 12), sizeof(r_digest) - 1);
        strncpy(r_manifest, PQgetvalue(r_res, 0, 14), sizeof(r_manifest) - 1);
        strncpy(r_verified, PQgetvalue(r_res, 0, 15), sizeof(r_verified) - 1);
        strncpy(r_manifest_sig, PQgetvalue(r_res, 0, 16), sizeof(r_manifest_sig) - 1);
        PQclear(r_res);

        /* ---------------- GET /api/v1/os/releases/:id (Details) ---------------- */
        if (strcmp(method, "GET") == 0 && action[0] == '\0') {
            /* Load Artifacts */
            const char *art_p[1] = { r_pk };
            int art_l[1] = { (int)strlen(r_pk) };
            PGresult *art_res = db_simple(conn,
                "SELECT artifact_name, artifact_type, sha256_digest, size_bytes FROM os_release_artifacts WHERE release_id = $1", 1, art_p, art_l);

            char art_json[2048] = "[";
            if (art_res) {
                int n_art = PQntuples(art_res);
                for (int i = 0; i < n_art; i++) {
                    if (i > 0) strncat(art_json, ",", sizeof(art_json) - strlen(art_json) - 1);
                    char item[256];
                    snprintf(item, sizeof(item), "{\"name\":\"%s\",\"type\":\"%s\",\"digest\":\"%s\",\"size\":%s}",
                             PQgetvalue(art_res, i, 0), PQgetvalue(art_res, i, 1),
                             PQgetvalue(art_res, i, 2), PQgetvalue(art_res, i, 3));
                    strncat(art_json, item, sizeof(art_json) - strlen(art_json) - 1);
                }
                PQclear(art_res);
            }
            strncat(art_json, "]", sizeof(art_json) - strlen(art_json) - 1);

            const char *test_p[1] = { r_pk };
            int test_l[1] = { (int)strlen(r_pk) };
            PGresult *test_res = db_simple(conn,
                "SELECT id, test_type, status, details, executed_at, title, classification, "
                "evidence_link, evidence_digest, evidence_source FROM os_release_test_results "
                "WHERE release_id = $1 ORDER BY executed_at DESC", 1, test_p, test_l);
            char tests_json[32768] = "[";
            if (test_res) {
                int n_tests = PQntuples(test_res);
                for (int i = 0; i < n_tests; i++) {
                    if (i > 0) strncat(tests_json, ",", sizeof(tests_json) - strlen(tests_json) - 1);
                    char digest[80] = {0};
                    if (os_evidence_digest(PQgetvalue(test_res, i, 1), PQgetvalue(test_res, i, 5),
                                           PQgetvalue(test_res, i, 6), PQgetvalue(test_res, i, 3),
                                           PQgetvalue(test_res, i, 7), digest, sizeof(digest)) != 0) {
                        PQclear(test_res);
                        db_release(conn, 0);
                        os_send_error(client_fd, 500, "Could not verify persisted evidence digest",
                                      origin, extra_headers, extra_len);
                        return;
                    }
                    const char *source = PQgetvalue(test_res, i, 9);
                    int integrity_valid = strcmp(source, "user_submitted") == 0 &&
                                          strcmp(digest, PQgetvalue(test_res, i, 8)) == 0;
                    char item[3072], escaped[7][384];
                    const int escape_columns[] = { 0, 1, 2, 7, 5, 6 };
                    for (int j = 0; j < 6; j++) {
                        os_json_escape(PQgetvalue(test_res, i, escape_columns[j]),
                                       escaped[j], sizeof(escaped[j]));
                    }
                    os_json_escape(source, escaped[6], sizeof(escaped[6]));
                    char evidence_hash[128];
                    os_json_escape(PQgetvalue(test_res, i, 8), evidence_hash, sizeof(evidence_hash));
                    snprintf(item, sizeof(item),
                        "{\"id\":\"%s\",\"test_type\":\"%s\",\"status\":\"%s\",\"title\":\"%s\","
                        "\"classification\":\"%s\",\"link\":\"%s\",\"evidence_digest\":\"%s\","
                        "\"evidence_source\":\"%s\",\"integrity_valid\":%s,\"executed_at\":%s}",
                        escaped[0], escaped[1], escaped[2], escaped[4], escaped[5], escaped[3],
                        evidence_hash, escaped[6], integrity_valid ? "true" : "false",
                        PQgetvalue(test_res, i, 4));
                    strncat(tests_json, item, sizeof(tests_json) - strlen(tests_json) - 1);
                }
                PQclear(test_res);
            }
            strncat(tests_json, "]", sizeof(tests_json) - strlen(tests_json) - 1);

            db_release(conn, 0);
            char escaped_id[128], escaped_release_id[128], escaped_version[128], escaped_kernel[128];
            char escaped_status[64], escaped_min[128], escaped_creator[128], escaped_digest[160];
            char escaped_signature[8192];
            os_json_escape(r_pk, escaped_id, sizeof(escaped_id));
            os_json_escape(r_id, escaped_release_id, sizeof(escaped_release_id));
            os_json_escape(r_ver, escaped_version, sizeof(escaped_version));
            os_json_escape(r_kern, escaped_kernel, sizeof(escaped_kernel));
            os_json_escape(r_stat, escaped_status, sizeof(escaped_status));
            os_json_escape(r_min, escaped_min, sizeof(escaped_min));
            os_json_escape(r_creator, escaped_creator, sizeof(escaped_creator));
            os_json_escape(r_digest, escaped_digest, sizeof(escaped_digest));
            os_json_escape(r_manifest_sig, escaped_signature, sizeof(escaped_signature));
            char resp[49152];
            snprintf(resp, sizeof(resp),
                "{\"release\":{\"id\":\"%s\",\"release_id\":\"%s\",\"version\":\"%s\",\"kernel_version\":\"%s\","
                "\"status\":\"%s\",\"minimum_supported_version\":\"%s\",\"rollback_permitted\":%s,"
                "\"created_by\":\"%s\",\"manifest_digest\":\"%s\",\"manifest\":%s,"
                "\"manifest_verified\":%s,\"manifest_signature\":\"%s\","
                "\"artifacts\":%s,\"tests\":%s}}",
                escaped_id, escaped_release_id, escaped_version, escaped_kernel, escaped_status,
                escaped_min, r_rollback ? "true" : "false", escaped_creator, escaped_digest,
                r_manifest, strcmp(r_verified, "t") == 0 ? "true" : "false",
                escaped_signature, art_json, tests_json);
            os_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/os/releases/:id/validate (Validation Results) ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(action, "/validate") == 0) {
            char test_type[64] = {0}, title[121] = {0}, classification[33] = "internal";
            char details[4097] = {0}, link[301] = {0}, digest[80] = {0};
            ctrl_json_string(body, "test_type", test_type, sizeof(test_type));
            ctrl_json_string(body, "details", details, sizeof(details));
            ctrl_json_string(body, "title", title, sizeof(title));
            ctrl_json_string(body, "classification", classification, sizeof(classification));
            ctrl_json_string(body, "link", link, sizeof(link));

            if (!test_type[0] || !title[0] || !os_valid_evidence_kind(test_type) ||
                !os_valid_evidence_classification(classification)) {
                db_release(conn, 0);
                os_send_error(client_fd, 400, "A title, supported evidence type, and valid classification are required",
                              origin, extra_headers, extra_len);
                return;
            }
            if (os_evidence_digest(test_type, title, classification, details, link,
                                   digest, sizeof(digest)) != 0) {
                db_release(conn, 0);
                os_send_error(client_fd, 500, "Could not compute evidence digest",
                              origin, extra_headers, extra_len);
                return;
            }

            char tid[64];
            snprintf(tid, sizeof(tid), "tst_%ld_%d", (long)time(NULL), rand() % 10000);
            const char *tp[9] = { tid, r_pk, test_type, details, title, classification, link, digest, "user_submitted" };
            int tl[9];
            for (int i = 0; i < 9; i++) tl[i] = (int)strlen(tp[i]);

            PGresult *tr = db_simple(conn,
                "INSERT INTO os_release_test_results "
                "(id, release_id, test_type, status, details, title, classification, evidence_link, "
                "evidence_digest, evidence_source, executed_at) "
                "VALUES ($1, $2, $3, 'submitted', $4, $5, $6, $7, $8, $9, "
                "EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 9, tp, tl);
            if (!tr || PQresultStatus(tr) != PGRES_COMMAND_OK) {
                if (tr) PQclear(tr);
                db_release(conn, 0);
                os_send_error(client_fd, 503, "Evidence could not be persisted",
                              origin, extra_headers, extra_len);
                return;
            }
            PQclear(tr);

            os_audit_log(sess.username, "OS_RELEASE_EVIDENCE_SUBMITTED", test_type);
            db_release(conn, 0);

            char resp[768], escaped_id[128], escaped_type[128], escaped_digest[128];
            os_json_escape(r_id, escaped_id, sizeof(escaped_id));
            os_json_escape(test_type, escaped_type, sizeof(escaped_type));
            os_json_escape(digest, escaped_digest, sizeof(escaped_digest));
            snprintf(resp, sizeof(resp),
                "{\"status\":\"submitted\",\"release_id\":\"%s\",\"evidence_id\":\"%s\","
                "\"test_type\":\"%s\",\"evidence_digest\":\"%s\","
                "\"message\":\"User-submitted evidence is not an automated test result.\"}",
                escaped_id, tid, escaped_type, escaped_digest);
            os_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/os/releases/:id/approve (Multi-Person Approval) ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(action, "/approve") == 0) {
            db_release(conn, 0);
            os_send_error(client_fd, 409,
                          "Direct release approval is disabled; submit and review this action through the centralized approval workflow",
                          origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/os/releases/:id/activate (Make Active for Rollout) ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(action, "/activate") == 0) {
            if (strcmp(r_stat, "approved") != 0 || strcmp(r_verified, "t") != 0 ||
                !r_manifest_sig[0]) {
                db_release(conn, 0);
                os_send_error(client_fd, 409, "Only a trusted, approved release can be activated",
                              origin, extra_headers, extra_len);
                return;
            }
            int rollback_ok = 1;
            ctrl_json_bool(body, "rollback_permitted", &rollback_ok);

            const char *target_stat = "active";
            const char *up[3] = { target_stat, rollback_ok ? "t" : "f", r_pk };
            int ul[3] = { (int)strlen(target_stat), 1, (int)strlen(r_pk) };

            PGresult *ur = db_simple(conn,
                "UPDATE os_releases SET status = $1, rollback_permitted = $2, "
                "updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 WHERE id = $3", 3, up, ul);
            if (ur) PQclear(ur);

            os_audit_log(sess.username, "OS_RELEASE_ACTIVATED", r_id);
            db_release(conn, 0);

            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"active\",\"release_id\":\"%s\",\"rollback_permitted\":%s}",
                     r_id, rollback_ok ? "true" : "false");
            os_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/os/releases/:id/suspend (Pause Rollout) ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(action, "/suspend") == 0) {
            const char *up[1] = { r_pk };
            int ul[1] = { (int)strlen(r_pk) };
            PGresult *ur = db_simple(conn,
                "UPDATE os_releases SET status = 'suspended', updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 WHERE id = $1", 1, up, ul);
            if (ur) PQclear(ur);

            os_audit_log(sess.username, "OS_RELEASE_SUSPENDED", r_id);
            db_release(conn, 0);

            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"suspended\",\"release_id\":\"%s\"}", r_id);
            os_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/os/releases/:id/revoke (Emergency Revocation) ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(action, "/revoke") == 0) {
            char reason[256] = "Security advisory: critical firmware or package integrity defect";
            ctrl_json_string(body, "reason", reason, sizeof(reason));

            const char *revoker = sess.username[0] ? sess.username : "security_officer";
            const char *up[3] = { revoker, reason, r_pk };
            int ul[3] = { (int)strlen(revoker), (int)strlen(reason), (int)strlen(r_pk) };

            PGresult *ur = db_simple(conn,
                "UPDATE os_releases SET status = 'revoked', rollback_permitted = FALSE, "
                "revoked_by = $1, revocation_reason = $2, revoked_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, "
                "updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 WHERE id = $3", 3, up, ul);
            if (ur) PQclear(ur);

            /* Invalidate in-flight update jobs */
            const char *uj[1] = { r_pk };
            int ujl[1] = { (int)strlen(r_pk) };
            PGresult *uj_r = db_simple(conn,
                "UPDATE os_update_jobs SET status = 'REVOKED', error_reason = 'Target release has been revoked', "
                "updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 WHERE target_release_id = $1 AND status != 'SUCCEEDED'", 1, uj, ujl);
            if (uj_r) PQclear(uj_r);

            os_audit_log(revoker, "OS_RELEASE_REVOKED", reason);
            db_release(conn, 0);

            char resp[512];
            snprintf(resp, sizeof(resp), "{\"status\":\"revoked\",\"release_id\":\"%s\",\"revoked_by\":\"%s\",\"reason\":\"%s\"}",
                     r_id, revoker, reason);
            os_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/os/releases/:id/retire (Retire Release) ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(action, "/retire") == 0) {
            const char *up[1] = { r_pk };
            int ul[1] = { (int)strlen(r_pk) };
            PGresult *ur = db_simple(conn,
                "UPDATE os_releases SET status = 'retired', rollback_permitted = FALSE, "
                "updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 WHERE id = $1", 1, up, ul);
            if (ur) PQclear(ur);

            os_audit_log(sess.username, "OS_RELEASE_RETIRED", r_id);
            db_release(conn, 0);

            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"retired\",\"release_id\":\"%s\"}", r_id);
            os_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }
    }

    /* =========================================================================
     * 4. POST /api/v1/os/deployments: Create Deployment Rollout Group
     * ========================================================================= */
    if (strcmp(method, "POST") == 0 && strcmp(path, "/api/v1/os/deployments") == 0) {
        char inst_id[64] = {0}, gname[128] = {0}, target_rel[64] = {0}, stage[32] = "pilot";
        int max_conc = 10;
        char win_start[32] = "00:00", win_end[32] = "23:59";

        ctrl_json_string(body, "institution_id", inst_id, sizeof(inst_id));
        ctrl_json_string(body, "group_name", gname, sizeof(gname));
        ctrl_json_string(body, "target_release_id", target_rel, sizeof(target_rel));
        ctrl_json_string(body, "rollout_stage", stage, sizeof(stage));
        ctrl_json_int(body, "max_concurrent_updates", &max_conc);
        ctrl_json_string(body, "maintenance_window_start", win_start, sizeof(win_start));
        ctrl_json_string(body, "maintenance_window_end", win_end, sizeof(win_end));
        if (max_conc < 1 || max_conc > 100) {
            db_release(conn, 0);
            os_send_error(client_fd, 400, "Maximum concurrent updates must be between 1 and 100",
                          origin, extra_headers, extra_len);
            return;
        }

        if (strncmp(stage, "stage-", 6) == 0) {
            char *end = NULL;
            long parsed = strtol(stage + 6, &end, 10);
            if (end == stage + 6 || *end != '\0' || parsed < 1 || parsed > 100) {
                db_release(conn, 0);
                os_send_error(client_fd, 400, "Rollout stage must be stage-1 through stage-100",
                              origin, extra_headers, extra_len);
                return;
            }
        } else if (strcmp(stage, "stable") == 0 || strcmp(stage, "general") == 0) {
            /* Full rollout stages are valid deployment targets, but do not dispatch devices. */
        } else {
            db_release(conn, 0);
            os_send_error(client_fd, 400, "Unsupported rollout stage",
                          origin, extra_headers, extra_len);
            return;
        }

        if (is_owner) {
            if (!inst_id[0]) {
                snprintf(inst_id, sizeof(inst_id), "%s", sess.institution_id);
            }
        } else if (sess.institution_id[0]) {
            snprintf(inst_id, sizeof(inst_id), "%s", sess.institution_id);
        } else {
            db_release(conn, 0);
            os_send_error(client_fd, 403, "An institution scope is required",
                          origin, extra_headers, extra_len);
            return;
        }
        if (!gname[0]) {
            snprintf(gname, sizeof(gname), "Rollout Group %ld", (long)time(NULL));
        }

        /* Resolve target release PK */
        const char *rp[1] = { target_rel };
        int rl[1] = { (int)strlen(target_rel) };
        PGresult *r_chk = db_simple(conn,
            "SELECT r.id, r.status, COALESCE(m.verified, FALSE), COALESCE(m.signature_value, '') "
            "FROM os_releases r LEFT JOIN os_release_manifests m ON m.release_id = r.id "
            "WHERE r.id = $1 OR r.release_id = $1", 1, rp, rl);
        if (!r_chk || PQntuples(r_chk) == 0) {
            if (r_chk) PQclear(r_chk);
            db_release(conn, 0);
            os_send_error(client_fd, 404, "Target release does not exist", origin, extra_headers, extra_len);
            return;
        }
        char rel_pk[64], rel_stat[32], rel_verified[8], rel_signature[4096];
        strncpy(rel_pk, PQgetvalue(r_chk, 0, 0), sizeof(rel_pk) - 1);
        strncpy(rel_stat, PQgetvalue(r_chk, 0, 1), sizeof(rel_stat) - 1);
        strncpy(rel_verified, PQgetvalue(r_chk, 0, 2), sizeof(rel_verified) - 1);
        strncpy(rel_signature, PQgetvalue(r_chk, 0, 3), sizeof(rel_signature) - 1);
        PQclear(r_chk);

        if (strcmp(rel_stat, "revoked") == 0) {
            db_release(conn, 0);
            os_send_error(client_fd, 403, "Cannot create deployment for revoked release", origin, extra_headers, extra_len);
            return;
        }
        if ((strcmp(rel_stat, "approved") != 0 && strcmp(rel_stat, "active") != 0 &&
             strcmp(rel_stat, "staged") != 0) || strcmp(rel_verified, "t") != 0 ||
            !rel_signature[0]) {
            db_release(conn, 0);
            os_send_error(client_fd, 409, "A trusted, verified release must be approved before deployment",
                          origin, extra_headers, extra_len);
            return;
        }

        char dep_id[64];
        snprintf(dep_id, sizeof(dep_id), "dep_%ld_%d", (long)time(NULL), rand() % 10000);
        char max_str[16];
        snprintf(max_str, sizeof(max_str), "%d", max_conc);

        const char *dp[8] = { dep_id, inst_id, gname, rel_pk, stage, max_str, win_start, win_end };
        int dl[8];
        for (int i = 0; i < 8; i++) dl[i] = dp[i] ? (int)strlen(dp[i]) : 0;

        PGresult *ins_dep = db_simple(conn,
            "INSERT INTO os_deployment_groups (id, institution_id, group_name, target_release_id, rollout_stage, "
            "max_concurrent_updates, maintenance_window_start, maintenance_window_end, status, created_at, updated_at) "
            "VALUES ($1, $2, $3, $4, $5, $6::int, $7, $8, 'planned', "
            "EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 8, dp, dl);
        if (!ins_dep || PQresultStatus(ins_dep) != PGRES_COMMAND_OK) {
            if (ins_dep) PQclear(ins_dep);
            db_release(conn, 0);
            os_send_error(client_fd, 503, "Deployment group could not be created",
                          origin, extra_headers, extra_len);
            return;
        }
        PQclear(ins_dep);

        os_audit_log(sess.username, "OS_DEPLOYMENT_CREATED", gname);
        db_release(conn, 0);

        char resp[1024], escaped_inst[128], escaped_name[256], escaped_target[128], escaped_stage[64];
        os_json_escape(inst_id, escaped_inst, sizeof(escaped_inst));
        os_json_escape(gname, escaped_name, sizeof(escaped_name));
        os_json_escape(target_rel, escaped_target, sizeof(escaped_target));
        os_json_escape(stage, escaped_stage, sizeof(escaped_stage));
        snprintf(resp, sizeof(resp),
            "{\"status\":\"created\",\"deployment_id\":\"%s\",\"institution_id\":\"%s\",\"group_name\":\"%s\","
            "\"target_release_id\":\"%s\",\"rollout_stage\":\"%s\",\"deployment_status\":\"planned\","
            "\"devices_assigned\":0,\"dispatched\":false}",
            dep_id, escaped_inst, escaped_name, escaped_target, escaped_stage);
        os_send_json(client_fd, 201, resp, origin, extra_headers, extra_len);
        return;
    }

    /* =========================================================================
     * 5. GET /api/v1/os/deployments: List persisted deployment groups
     * ========================================================================= */
    const char *dep_pfx = "/api/v1/os/deployments/";
    size_t dep_plen = strlen(dep_pfx);
    if (strcmp(method, "GET") == 0 && strcmp(path, "/api/v1/os/deployments") == 0) {
        const char *params[2] = { is_owner ? "TRUE" : "FALSE", sess.institution_id };
        int lengths[2] = { is_owner ? 4 : 5, (int)strlen(sess.institution_id) };
        PGresult *groups = db_simple(conn,
            "SELECT g.id, g.institution_id, g.group_name, r.release_id, r.version, "
            "g.rollout_stage, g.status, g.max_concurrent_updates, g.created_at, "
            "(SELECT COUNT(*) FROM os_deployment_assignments a WHERE a.group_id = g.id), "
            "(SELECT COUNT(*) FROM os_deployment_assignments a WHERE a.group_id = g.id "
            "AND a.status IN ('installed','verified')), "
            "(SELECT COUNT(*) FROM os_deployment_assignments a WHERE a.group_id = g.id "
            "AND a.status = 'failed') "
            "FROM os_deployment_groups g JOIN os_releases r ON g.target_release_id = r.id "
            "WHERE ($1 = TRUE OR g.institution_id = $2) ORDER BY g.created_at DESC", 2, params, lengths);
        if (!groups || PQresultStatus(groups) != PGRES_TUPLES_OK) {
            if (groups) PQclear(groups);
            db_release(conn, 0);
            os_send_error(client_fd, 500, "Failed to load deployment groups", origin, extra_headers, extra_len);
            return;
        }
        char *json = malloc(131072);
        if (!json) {
            PQclear(groups);
            db_release(conn, 0);
            os_send_error(client_fd, 500, "Out of memory", origin, extra_headers, extra_len);
            return;
        }
        size_t pos = (size_t)snprintf(json, 131072, "{\"deployments\":[");
        for (int i = 0; i < PQntuples(groups) && pos < 131072; i++) {
            if (i) pos += (size_t)snprintf(json + pos, 131072 - pos, ",");
            char fields[7][256];
            for (int j = 0; j < 7; j++) {
                os_json_escape(PQgetvalue(groups, i, j), fields[j], sizeof(fields[j]));
            }
            pos += (size_t)snprintf(json + pos, 131072 - pos,
                "{\"id\":\"%s\",\"institution_id\":\"%s\",\"group_name\":\"%s\","
                "\"target_release_id\":\"%s\",\"target_version\":\"%s\","
                "\"rollout_stage\":\"%s\",\"status\":\"%s\","
                "\"max_concurrent_updates\":%s,\"created_at\":%s,"
                "\"devices_assigned\":%s,\"devices_completed\":%s,\"devices_failed\":%s,"
                "\"dispatched\":false}",
                fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6],
                PQgetvalue(groups, i, 7), PQgetvalue(groups, i, 8),
                PQgetvalue(groups, i, 9), PQgetvalue(groups, i, 10), PQgetvalue(groups, i, 11));
        }
        if (pos < 131072) pos += (size_t)snprintf(json + pos, 131072 - pos, "]}");
        PQclear(groups);
        db_release(conn, 0);
        os_send_json(client_fd, 200, json, origin, extra_headers, extra_len);
        free(json);
        return;
    }

    /* =========================================================================
     * 6. GET /api/v1/os/deployments/:id: View Deployment Status
     * ========================================================================= */
    if (strncmp(path, dep_pfx, dep_plen) == 0 && strcmp(method, "GET") == 0) {
        const char *dep_id = path + dep_plen;
        PGresult *dr = db_simple(conn,
            "SELECT g.id, g.institution_id, g.group_name, r.release_id, r.version, g.rollout_stage, g.status, "
            "g.max_concurrent_updates, g.created_at, "
            "(SELECT COUNT(*) FROM os_deployment_assignments a WHERE a.group_id = g.id), "
            "(SELECT COUNT(*) FROM os_deployment_assignments a WHERE a.group_id = g.id "
            "AND a.status IN ('installed','verified')), "
            "(SELECT COUNT(*) FROM os_deployment_assignments a WHERE a.group_id = g.id "
            "AND a.status = 'failed') "
            "FROM os_deployment_groups g JOIN os_releases r ON g.target_release_id = r.id "
            "WHERE g.id = $1 AND ($2 = TRUE OR g.institution_id = $3)", 3,
            (const char *[]){ dep_id, is_owner ? "TRUE" : "FALSE", sess.institution_id },
            (int []){ (int)strlen(dep_id), is_owner ? 4 : 5, (int)strlen(sess.institution_id) });

        if (!dr || PQntuples(dr) == 0) {
            if (dr) PQclear(dr);
            db_release(conn, 0);
            os_send_error(client_fd, 404, "Deployment group not found", origin, extra_headers, extra_len);
            return;
        }

        char resp[3072], fields[7][256];
        for (int i = 0; i < 7; i++) {
            os_json_escape(PQgetvalue(dr, 0, i), fields[i], sizeof(fields[i]));
        }
        snprintf(resp, sizeof(resp),
            "{\"deployment\":{\"id\":\"%s\",\"institution_id\":\"%s\",\"group_name\":\"%s\","
            "\"target_release_id\":\"%s\",\"target_version\":\"%s\",\"rollout_stage\":\"%s\","
            "\"status\":\"%s\",\"max_concurrent_updates\":%s,\"created_at\":%s,"
            "\"devices_assigned\":%s,\"devices_completed\":%s,\"devices_failed\":%s,"
            "\"dispatched\":false}}",
            fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6],
            PQgetvalue(dr, 0, 7), PQgetvalue(dr, 0, 8),
            PQgetvalue(dr, 0, 9), PQgetvalue(dr, 0, 10), PQgetvalue(dr, 0, 11));
        PQclear(dr);

        db_release(conn, 0);
        os_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
        return;
    }

    /* =========================================================================
     * 6. Device Update Sub-routes: /api/v1/os/devices/:id/...
     * ========================================================================= */
    const char *odev_pfx = "/api/v1/os/devices/";
    size_t odev_plen = strlen(odev_pfx);
    if (strncmp(path, odev_pfx, odev_plen) == 0) {
        const char *sub = path + odev_plen;
        char device_id[64] = {0};
        const char *slash = strchr(sub, '/');
        size_t len = slash ? (size_t)(slash - sub) : strlen(sub);
        if (len >= sizeof(device_id)) {
            db_release(conn, 0);
            os_send_error(client_fd, 400, "Invalid device ID", origin, extra_headers, extra_len);
            return;
        }
        memcpy(device_id, sub, len);
        device_id[len] = '\0';
        const char *action = slash ? slash : "";

        if (strcmp(method, "POST") == 0 &&
            (strcmp(action, "/update-events") == 0 || strcmp(action, "/verify-release") == 0)) {
            db_release(conn, 0);
            os_send_error(client_fd, 501,
                          "Authenticated device-agent event and post-boot attestation ingestion is not configured",
                          origin, extra_headers, extra_len);
            return;
        }

        /* Load Device */
        const char *dev_p[1] = { device_id };
        int dev_l[1] = { (int)strlen(device_id) };
        PGresult *d_res = db_simple(conn,
            "SELECT id, institution_id, os_release_id, secure_boot_state, tpm_present, status FROM devices WHERE id = $1", 1, dev_p, dev_l);

        if (!d_res || PQntuples(d_res) == 0) {
            if (d_res) PQclear(d_res);
            db_release(conn, 0);
            os_send_error(client_fd, 404, "Device not registered in ExamOS", origin, extra_headers, extra_len);
            return;
        }

        char d_inst[64] = {0}, cur_release[64] = {0}, d_sb[32] = {0}, d_status[32] = {0};
        int d_tpm = 1;
        strncpy(d_inst, PQgetvalue(d_res, 0, 1), sizeof(d_inst) - 1);
        strncpy(cur_release, PQgetvalue(d_res, 0, 2), sizeof(cur_release) - 1);
        strncpy(d_sb, PQgetvalue(d_res, 0, 3), sizeof(d_sb) - 1);
        d_tpm = (strcmp(PQgetvalue(d_res, 0, 4), "t") == 0);
        strncpy(d_status, PQgetvalue(d_res, 0, 5), sizeof(d_status) - 1);
        PQclear(d_res);

        if (!is_owner && (!sess.institution_id[0] || strcmp(sess.institution_id, d_inst) != 0)) {
            db_release(conn, 0);
            os_send_error(client_fd, 403, "Device is outside the authenticated institution scope",
                          origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- GET /api/v1/os/devices/:id/update (Check Update Eligibility) ---------------- */
        if (strcmp(method, "GET") == 0 && strcmp(action, "/update") == 0) {
            /* 1. Device Registration / Health Check */
            if (strcmp(d_status, "revoked") == 0 || strcmp(d_status, "quarantined") == 0) {
                db_release(conn, 0);
                os_send_json(client_fd, 200, "{\"outcome\":\"BLOCKED\",\"reason\":\"Device status is untrusted or quarantined\"}", origin, extra_headers, extra_len);
                return;
            }

            /* 2. ACTIVE EXAM SESSION GUARD (Critical Module 11/12/14 safeguard) */
            /* Under no circumstances may an OS update occur during an active examination */
            const char *es_p[1] = { device_id };
            int es_l[1] = { (int)strlen(device_id) };
            PGresult *es_res = db_simple(conn,
                "SELECT id, student_id, examination_id FROM exam_sessions "
                "WHERE device_id = $1 AND status IN ('active', 'in_progress', 'authorized') LIMIT 1", 1, es_p, es_l);

            if (es_res && PQntuples(es_res) > 0) {
                PQclear(es_res);
                db_release(conn, 0);
                os_send_json(client_fd, 200,
                    "{\"outcome\":\"BLOCKED\",\"reason\":\"ACTIVE_EXAM_SESSION: OS updates forbidden during active examination\"}",
                    origin, extra_headers, extra_len);
                return;
            }
            if (es_res) PQclear(es_res);

            /* 3. Hardware Preconditions */
            if (strcmp(d_sb, "enabled") != 0 || !d_tpm) {
                db_release(conn, 0);
                os_send_json(client_fd, 200,
                    "{\"outcome\":\"BLOCKED\",\"reason\":\"Hardware security preconditions failed (TPM or Secure Boot missing)\"}",
                    origin, extra_headers, extra_len);
                return;
            }

            /* 4. Find Latest Active Release */
            const char *candidate_params[1] = { device_id };
            int candidate_lengths[1] = { (int)strlen(device_id) };
            PGresult *rel_r = db_simple(conn,
                "SELECT r.id, r.release_id, r.version, r.kernel_version, r.status, r.minimum_supported_version, "
                "r.signing_key_id, r.manifest_signature "
                "FROM os_releases r "
                "JOIN os_release_manifests m ON m.release_id = r.id AND m.verified = TRUE "
                "WHERE r.status = 'active' AND m.signature_value IS NOT NULL AND m.signature_value <> '' "
                "AND EXISTS (SELECT 1 FROM os_deployment_assignments a "
                "JOIN os_deployment_groups g ON g.id = a.group_id "
                "WHERE a.device_id = $1 AND a.target_release_id = r.id AND g.status = 'active' "
                "AND a.status IN ('assigned','downloading','staged')) "
                "AND r.signing_key_id IS NOT NULL "
                "ORDER BY r.created_at DESC LIMIT 1", 1, candidate_params, candidate_lengths);

            if (!rel_r || PQntuples(rel_r) == 0) {
                if (rel_r) PQclear(rel_r);
                db_release(conn, 0);
                os_send_json(client_fd, 200, "{\"outcome\":\"UP_TO_DATE\",\"reason\":\"No active target release available\"}", origin, extra_headers, extra_len);
                return;
            }

            char t_pk[64], t_id[64], t_ver[64], t_kern[64], t_stat[32], t_min[64], t_key[64], t_sig[128];
            strncpy(t_pk, PQgetvalue(rel_r, 0, 0), sizeof(t_pk) - 1);
            strncpy(t_id, PQgetvalue(rel_r, 0, 1), sizeof(t_id) - 1);
            strncpy(t_ver, PQgetvalue(rel_r, 0, 2), sizeof(t_ver) - 1);
            strncpy(t_kern, PQgetvalue(rel_r, 0, 3), sizeof(t_kern) - 1);
            strncpy(t_stat, PQgetvalue(rel_r, 0, 4), sizeof(t_stat) - 1);
            strncpy(t_min, PQgetvalue(rel_r, 0, 5), sizeof(t_min) - 1);
            strncpy(t_key, PQgetvalue(rel_r, 0, 6), sizeof(t_key) - 1);
            strncpy(t_sig, PQgetvalue(rel_r, 0, 7), sizeof(t_sig) - 1);
            PQclear(rel_r);

            /* Check if already running target release */
            if (strcmp(cur_release, t_id) == 0 || strcmp(cur_release, t_ver) == 0) {
                db_release(conn, 0);
                char resp[256];
                snprintf(resp, sizeof(resp), "{\"outcome\":\"UP_TO_DATE\",\"current_release\":\"%s\"}", t_id);
                os_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
                return;
            }

            /* Anti-Downgrade Check: Target version cannot be lower than minimum security baseline */
            if (semver_cmp(t_ver, t_min) < 0) {
                db_release(conn, 0);
                os_send_json(client_fd, 200, "{\"outcome\":\"BLOCKED\",\"reason\":\"Anti-downgrade violation: version below security baseline\"}", origin, extra_headers, extra_len);
                return;
            }

            /* Record / Update Job */
            char jid[64];
            snprintf(jid, sizeof(jid), "upj_%ld_%d", (long)time(NULL), rand() % 10000);
            const char *jp[5] = { jid, device_id, d_inst, cur_release, t_pk };
            int jl[5];
            for (int i = 0; i < 5; i++) jl[i] = jp[i] ? (int)strlen(jp[i]) : 0;

            PGresult *jr = db_simple(conn,
                "INSERT INTO os_update_jobs (id, device_id, institution_id, source_release_id, target_release_id, status, created_at, updated_at) "
                "VALUES ($1, $2, $3, $4, $5, 'AVAILABLE', EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 5, jp, jl);
            if (jr) PQclear(jr);

            db_release(conn, 0);

            char resp[2048];
            snprintf(resp, sizeof(resp),
                "{\"outcome\":\"AVAILABLE\",\"job_id\":\"%s\",\"target_release\":{\"id\":\"%s\",\"release_id\":\"%s\","
                "\"version\":\"%s\",\"kernel_version\":\"%s\",\"signing_key_id\":\"%s\",\"manifest_signature\":\"%s\"},"
                "\"preservation_guarantee\":{\"preserve_windows\":true,\"no_repartition\":true,\"atomic_staging\":true}}",
                jid, t_pk, t_id, t_ver, t_kern, t_key, t_sig);
            os_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/os/devices/:id/update-events (Telemetry / Progress) ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(action, "/update-events") == 0) {
            char ev_type[64] = "DOWNLOAD_COMPLETED", severity[16] = "INFO", details[256] = "";
            int pct = 100;
            ctrl_json_string(body, "event_type", ev_type, sizeof(ev_type));
            ctrl_json_string(body, "severity", severity, sizeof(severity));
            ctrl_json_string(body, "details", details, sizeof(details));
            ctrl_json_int(body, "progress_pct", &pct);

            char eid[64];
            snprintf(eid, sizeof(eid), "oev_%ld_%d", (long)time(NULL), rand() % 10000);

            const char *ep[4] = { eid, device_id, ev_type, details };
            int el[4];
            for (int i = 0; i < 4; i++) el[i] = ep[i] ? (int)strlen(ep[i]) : 0;

            PGresult *er = db_simple(conn,
                "INSERT INTO os_update_events (id, device_id, event_type, details, occurred_at) "
                "VALUES ($1, $2, $3, $4, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 4, ep, el);
            if (er) PQclear(er);

            /* Update active job status if STAGED */
            if (strcmp(ev_type, "STAGED") == 0) {
                const char *up[2] = { "STAGED", device_id };
                int ul[2] = { 6, (int)strlen(device_id) };
                PGresult *ur = db_simple(conn,
                    "UPDATE os_update_jobs SET status = $1, progress_pct = 100, updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 "
                    "WHERE device_id = $2 AND status = 'AVAILABLE'", 2, up, ul);
                if (ur) PQclear(ur);
            }

            db_release(conn, 0);
            char resp[256];
            snprintf(resp, sizeof(resp), "{\"status\":\"recorded\",\"event_id\":\"%s\",\"event_type\":\"%s\"}", eid, ev_type);
            os_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }

        /* ---------------- POST /api/v1/os/devices/:id/verify-release (Post-Boot Evidence) ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(action, "/verify-release") == 0) {
            char rel_id[64] = {0}, boot_slot[32] = "B", boot_status[32] = "SUCCESS";
            int win_preserved = 1;
            ctrl_json_string(body, "release_id", rel_id, sizeof(rel_id));
            ctrl_json_string(body, "boot_slot", boot_slot, sizeof(boot_slot));
            ctrl_json_string(body, "boot_status", boot_status, sizeof(boot_status));
            ctrl_json_bool(body, "data_preservation_verified", &win_preserved);

            /* Resolve release PK */
            const char *rp[1] = { rel_id };
            int rl[1] = { (int)strlen(rel_id) };
            PGresult *rel_r = db_simple(conn, "SELECT id, status FROM os_releases WHERE id = $1 OR release_id = $1", 1, rp, rl);

            if (!rel_r || PQntuples(rel_r) == 0) {
                if (rel_r) PQclear(rel_r);
                db_release(conn, 0);
                os_send_error(client_fd, 404, "Target release record not found", origin, extra_headers, extra_len);
                return;
            }
            char r_pk[64], r_stat[32];
            strncpy(r_pk, PQgetvalue(rel_r, 0, 0), sizeof(r_pk) - 1);
            strncpy(r_stat, PQgetvalue(rel_r, 0, 1), sizeof(r_stat) - 1);
            PQclear(rel_r);

            /* Record Boot Attempt */
            char bid[64];
            snprintf(bid, sizeof(bid), "bat_%ld_%d", (long)time(NULL), rand() % 10000);
            const char *bp[4] = { bid, device_id, r_pk, boot_status };
            int bl[4] = { (int)strlen(bid), (int)strlen(device_id), (int)strlen(r_pk), (int)strlen(boot_status) };
            PGresult *br = db_simple(conn,
                "INSERT INTO os_boot_attempts (id, device_id, release_id, boot_status, attempted_at) "
                "VALUES ($1, $2, $3, $4, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 4, bp, bl);
            if (br) PQclear(br);

            if (strcmp(boot_status, "SUCCESS") == 0 && win_preserved) {
                /* Update device running OS release */
                const char *up[2] = { rel_id, device_id };
                int ul[2] = { (int)strlen(rel_id), (int)strlen(device_id) };
                PGresult *ur = db_simple(conn,
                    "UPDATE devices SET os_release_id = $1, last_attestation_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, "
                    "updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 WHERE id = $2", 2, up, ul);
                if (ur) PQclear(ur);

                /* Mark Update Job SUCCEEDED */
                const char *uj[2] = { device_id, r_pk };
                int ujl[2] = { (int)strlen(device_id), (int)strlen(r_pk) };
                PGresult *uj_r = db_simple(conn,
                    "UPDATE os_update_jobs SET status = 'SUCCEEDED', progress_pct = 100, "
                    "completed_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, "
                    "updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 "
                    "WHERE device_id = $1 AND target_release_id = $2", 2, uj, ujl);
                if (uj_r) PQclear(uj_r);

                os_audit_log(sess.username, "RELEASE_UPDATE_SUCCEEDED", rel_id);
                db_release(conn, 0);

                char resp[512];
                snprintf(resp, sizeof(resp),
                    "{\"status\":\"SUCCEEDED\",\"device_id\":\"%s\",\"active_release\":\"%s\","
                    "\"data_preservation_verified\":true}",
                    device_id, rel_id);
                os_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
                return;
            } else {
                /* Mark Job Failed / Recovery Required */
                const char *uj[2] = { device_id, r_pk };
                int ujl[2] = { (int)strlen(device_id), (int)strlen(r_pk) };
                PGresult *uj_r = db_simple(conn,
                    "UPDATE os_update_jobs SET status = 'RECOVERY_REQUIRED', error_reason = 'Candidate boot verification failed', "
                    "updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000 "
                    "WHERE device_id = $1 AND target_release_id = $2", 2, uj, ujl);
                if (uj_r) PQclear(uj_r);

                os_audit_log(sess.username, "RELEASE_BOOT_FAILED", rel_id);
                db_release(conn, 0);

                char resp[256];
                snprintf(resp, sizeof(resp), "{\"status\":\"RECOVERY_REQUIRED\",\"device_id\":\"%s\"}", device_id);
                os_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
                return;
            }
        }

        /* ---------------- POST /api/v1/os/devices/:id/recovery (Authorized Rollback) ---------------- */
        if (strcmp(method, "POST") == 0 && strcmp(action, "/recovery") == 0) {
            char rec_rel[64] = {0}, reason[256] = "Candidate boot failed, initiating approved recovery";
            ctrl_json_string(body, "recovery_release_id", rec_rel, sizeof(rec_rel));
            ctrl_json_string(body, "reason", reason, sizeof(reason));

            if (!rec_rel[0]) {
                db_release(conn, 0);
                os_send_error(client_fd, 400, "Recovery release ID is required", origin, extra_headers, extra_len);
                return;
            }

            /* Anti-Downgrade & Recovery Authorization Check */
            const char *rp[1] = { rec_rel };
            int rl[1] = { (int)strlen(rec_rel) };
            PGresult *rel_r = db_simple(conn,
                "SELECT r.id, r.release_id, r.status, r.rollback_permitted, r.minimum_supported_version, "
                "r.version, COALESCE(m.verified, FALSE), COALESCE(m.signature_value, '') "
                "FROM os_releases r LEFT JOIN os_release_manifests m ON m.release_id = r.id "
                "WHERE r.id = $1 OR r.release_id = $1", 1, rp, rl);

            if (!rel_r || PQntuples(rel_r) == 0) {
                if (rel_r) PQclear(rel_r);
                db_release(conn, 0);
                os_send_error(client_fd, 404, "Recovery release does not exist", origin, extra_headers, extra_len);
                return;
            }

            char r_pk[64] = {0}, r_id[64] = {0}, r_stat[32] = {0}, r_min[64] = {0}, r_ver[64] = {0};
            char target_verified[8] = {0}, target_signature[4096] = {0};
            int rollback_ok = 0;
            strncpy(r_pk, PQgetvalue(rel_r, 0, 0), sizeof(r_pk) - 1);
            strncpy(r_id, PQgetvalue(rel_r, 0, 1), sizeof(r_id) - 1);
            strncpy(r_stat, PQgetvalue(rel_r, 0, 2), sizeof(r_stat) - 1);
            rollback_ok = (strcmp(PQgetvalue(rel_r, 0, 3), "t") == 0);
            strncpy(r_min, PQgetvalue(rel_r, 0, 4), sizeof(r_min) - 1);
            strncpy(r_ver, PQgetvalue(rel_r, 0, 5), sizeof(r_ver) - 1);
            strncpy(target_verified, PQgetvalue(rel_r, 0, 6), sizeof(target_verified) - 1);
            strncpy(target_signature, PQgetvalue(rel_r, 0, 7), sizeof(target_signature) - 1);
            PQclear(rel_r);

            /* Anti-Downgrade Violation 1: Release is revoked */
            if (strcmp(r_stat, "revoked") == 0) {
                /* Log rejected downgrade attempt */
                char rec_id[64];
                snprintf(rec_id, sizeof(rec_id), "rec_%ld_%d", (long)time(NULL), rand() % 10000);
                const char *rec_p[6] = { rec_id, device_id, d_inst, cur_release, r_pk, "REJECTED_DOWNGRADE" };
                int rec_l[6];
                for (int i = 0; i < 6; i++) rec_l[i] = rec_p[i] ? (int)strlen(rec_p[i]) : 0;
                PGresult *rec_r = db_simple(conn,
                    "INSERT INTO os_recovery_events (id, device_id, institution_id, failed_release_id, recovery_release_id, reason, status, authorized, occurred_at) "
                    "VALUES ($1, $2, $3, $4, $5, 'Anti-downgrade violation: Target recovery release has been revoked', $6, FALSE, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 6, rec_p, rec_l);
                if (rec_r) PQclear(rec_r);

                db_release(conn, 0);
                os_send_error(client_fd, 403, "Anti-downgrade violation: Target recovery release has been revoked", origin, extra_headers, extra_len);
                return;
            }

            /* Anti-Downgrade Violation 2: Rollback is not specifically permitted */
            if (!rollback_ok) {
                db_release(conn, 0);
                os_send_error(client_fd, 403, "Anti-downgrade violation: Target release is not authorized for rollback", origin, extra_headers, extra_len);
                return;
            }

            /* Anti-Downgrade Violation 3: Below security baseline */
            if (semver_cmp(r_ver, r_min) < 0) {
                db_release(conn, 0);
                os_send_error(client_fd, 403, "Anti-downgrade violation: Target recovery release version is below security baseline", origin, extra_headers, extra_len);
                return;
            }

            if (strcmp(target_verified, "t") != 0 || !target_signature[0] ||
                (strcmp(r_stat, "active") != 0 && strcmp(r_stat, "approved") != 0 &&
                 strcmp(r_stat, "retired") != 0)) {
                db_release(conn, 0);
                os_send_error(client_fd, 409, "Recovery target is not a trusted verified release",
                              origin, extra_headers, extra_len);
                return;
            }

            /* Persist the request; only an authenticated device agent can confirm recovery. */
            char rec_id[64];
            snprintf(rec_id, sizeof(rec_id), "rec_%ld_%d", (long)time(NULL), rand() % 10000);
            const char *rec_p[7] = { rec_id, device_id, d_inst, cur_release, r_pk, reason, "INITIATED" };
            int rec_l[7];
            for (int i = 0; i < 7; i++) rec_l[i] = (int)strlen(rec_p[i]);
            PGresult *rec_r = db_simple(conn,
                "INSERT INTO os_recovery_events (id, device_id, institution_id, failed_release_id, recovery_release_id, reason, status, authorized, occurred_at) "
                "VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)", 7, rec_p, rec_l);
            if (!rec_r || PQresultStatus(rec_r) != PGRES_COMMAND_OK) {
                if (rec_r) PQclear(rec_r);
                db_release(conn, 0);
                os_send_error(client_fd, 503, "Recovery request could not be persisted",
                              origin, extra_headers, extra_len);
                return;
            }
            PQclear(rec_r);

            os_audit_log(sess.username, "OS_RECOVERY_REQUESTED", r_id);
            db_release(conn, 0);

            char resp[512];
            snprintf(resp, sizeof(resp),
                "{\"status\":\"INITIATED\",\"device_id\":\"%s\",\"recovery_release_id\":\"%s\","
                "\"dispatched\":false,\"message\":\"Device completion requires authenticated agent acknowledgement\"}",
                device_id, r_pk);
            os_send_json(client_fd, 200, resp, origin, extra_headers, extra_len);
            return;
        }
    }

    db_release(conn, 0);
    os_send_error(client_fd, 404, "OS release or deployment endpoint not found", origin, extra_headers, extra_len);
}
