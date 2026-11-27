#include "approvals_controller.h"

#include "../audit/audit.h"
#include "../db/db.h"
#include "../security/release_signature.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void approval_send(int fd, int status, const char *body,
                          const char *origin, char *extra, size_t extra_len) {
    ctrl_set_cors(extra, extra_len, origin, ctrl_cors_origin_allowed(origin));
    ctrl_send_json(fd, status, body, extra);
}

static void approval_error(int fd, int status, const char *message,
                           const char *origin, char *extra, size_t extra_len) {
    char escaped[512], body[640];
    ctrl_json_escape(message, escaped, sizeof(escaped));
    snprintf(body, sizeof(body), "{\"error\":\"%s\"}", escaped);
    approval_send(fd, status, body, origin, extra, extra_len);
}

static int approval_id(char *out, size_t out_len, const char *prefix) {
    unsigned char random[16];
    static const char hex[] = "0123456789abcdef";
    size_t prefix_len = strlen(prefix);
    if (out_len < prefix_len + sizeof(random) * 2 + 1 || RAND_bytes(random, sizeof(random)) != 1)
        return -1;
    memcpy(out, prefix, prefix_len);
    for (size_t i = 0; i < sizeof(random); i++) {
        out[prefix_len + i * 2] = hex[random[i] >> 4];
        out[prefix_len + i * 2 + 1] = hex[random[i] & 15];
    }
    out[prefix_len + sizeof(random) * 2] = '\0';
    return 0;
}

static int approval_safe_id(const char *id) {
    if (!id || !id[0] || strlen(id) > 64) return 0;
    for (const unsigned char *p = (const unsigned char *)id; *p; p++) {
        if (!( (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
               (*p >= '0' && *p <= '9') || *p == '_' || *p == '-' || *p == '.' ))
            return 0;
    }
    return 1;
}

static const char *approval_role_alias(user_role_t role) {
    switch (role) {
        case ROLE_PLATFORM_OWNER: return "superadmin";
        case ROLE_INSTITUTION_ADMIN: return "inst_admin";
        case ROLE_EXAM_MANAGER: return "exam_controller";
        case ROLE_SECURITY_ADMIN: return "security_engineer";
        case ROLE_INVIGILATOR: return "invigilator";
        case ROLE_TECH_OPERATOR: return "ops_admin";
        case ROLE_INCIDENT_INVESTIGATOR: return "incident_investigator";
        case ROLE_READONLY_AUDITOR: return "auditor";
        case ROLE_SUPPORT_ENGINEER: return "support";
        default: return "";
    }
}

static int approval_role_id(const char *role) {
    if (strcasecmp(role, "superadmin") == 0 ||
        strcasecmp(role, "PLATFORM_OWNER") == 0) return ROLE_PLATFORM_OWNER;
    if (strcasecmp(role, "inst_admin") == 0 ||
        strcasecmp(role, "INSTITUTION_ADMIN") == 0) return ROLE_INSTITUTION_ADMIN;
    if (strcasecmp(role, "exam_controller") == 0 ||
        strcasecmp(role, "EXAM_MANAGER") == 0) return ROLE_EXAM_MANAGER;
    if (strcasecmp(role, "security_engineer") == 0 ||
        strcasecmp(role, "SECURITY_ADMIN") == 0) return ROLE_SECURITY_ADMIN;
    if (strcasecmp(role, "invigilator") == 0) return ROLE_INVIGILATOR;
    if (strcasecmp(role, "ops_admin") == 0 || strcasecmp(role, "it_admin") == 0 ||
        strcasecmp(role, "TECH_OPERATOR") == 0)
        return ROLE_TECH_OPERATOR;
    if (strcasecmp(role, "auditor") == 0 ||
        strcasecmp(role, "incident_investigator") == 0)
        return ROLE_INCIDENT_INVESTIGATOR;
    if (strcasecmp(role, "readonly_auditor") == 0 ||
        strcasecmp(role, "READONLY_AUDITOR") == 0) return ROLE_READONLY_AUDITOR;
    if (strcasecmp(role, "support") == 0 ||
        strcasecmp(role, "SUPPORT_ENGINEER") == 0) return ROLE_SUPPORT_ENGINEER;
    return 0;
}

static const char *approval_role_name(int role_id) {
    switch (role_id) {
        case ROLE_PLATFORM_OWNER: return "superadmin";
        case ROLE_INSTITUTION_ADMIN: return "inst_admin";
        case ROLE_EXAM_MANAGER: return "exam_controller";
        case ROLE_SECURITY_ADMIN: return "security_engineer";
        case ROLE_INVIGILATOR: return "invigilator";
        case ROLE_TECH_OPERATOR: return "ops_admin";
        case ROLE_INCIDENT_INVESTIGATOR: return "auditor";
        case ROLE_READONLY_AUDITOR: return "readonly_auditor";
        case ROLE_SUPPORT_ENGINEER: return "support";
        default: return "";
    }
}

static int approval_role_rank(int role_id) {
    switch (role_id) {
        case ROLE_PLATFORM_OWNER: return 100;
        case ROLE_INSTITUTION_ADMIN: return 80;
        case ROLE_EXAM_MANAGER: return 70;
        case ROLE_SECURITY_ADMIN: return 65;
        case ROLE_INVIGILATOR: return 50;
        case ROLE_TECH_OPERATOR: return 60;
        case ROLE_INCIDENT_INVESTIGATOR:
        case ROLE_READONLY_AUDITOR: return 40;
        case ROLE_SUPPORT_ENGINEER: return 30;
        default: return 0;
    }
}

static int approval_role_change_target(PGconn *conn, const char *target_id,
                                       const char *tenant_id, const char *proposed_data,
                                       const char *requester_id, int requester_role,
                                       char *canonical_id, size_t canonical_id_len,
                                       int *new_role_id) {
    char requested_role[64] = {0};
    if (!ctrl_json_string(proposed_data, "role", requested_role, sizeof(requested_role)))
        return 0;
    int role_id = approval_role_id(requested_role);
    if (!role_id || (role_id != ROLE_PLATFORM_OWNER &&
                     approval_role_rank(role_id) < 60) ||
        (role_id == ROLE_PLATFORM_OWNER && requester_role != ROLE_PLATFORM_OWNER) ||
        (requester_role != ROLE_PLATFORM_OWNER &&
         approval_role_rank(role_id) >= approval_role_rank(requester_role))) {
        return 0;
    }

    const char *params[1] = { target_id };
    const int lengths[1] = { (int)strlen(params[0]) };
    PGresult *res = db_simple(conn,
        "SELECT target_id,target_tenant,target_role FROM ("
        "SELECT id AS target_id,COALESCE(tenant_id,'') AS target_tenant,"
        "role::text AS target_role,1 AS source_order FROM users "
        "WHERE (id=$1 OR username=$1) "
        "UNION ALL "
        "SELECT user_id,COALESCE(institution_id,''),role::text,2 FROM examos_admin_users "
        "WHERE (user_id=$1 OR username=$1)) target "
        "ORDER BY source_order LIMIT 1",
        1, params, lengths);
    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) != 1) {
        if (res) PQclear(res);
        return -1;
    }
    const char *resolved_id = PQgetvalue(res, 0, 0);
    const char *resolved_tenant = PQgetvalue(res, 0, 1);
    const char *current_role = PQgetvalue(res, 0, 2);
    int current_role_id = approval_role_id(PQgetvalue(res, 0, 2));
    int current_role_is_candidate =
        strcasecmp(current_role, "student") == 0 ||
        strcasecmp(current_role, "candidate") == 0;
    int valid = resolved_id[0] && strcmp(resolved_id, requester_id) != 0 &&
                strcmp(resolved_tenant, tenant_id ? tenant_id : "") == 0 &&
                (current_role_id != 0 || current_role_is_candidate) &&
                current_role_id != role_id &&
                (requester_role == ROLE_PLATFORM_OWNER ||
                 approval_role_rank(current_role_id) < approval_role_rank(requester_role)) &&
                strlen(resolved_id) < canonical_id_len;
    if (valid) {
        snprintf(canonical_id, canonical_id_len, "%s", resolved_id);
        *new_role_id = role_id;
    }
    PQclear(res);
    return valid;
}



static int approval_execute_role_change(PGconn *conn, const char *target_id,
                                        const char *tenant_id, const char *proposed_data,
                                        const char *requester_id, int requester_role) {
    char canonical_id[129] = {0};
    int role_id = 0;
    if (approval_role_change_target(conn, target_id, tenant_id, proposed_data,
                                    requester_id, requester_role,
                                    canonical_id, sizeof(canonical_id), &role_id) != 1)
        return -1;

    char role_id_text[16];
    snprintf(role_id_text, sizeof(role_id_text), "%d", role_id);
    const char *user_params[2] = { approval_role_name(role_id), canonical_id };
    const int user_lengths[2] = {
        (int)strlen(user_params[0]), (int)strlen(user_params[1])
    };
    PGresult *user_update = db_simple(conn,
        "UPDATE users SET role=$1 WHERE id=$2 AND COALESCE(tenant_id,'')=$3",
        3, (const char *[]){ user_params[0], user_params[1], tenant_id ? tenant_id : "" },
        (const int []){ user_lengths[0], user_lengths[1], (int)strlen(tenant_id ? tenant_id : "") });
    if (!user_update || PQresultStatus(user_update) != PGRES_COMMAND_OK ||
        strcmp(PQcmdTuples(user_update), "1") != 0) {
        if (user_update) PQclear(user_update);
        return -1;
    }
    PQclear(user_update);

    const char *admin_params[3] = { role_id_text, canonical_id, tenant_id ? tenant_id : "" };
    const int admin_lengths[3] = {
        (int)strlen(admin_params[0]), (int)strlen(admin_params[1]), (int)strlen(admin_params[2])
    };
    PGresult *admin_update = db_simple(conn,
        "UPDATE examos_admin_users SET role=$1::smallint "
        "WHERE user_id=$2 AND COALESCE(institution_id,'')=$3",
        3, admin_params, admin_lengths);
    if (!admin_update || PQresultStatus(admin_update) != PGRES_COMMAND_OK ||
        strcmp(PQcmdTuples(admin_update), "1") != 0) {
        if (admin_update) PQclear(admin_update);
        return -1;
    }
    PQclear(admin_update);

    PGresult *session_update = db_simple(conn,
        "UPDATE auth_sessions SET status='ended' WHERE user_id=$1 AND status='active'",
        1, (const char *[]){ canonical_id }, (const int []){ (int)strlen(canonical_id) });
    if (!session_update || PQresultStatus(session_update) != PGRES_COMMAND_OK) {
        if (session_update) PQclear(session_update);
        return -1;
    }
    PQclear(session_update);
    session_update = db_simple(conn,
        "UPDATE examos_admin_sessions SET revoked_at=clock_timestamp() "
        "WHERE user_id=$1 AND revoked_at IS NULL",
        1, (const char *[]){ canonical_id }, (const int []){ (int)strlen(canonical_id) });
    if (!session_update || PQresultStatus(session_update) != PGRES_COMMAND_OK) {
        if (session_update) PQclear(session_update);
        return -1;
    }
    PQclear(session_update);
    return 0;
}

static int approval_release_target_valid(PGconn *conn, const char *release_id,
                                         const char *requester_id,
                                         const char *requester_name,
                                         const char *approver_id,
                                         const char *approver_name,
                                         const char *proposed_data) {
    char proposed_release_id[65] = {0}, proposed_digest[129] = {0};
    if (!ctrl_json_string(proposed_data, "releaseId", proposed_release_id,
                          sizeof(proposed_release_id)) ||
        !ctrl_json_string(proposed_data, "manifestDigest", proposed_digest,
                          sizeof(proposed_digest)) ||
        strcmp(proposed_release_id, release_id) != 0 ||
        strncmp(proposed_digest, "sha256:", 7) != 0 ||
        strlen(proposed_digest) != 71)
        return 0;
    for (size_t i = 7; i < 71; i++) {
        if (!((proposed_digest[i] >= '0' && proposed_digest[i] <= '9') ||
              (proposed_digest[i] >= 'a' && proposed_digest[i] <= 'f') ||
              (proposed_digest[i] >= 'A' && proposed_digest[i] <= 'F')))
            return 0;
    }

    PGresult *res = db_simple(conn,
        "SELECT r.status,r.created_by,r.manifest_digest,m.manifest_digest,"
        "m.signed_digest,r.verification_digest,m.signature_value,m.verified,"
        "m.signature_verified,m.signature_verified_at,r.trust_status,"
        "r.verification_state,r.verification_at,r.verification_expires_at,"
        "k.status,k.key_type,k.public_key_pem,k.key_fingerprint,"
        "m.signature_algorithm,k.algorithm,m.signing_key_id,r.signing_key_id,"
        "m.manifest_json::text,r.version,m.canonical_payload,"
        "m.canonical_version,m.canonical_payload_sha256 "
        "FROM os_releases r "
        "JOIN os_release_manifests m ON m.release_id=r.id "
        "JOIN os_release_signing_keys k ON k.key_id=r.signing_key_id "
        "WHERE r.id=$1 FOR UPDATE OF r,m,k",
        1, (const char *[]){ release_id },
        (const int []){ (int)strlen(release_id) });
    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
        if (res) PQclear(res);
        return -1;
    }
    if (PQntuples(res) != 1) {
        PQclear(res);
        return 0;
    }

    const char *release_status = PQgetvalue(res, 0, 0);
    const char *creator = PQgetvalue(res, 0, 1);
    const char *release_digest = PQgetvalue(res, 0, 2);
    const char *manifest_digest = PQgetvalue(res, 0, 3);
    const char *signed_digest = PQgetvalue(res, 0, 4);
    const char *verification_digest = PQgetvalue(res, 0, 5);
    const char *signature = PQgetvalue(res, 0, 6);
    const char *verified = PQgetvalue(res, 0, 7);
    const char *signature_verified = PQgetvalue(res, 0, 8);
    const char *signature_verified_at = PQgetvalue(res, 0, 9);
    const char *trust_status = PQgetvalue(res, 0, 10);
    const char *verification_state = PQgetvalue(res, 0, 11);
    const char *verification_at = PQgetvalue(res, 0, 12);
    const char *verification_expires_at = PQgetvalue(res, 0, 13);
    const char *key_status = PQgetvalue(res, 0, 14);
    const char *key_type = PQgetvalue(res, 0, 15);
    const char *public_key = PQgetvalue(res, 0, 16);
    const char *key_fingerprint = PQgetvalue(res, 0, 17);
    const char *signature_algorithm = PQgetvalue(res, 0, 18);
    const char *key_algorithm = PQgetvalue(res, 0, 19);
    const char *manifest_key_id = PQgetvalue(res, 0, 20);
    const char *release_key_id = PQgetvalue(res, 0, 21);
    const char *manifest_json = PQgetvalue(res, 0, 22);
    const char *release_version = PQgetvalue(res, 0, 23);
    const char *canonical_payload = PQgetvalue(res, 0, 24);
    const char *canonical_version = PQgetvalue(res, 0, 25);
    const char *canonical_payload_digest = PQgetvalue(res, 0, 26);
    long long now_ms = (long long)time(NULL) * 1000;
    int valid = strcmp(release_status, "signed") == 0 &&
                creator[0] && strcmp(creator, requester_id) != 0 &&
                (!requester_name || strcmp(creator, requester_name) != 0) &&
                (!approver_id || (strcmp(creator, approver_id) != 0 &&
                                  (!approver_name ||
                                   strcmp(creator, approver_name) != 0))) &&
                strcmp(release_digest, proposed_digest) == 0 &&
                strcmp(manifest_digest, proposed_digest) == 0 &&
                strcmp(signed_digest, proposed_digest) == 0 &&
                strcmp(verification_digest, proposed_digest) == 0 &&
                signature[0] && strcmp(verified, "t") == 0 &&
                strcmp(signature_verified, "t") == 0 &&
                strtoll(signature_verified_at, NULL, 10) > 0 &&
                strtoll(signature_verified_at, NULL, 10) <= now_ms &&
                strcmp(trust_status, "verified") == 0 &&
                strcmp(verification_state, "verified") == 0 &&
                strcmp(canonical_version, "RFC8785") == 0 &&
                strcmp(canonical_payload_digest, proposed_digest) == 0 &&
                canonical_payload[0] &&
                strtoll(verification_at, NULL, 10) > 0 &&
                strtoll(verification_at, NULL, 10) <= now_ms &&
                strtoll(verification_expires_at, NULL, 10) > now_ms &&
                strcmp(key_status, "active") == 0 &&
                strcmp(key_type, "production") == 0 &&
                public_key[0] && key_fingerprint[0] &&
                strcmp(signature_algorithm, key_algorithm) == 0 &&
                strcmp(manifest_key_id, release_key_id) == 0;
    if (valid) {
        char manifest_release_id[65] = {0}, manifest_version[65] = {0};
        valid = ctrl_json_string(manifest_json, "release_id", manifest_release_id,
                                 sizeof(manifest_release_id)) &&
                ctrl_json_string(manifest_json, "version", manifest_version,
                                 sizeof(manifest_version)) &&
                strcmp(manifest_release_id, release_id) == 0 &&
                strcmp(manifest_version, release_version) == 0;
        if (valid) {
            int signature_result = release_signature_verify(
                canonical_payload, strlen(canonical_payload), release_digest,
                canonical_payload_digest, signed_digest, signature_algorithm,
                key_algorithm, signature, public_key, key_fingerprint);
            if (signature_result < 0) {
                PQclear(res);
                return -1;
            }
            valid = signature_result == 1;
        }
    }
    PQclear(res);
    return valid;
}

static int approval_device_reauth_target_valid(PGconn *conn,
                                               const char *device_id,
                                               const char *tenant_id) {
    PGresult *res = db_simple(conn,
        "SELECT status FROM devices WHERE id=$1 AND institution_id=$2 FOR UPDATE",
        2, (const char *[]){ device_id, tenant_id },
        (const int []){ (int)strlen(device_id), (int)strlen(tenant_id) });
    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
        if (res) PQclear(res);
        return -1;
    }
    if (PQntuples(res) != 1) {
        PQclear(res);
        return 0;
    }
    int valid = strcmp(PQgetvalue(res, 0, 0), "revoked") == 0;
    PQclear(res);
    return valid;
}

static int approval_execute_release(PGconn *conn, const char *release_id,
                                    const char *requester_id,
                                    const char *requester_name,
                                    const char *approver_id,
                                    const char *approver_name,
                                    const char *proposed_data,
                                    const char *decision_reason) {
    if (approval_release_target_valid(conn, release_id, requester_id,
                                      requester_name, approver_id, approver_name,
                                      proposed_data) != 1)
        return -1;

    char approval_record_id[64];
    if (approval_id(approval_record_id, sizeof(approval_record_id), "osap_") != 0)
        return -1;
    const char *insert_params[4] = {
        approval_record_id, release_id, approver_id, decision_reason
    };
    const int insert_lengths[4] = {
        (int)strlen(insert_params[0]), (int)strlen(insert_params[1]),
        (int)strlen(insert_params[2]), (int)strlen(insert_params[3])
    };
    PGresult *insert = db_simple(conn,
        "INSERT INTO os_release_approvals "
        "(id,release_id,reviewer_id,decision,notes,created_at) "
        "VALUES ($1,$2,$3,'approved',$4,"
        "(EXTRACT(EPOCH FROM clock_timestamp())*1000)::bigint)",
        4, insert_params, insert_lengths);
    if (!insert || PQresultStatus(insert) != PGRES_COMMAND_OK) {
        if (insert) PQclear(insert);
        return -1;
    }
    PQclear(insert);

    char proposed_digest[129] = {0};
    if (!ctrl_json_string(proposed_data, "manifestDigest", proposed_digest,
                          sizeof(proposed_digest)))
        return -1;
    const char *update_params[3] = { approver_id, release_id, proposed_digest };
    const int update_lengths[3] = {
        (int)strlen(update_params[0]), (int)strlen(update_params[1]),
        (int)strlen(update_params[2])
    };
    PGresult *update = db_simple(conn,
        "UPDATE os_releases SET status='approved',approved_by=$1,"
        "approved_at=(EXTRACT(EPOCH FROM clock_timestamp())*1000)::bigint,"
        "updated_at=(EXTRACT(EPOCH FROM clock_timestamp())*1000)::bigint "
        "WHERE id=$2 AND status='signed' AND created_by<>$1 "
        "AND manifest_digest=$3",
        3, update_params, update_lengths);
    if (!update || PQresultStatus(update) != PGRES_COMMAND_OK ||
        strcmp(PQcmdTuples(update), "1") != 0) {
        if (update) PQclear(update);
        return -1;
    }
    PQclear(update);
    return 0;
}

static int approval_actor_active(PGconn *conn, const auth_session_t *actor) {
    const char *role = security_role_to_string(actor->role);
    const char *alias = approval_role_alias(actor->role);
    char role_num[8];
    snprintf(role_num, sizeof(role_num), "%d", (int)actor->role);
    const char *params[4] = { actor->user_id, role, alias, role_num };
    int lengths[4] = {
        (int)strlen(params[0]), (int)strlen(params[1]),
        (int)strlen(params[2]), (int)strlen(params[3])
    };
    PGresult *res = db_simple(conn,
        "SELECT (EXISTS (SELECT 1 FROM users WHERE id=$1 AND status='active' "
        "AND role IN ($2,$3)) OR EXISTS (SELECT 1 FROM examos_admin_users "
        "WHERE user_id=$1 AND active=TRUE AND role=$4::smallint))::text",
        4, params, lengths);
    int active = res && PQresultStatus(res) == PGRES_TUPLES_OK &&
                 PQntuples(res) == 1 && strcmp(PQgetvalue(res, 0, 0), "true") == 0;
    if (res) PQclear(res);
    return active;
}

/* =========================================================================
 * Resource fingerprints and structured conflict evidence
 *
 * A fingerprint is a SHA-256 over the canonical current state of the target
 * resource.  It is captured when the request is submitted and recomputed from
 * the database before every decision and every execution.  A mismatch is a
 * blocking concurrent-modification conflict: an approval for state A can never
 * silently apply to state B.
 * ========================================================================= */
static int approval_fingerprint(PGconn *conn, const char *kind, const char *target_id,
                                const char *tenant_id, const char *proposed_data,
                                char *out, size_t out_len) {
    PGresult *res = NULL;
    const char *tenant = tenant_id ? tenant_id : "";
    const int target_len = (int)strlen(target_id);
    const int tenant_len = (int)strlen(tenant);

    if (strcmp(kind, "role-change") == 0) {
        res = db_simple(conn,
            "SELECT (id||'|'||role::text||'|'||COALESCE(tenant_id,'')||'|'||status) "
            "FROM users WHERE id=$1 "
            "UNION ALL "
            "SELECT (user_id||'|'||role::text||'|'||COALESCE(institution_id,'')||'|'||"
            "CASE WHEN active THEN 'active' ELSE 'inactive' END) "
            "FROM examos_admin_users WHERE user_id=$1 LIMIT 1",
            1, (const char *[]){ target_id }, (const int []){ target_len });
    } else if (strcmp(kind, "release-approve") == 0) {
        res = db_simple(conn,
            "SELECT (r.status||'|'||r.created_by||'|'||COALESCE(r.manifest_digest,'')||'|'||"
            "COALESCE(m.manifest_digest,'')||'|'||COALESCE(m.signed_digest,'')||'|'||"
            "COALESCE(r.verification_digest,'')||'|'||COALESCE(m.signature_value,'')||'|'||"
            "COALESCE(m.verified,FALSE)::text||'|'||COALESCE(m.signature_verified,FALSE)::text||'|'||"
            "COALESCE(m.signature_verified_at::text,'')||'|'||COALESCE(r.trust_status,'')||'|'||"
            "COALESCE(r.verification_state,'')||'|'||COALESCE(r.verification_at::text,'')||'|'||"
            "COALESCE(r.verification_expires_at::text,'')||'|'||"
            "COALESCE(k.status,'')||'|'||COALESCE(k.key_type,'')||'|'||"
            "COALESCE(k.public_key_pem,'')||'|'||COALESCE(k.key_fingerprint,'')) "
            "FROM os_releases r "
            "JOIN os_release_manifests m ON m.release_id=r.id "
            "JOIN os_release_signing_keys k ON k.key_id=r.signing_key_id "
            "WHERE r.id=$1",
            1, (const char *[]){ target_id }, (const int []){ target_len });
    } else if (strcmp(kind, "policy-publish") == 0) {
        res = db_simple(conn,
            "SELECT (data->>'status'||'|'||data->>'name'||'|'||data->>'version'||'|'||"
            "md5(COALESCE(data->'config','{}'::jsonb)::text)) "
            "FROM console_records WHERE collection='policies' AND record_id=$1 "
            "AND institution_id IS NOT DISTINCT FROM NULLIF($2,'')",
            2, (const char *[]){ target_id, tenant },
            (const int []){ target_len, tenant_len });
    } else if (strcmp(kind, "policy-rollback") == 0) {
        res = db_simple(conn,
            "SELECT (data->>'status'||'|'||data->>'name'||'|'||data->>'version'||'|'||"
            "md5(COALESCE(data->'config','{}'::jsonb)::text)) "
            "FROM console_records WHERE collection='policies' AND record_id=$1 "
            "AND institution_id IS NOT DISTINCT FROM NULLIF($2,'')",
            2, (const char *[]){ target_id, tenant },
            (const int []){ target_len, tenant_len });
    } else if (strcmp(kind, "device-reauth") == 0) {
        res = db_simple(conn,
            "SELECT status FROM devices WHERE id=$1 AND institution_id=$2",
            2, (const char *[]){ target_id, tenant },
            (const int []){ target_len, tenant_len });
    } else if (strcmp(kind, "exam-approve") == 0) {
        res = db_simple(conn,
            "SELECT (state||'|'||policy_version::text||'|'||COALESCE(policy_signature,'')) "
            "FROM examos_exams WHERE exam_id=$1 AND institution_id=$2",
            2, (const char *[]){ target_id, tenant },
            (const int []){ target_len, tenant_len });
    } else if (strcmp(kind, "config-change") == 0) {
        res = db_simple(conn,
            "SELECT md5(COALESCE(data->'value','{}'::jsonb)::text) "
            "FROM console_records WHERE collection='configs' AND record_id=$1",
            1, (const char *[]){ target_id }, (const int []){ target_len });
    } else if (strcmp(kind, "billing-change") == 0) {
        res = db_simple(conn,
            "SELECT (data->>'planId'||'|'||data->>'status'||'|'||"
            "data->>'seats'||'|'||data->>'autoRenew') "
            "FROM console_records WHERE collection='subscriptions' AND record_id=$1 "
            "AND institution_id IS NOT DISTINCT FROM NULLIF($2,'')",
            2, (const char *[]){ target_id, tenant },
            (const int []){ target_len, tenant_len });
    } else if (strcmp(kind, "privacy-deletion") == 0) {
        res = db_simple(conn,
            "SELECT (data->>'status'||'|'||data->>'type'||'|'||data->>'subjectId') "
            "FROM console_records WHERE collection='privacy' AND record_id=$1 "
            "AND institution_id IS NOT DISTINCT FROM NULLIF($2,'')",
            2, (const char *[]){ target_id, tenant },
            (const int []){ target_len, tenant_len });
    } else if (strcmp(kind, "support-recovery") == 0) {
        res = db_simple(conn,
            "SELECT (state||'|'||kind||'|'||target) FROM support_recoveries "
            "WHERE id=$1 AND institution_id IS NOT DISTINCT FROM NULLIF($2,'')",
            2, (const char *[]){ target_id, tenant },
            (const int []){ target_len, tenant_len });
    } else {
        res = db_simple(conn,
            "SELECT md5(data::text) FROM console_records WHERE record_id=$1 "
            "AND institution_id IS NOT DISTINCT FROM NULLIF($2,'')",
            2, (const char *[]){ target_id, tenant },
            (const int []){ target_len, tenant_len });
    }

    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
        if (res) PQclear(res);
        return -1;
    }
    char canonical[16385];
    if (PQntuples(res) == 1 && !PQgetisnull(res, 0, 0)) {
        snprintf(canonical, sizeof(canonical), "%s", PQgetvalue(res, 0, 0));
    } else {
        snprintf(canonical, sizeof(canonical), "absent");
    }
    PQclear(res);

    unsigned char digest[SHA256_DIGEST_LENGTH];
    static const char hex[] = "0123456789abcdef";
    SHA256((const unsigned char *)canonical, strlen(canonical), digest);
    if (out_len < 7 + sizeof(digest) * 2 + 1) return -1;
    memcpy(out, "sha256:", 7);
    for (size_t i = 0; i < sizeof(digest); i++) {
        out[7 + i * 2] = hex[digest[i] >> 4];
        out[7 + i * 2 + 1] = hex[digest[i] & 15];
    }
    out[7 + sizeof(digest) * 2] = '\0';
    return 0;
}

typedef struct {
    char conflicts[8192];
    size_t conflicts_len;
    char warnings[8192];
    size_t warnings_len;
    int blocking_count;
    int warning_count;
} approval_conflict_set;

static void approval_conflict_entry(char *buffer, size_t buffer_len, size_t *used,
                                    const char *code, const char *message) {
    char entry[512];
    snprintf(entry, sizeof(entry),
             "%s{\"code\":\"%s\",\"message\":\"%s\"}",
             *used ? "," : "", code, message);
    size_t entry_len = strlen(entry);
    if (*used + entry_len + 1 >= buffer_len) return;
    memcpy(buffer + *used, entry, entry_len + 1);
    *used += entry_len;
}

static void approval_conflict_add(approval_conflict_set *set, int blocking,
                                  const char *code, const char *message) {
    if (blocking) {
        approval_conflict_entry(set->conflicts, sizeof(set->conflicts),
                                &set->conflicts_len, code, message);
        set->blocking_count++;
    } else {
        approval_conflict_entry(set->warnings, sizeof(set->warnings),
                                &set->warnings_len, code, message);
        set->warning_count++;
    }
}

static int approval_identity_active(PGconn *conn, const char *user_id,
                                    const char *role_name) {
    int role_id = approval_role_id(role_name);
    char role_num[8];
    snprintf(role_num, sizeof(role_num), "%d", role_id);
    const char *canonical = role_id ? approval_role_name(role_id) : role_name;
    const char *alias = role_id ? approval_role_alias((user_role_t)role_id) : role_name;
    const char *params[4] = { user_id, canonical, alias, role_num };
    int lengths[4] = {
        (int)strlen(params[0]), (int)strlen(params[1]),
        (int)strlen(params[2]), (int)strlen(params[3])
    };
    PGresult *res = db_simple(conn,
        "SELECT (EXISTS (SELECT 1 FROM users WHERE id=$1 AND status='active' "
        "AND role IN ($2,$3)) OR EXISTS (SELECT 1 FROM examos_admin_users "
        "WHERE user_id=$1 AND active=TRUE AND role=$4::smallint))::text",
        4, params, lengths);
    int active = res && PQresultStatus(res) == PGRES_TUPLES_OK &&
                 PQntuples(res) == 1 && strcmp(PQgetvalue(res, 0, 0), "true") == 0;
    if (res) PQclear(res);
    return active;
}

/* Collects the full conflict report for one stage.  Authorization failures are
 * also returned as blocking conflicts so a caller can never forget one. */
static int approval_conflicts_evaluate(PGconn *conn, const auth_session_t *actor,
                                       const char *stage, const char *request_id,
                                       const char *policy_key, int policy_version,
                                       int policy_active, const char *requester_id,
                                       const char *tenant_id, const char *target_id,
                                       const char *proposed_data,
                                       const char *stored_fingerprint,
                                       const char *status, long long expires_at,
                                       int required_approvals, int actor_role_allowed,
                                       approval_conflict_set *set,
                                       char *current_fingerprint,
                                       size_t fingerprint_len) {
    memset(set, 0, sizeof(*set));
    if (approval_fingerprint(conn, policy_key, target_id, tenant_id, proposed_data,
                             current_fingerprint, fingerprint_len) != 0)
        return -1;

    if (stored_fingerprint && stored_fingerprint[0] &&
        strcmp(stored_fingerprint, current_fingerprint) != 0)
        approval_conflict_add(set, 1, "RESOURCE_CHANGED",
            "The target resource changed after the request was submitted; a new review is required");

    if (strcmp(stage, "submission") == 0) {
        if (!stored_fingerprint || !stored_fingerprint[0])
            approval_conflict_add(set, 0, "FINGERPRINT_UNAVAILABLE",
                "The target resource did not exist at submission; the request will be rechecked before execution");
    } else {
        if (strcmp(actor->user_id, requester_id) == 0)
            approval_conflict_add(set, 1, "SELF_APPROVAL",
                "The requester cannot approve their own request");
        if (actor->role != ROLE_PLATFORM_OWNER &&
            (!actor->institution_id[0] ||
             strcmp(actor->institution_id, tenant_id ? tenant_id : "") != 0))
            approval_conflict_add(set, 1, "CROSS_TENANT",
                "The actor is outside the institution that owns this request");
        if (!actor_role_allowed && actor->role != ROLE_PLATFORM_OWNER)
            approval_conflict_add(set, 1, "UNAUTHORIZED_APPROVER",
                "The actor's current role is not an authorized approver for this policy");
        if (!policy_active)
            approval_conflict_add(set, 1, "POLICY_INACTIVE",
                "The policy version used by this request is no longer active");
        long long now_ms = (long long)time(NULL) * 1000;
        if (expires_at > 0 && expires_at < now_ms)
            approval_conflict_add(set, 1, "REQUEST_EXPIRED",
                "The approval request has expired");

        const char *expected = strcmp(stage, "decision") == 0
            ? "pending_review" : "execution_pending";
        if (strcmp(status, expected) != 0)
            approval_conflict_add(set, 1, "INVALID_STATE",
                "The request is not in the state required for this action");

        char version_text[16];
        snprintf(version_text, sizeof(version_text), "%d", policy_version);
        const char *dup_params[4] = { policy_key, target_id,
                                      tenant_id ? tenant_id : "", request_id };
        int dup_lengths[4] = {
            (int)strlen(dup_params[0]), (int)strlen(dup_params[1]),
            (int)strlen(dup_params[2]), (int)strlen(dup_params[3])
        };
        PGresult *dup = db_simple(conn,
            "SELECT count(*)::text FROM approval_requests "
            "WHERE policy_key=$1 AND resource_type=$1 AND resource_id=$2 "
            "AND institution_id IS NOT DISTINCT FROM NULLIF($3,'') "
            "AND status IN ('pending_review','approved','execution_pending','executing') "
            "AND id<>$4",
            4, dup_params, dup_lengths);
        if (!dup || PQresultStatus(dup) != PGRES_TUPLES_OK || PQntuples(dup) != 1) {
            if (dup) PQclear(dup);
            return -1;
        }
        int other_open = atoi(PQgetvalue(dup, 0, 0)) > 0;
        PQclear(dup);
        if (other_open)
            approval_conflict_add(set, 1, "DUPLICATE_OPEN_REQUEST",
                "Another open approval request already exists for this resource");

        if (strcmp(stage, "execution") == 0) {
            PGresult *roles = db_simple(conn,
                "SELECT count(DISTINCT actor_role)::text FROM approval_decisions "
                "WHERE request_id=$1 AND decision='approved'",
                1, (const char *[]){ request_id },
                (const int []){ (int)strlen(request_id) });
            if (!roles || PQresultStatus(roles) != PGRES_TUPLES_OK || PQntuples(roles) != 1) {
                if (roles) PQclear(roles);
                return -1;
            }
            int approved_roles = atoi(PQgetvalue(roles, 0, 0));
            PQclear(roles);
            if (approved_roles < required_approvals)
                approval_conflict_add(set, 1, "INSUFFICIENT_APPROVALS",
                    "The number of independent approved roles is below the policy requirement");

            PGresult *decisions = db_simple(conn,
                "SELECT actor_id,actor_role FROM approval_decisions "
                "WHERE request_id=$1 AND decision='approved'",
                1, (const char *[]){ request_id },
                (const int []){ (int)strlen(request_id) });
            if (!decisions || PQresultStatus(decisions) != PGRES_TUPLES_OK) {
                if (decisions) PQclear(decisions);
                return -1;
            }
            int inactive = 0;
            for (int i = 0; i < PQntuples(decisions); i++) {
                if (!approval_identity_active(conn, PQgetvalue(decisions, i, 0),
                                              PQgetvalue(decisions, i, 1)))
                    inactive = 1;
            }
            PQclear(decisions);
            if (inactive)
                approval_conflict_add(set, 1, "APPROVER_INACTIVE",
                    "At least one approver is no longer active or no longer holds the approving role");
        }
        (void)version_text;
    }
    return 0;
}

static const char *approval_conflict_result(const approval_conflict_set *set) {
    if (set->blocking_count > 0) return "BLOCKED";
    if (set->warning_count > 0) return "WARNING";
    return "CLEAR";
}

static int approval_record_conflict(PGconn *conn, const auth_session_t *actor,
                                    const char *request_id, int policy_version,
                                    const char *stage, const char *stored_fingerprint,
                                    const char *current_fingerprint,
                                    const approval_conflict_set *set,
                                    const char *result, char *detail_out,
                                    size_t detail_len) {
    char detail[17408];
    snprintf(detail, sizeof(detail),
        "{\"result\":\"%s\",\"stage\":\"%s\",\"policyVersion\":%d,"
        "\"storedFingerprint\":\"%s\",\"resourceFingerprint\":\"%s\","
        "\"blockingCount\":%d,\"warningCount\":%d,"
        "\"conflicts\":[%s],\"warnings\":[%s]}",
        result, stage, policy_version,
        stored_fingerprint ? stored_fingerprint : "",
        current_fingerprint ? current_fingerprint : "",
        set->blocking_count, set->warning_count,
        set->conflicts, set->warnings);
    if (detail_out && detail_len) snprintf(detail_out, detail_len, "%s", detail);

    char conflict_id[64];
    if (approval_id(conflict_id, sizeof(conflict_id), "apc_") != 0) return -1;
    char version_text[16], blocking_text[16];
    snprintf(version_text, sizeof(version_text), "%d", policy_version);
    snprintf(blocking_text, sizeof(blocking_text), "%d", set->blocking_count);
    const char *params[13] = {
        conflict_id, request_id, stage, result, version_text, actor->user_id,
        actor->username, security_role_to_string(actor->role),
        set->conflicts_len ? set->conflicts : "[]",
        set->warnings_len ? set->warnings : "[]",
        blocking_text, current_fingerprint ? current_fingerprint : "",
        detail
    };
    int lengths[13];
    for (int i = 0; i < 13; i++) lengths[i] = (int)strlen(params[i]);
    PGresult *insert = db_simple(conn,
        "INSERT INTO approval_conflicts "
        "(id,request_id,check_stage,result,policy_version,checked_by,checked_by_name,"
        "checked_by_role,conflicts,warnings,blocking_count,resource_fingerprint) "
        "VALUES ($1,$2,$3,$4,$5::int,$6,$7,$8,$9::jsonb,$10::jsonb,$11::smallint,$12)",
        12, params, lengths);
    if (!insert || PQresultStatus(insert) != PGRES_COMMAND_OK) {
        if (insert) PQclear(insert);
        return -1;
    }
    PQclear(insert);

    const char *update_params[3] = { request_id, result, detail };
    const int update_lengths[3] = {
        (int)strlen(request_id), (int)strlen(result), (int)strlen(detail)
    };
    PGresult *update = db_simple(conn,
        "UPDATE approval_requests SET conflict_status=$2,conflict_detail=$3::jsonb,"
        "updated_at=(EXTRACT(EPOCH FROM clock_timestamp())*1000)::bigint WHERE id=$1",
        3, update_params, update_lengths);
    int ok = update && PQresultStatus(update) == PGRES_COMMAND_OK;
    if (update) PQclear(update);
    return ok ? 0 : -1;
}

static int approval_record_execution(PGconn *conn, const auth_session_t *actor,
                                     const char *request_id, const char *operation,
                                     const char *result, const char *detail,
                                     const char *reason) {
    char execution_id[64];
    if (approval_id(execution_id, sizeof(execution_id), "apx_") != 0) return -1;
    const char *params[9] = {
        execution_id, request_id, actor->user_id, actor->username,
        security_role_to_string(actor->role), operation, result,
        detail ? detail : "{}", reason ? reason : ""
    };
    int lengths[9];
    for (int i = 0; i < 9; i++) lengths[i] = (int)strlen(params[i]);
    PGresult *res = db_simple(conn,
        "INSERT INTO approval_executions "
        "(id,request_id,actor_id,actor_name,actor_role,operation,result,detail,reason) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9)",
        9, params, lengths);
    int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
    if (res) PQclear(res);
    return ok ? 0 : -1;
}

static int approval_policy_publish_target_valid(PGconn *conn, const char *target_id,
                                                const char *tenant_id,
                                                const char *proposed_data) {
    const char *params[3] = { target_id, tenant_id, proposed_data };
    const int lengths[3] = {
        (int)strlen(target_id), (int)strlen(tenant_id), (int)strlen(proposed_data)
    };
    PGresult *res = db_simple(conn,
        "SELECT EXISTS (SELECT 1 FROM console_records p "
        "WHERE p.collection='policies' AND p.record_id=$1 AND p.institution_id=$2 "
        "AND p.data->>'id'=$1 AND p.data->>'tenantId'=$2 AND p.data->>'status'='draft' "
        "AND (p.data->>'name')=($3::jsonb->>'policyName') "
        "AND (p.data->>'version')=($3::jsonb->>'policyVersion') "
        "AND (p.data->'config')=($3::jsonb->'config') "
        "AND ($3::jsonb->>'policyId')=$1 "
        "AND COALESCE(($3::jsonb->>'replacesPolicyId'),'') = COALESCE(("
        "SELECT live.record_id FROM console_records live "
        "WHERE live.collection='policies' AND live.institution_id=$2 "
        "AND live.data->>'tenantId'=$2 AND live.data->>'name'=p.data->>'name' "
        "AND live.data->>'status'='published' "
        "ORDER BY CASE WHEN live.data->>'version' ~ '^[0-9]+$' "
        "THEN (live.data->>'version')::numeric ELSE -1 END DESC LIMIT 1),'')"
        ")::text",
        3, params, lengths);
    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) != 1) {
        if (res) PQclear(res);
        return -1;
    }
    int valid = strcmp(PQgetvalue(res, 0, 0), "true") == 0;
    PQclear(res);
    return valid;
}

static int approval_sign_policy_payload(const char *canonical_config,
                                        char *out_digest_hex, size_t digest_len,
                                        char *out_sig_hex, size_t sig_len,
                                        char *out_alg, size_t alg_len) {
    static const char hex[] = "0123456789abcdef";
    unsigned char hash[SHA256_DIGEST_LENGTH];
    if (!canonical_config || digest_len < 65 || sig_len < 65 || alg_len < 32)
        return -1;
    SHA256((const unsigned char *)canonical_config, strlen(canonical_config), hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        out_digest_hex[i * 2] = hex[hash[i] >> 4];
        out_digest_hex[i * 2 + 1] = hex[hash[i] & 15];
    }
    out_digest_hex[SHA256_DIGEST_LENGTH * 2] = '\0';

    const char *secret = getenv("EXAMOS_POLICY_SIGNING_SECRET");
    if (!secret || !secret[0]) secret = getenv("EXAMOS_JWT_SECRET");
    if (!secret || !secret[0]) secret = "examos-policy-signing-key-v1";

    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int mac_len = 0;
    if (!HMAC(EVP_sha256(), secret, (int)strlen(secret),
              (const unsigned char *)out_digest_hex, strlen(out_digest_hex),
              mac, &mac_len) || mac_len != 32) {
        return -1;
    }
    for (unsigned int i = 0; i < mac_len; i++) {
        out_sig_hex[i * 2] = hex[mac[i] >> 4];
        out_sig_hex[i * 2 + 1] = hex[mac[i] & 15];
    }
    out_sig_hex[mac_len * 2] = '\0';
    snprintf(out_alg, alg_len, "hmac-sha256");
    return 0;
}

static int approval_policy_rollback_target_valid(PGconn *conn, const char *target_id,
                                                 const char *tenant_id) {
    const char *params[2] = { target_id, tenant_id ? tenant_id : "" };
    const int lengths[2] = { (int)strlen(params[0]), (int)strlen(params[1]) };
    PGresult *res = db_simple(conn,
        "SELECT EXISTS (SELECT 1 FROM console_records p "
        "WHERE p.collection='policies' AND p.record_id=$1 "
        "AND p.institution_id IS NOT DISTINCT FROM NULLIF($2,'') "
        "AND p.data->>'status'='superseded')::text",
        2, params, lengths);
    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) != 1) {
        if (res) PQclear(res);
        return -1;
    }
    int valid = strcmp(PQgetvalue(res, 0, 0), "true") == 0;
    PQclear(res);
    return valid;
}

static int approval_execute_policy_publish(PGconn *conn, const char *target_id,
                                           const char *tenant_id,
                                           const char *approver_name,
                                           const char *proposed_data) {
    if (approval_policy_publish_target_valid(conn, target_id, tenant_id,
                                             proposed_data) != 1)
        return -1;

    const char *cfg_params[2] = { target_id, tenant_id ? tenant_id : "" };
    const int cfg_lengths[2] = { (int)strlen(cfg_params[0]), (int)strlen(cfg_params[1]) };
    PGresult *cfg_res = db_simple(conn,
        "SELECT data->>'name', (data->'config')::text FROM console_records "
        "WHERE collection='policies' AND record_id=$1 "
        "AND institution_id IS NOT DISTINCT FROM NULLIF($2,'') FOR UPDATE",
        2, cfg_params, cfg_lengths);
    if (!cfg_res || PQresultStatus(cfg_res) != PGRES_TUPLES_OK || PQntuples(cfg_res) != 1) {
        if (cfg_res) PQclear(cfg_res);
        return -1;
    }
    char policy_name[128] = {0};
    char canonical_config[16384] = {0};
    snprintf(policy_name, sizeof(policy_name), "%s", PQgetvalue(cfg_res, 0, 0));
    snprintf(canonical_config, sizeof(canonical_config), "%s", PQgetvalue(cfg_res, 0, 1));
    PQclear(cfg_res);

    char digest_hex[65] = {0}, sig_hex[65] = {0}, sig_alg[32] = {0};
    if (approval_sign_policy_payload(canonical_config, digest_hex, sizeof(digest_hex),
                                     sig_hex, sizeof(sig_hex), sig_alg, sizeof(sig_alg)) != 0)
        return -1;

    const char *sup_params[4] = { tenant_id ? tenant_id : "", policy_name, target_id, approver_name };
    const int sup_lengths[4] = {
        (int)strlen(sup_params[0]), (int)strlen(sup_params[1]),
        (int)strlen(sup_params[2]), (int)strlen(sup_params[3])
    };
    PGresult *sup = db_simple(conn,
        "UPDATE console_records "
        "SET data = jsonb_set(data, '{status}', '\"superseded\"'::jsonb), "
        "updated_by = $4, updated_at = (EXTRACT(EPOCH FROM clock_timestamp())*1000)::bigint "
        "WHERE collection='policies' "
        "AND institution_id IS NOT DISTINCT FROM NULLIF($1,'') "
        "AND data->>'name'=$2 AND data->>'status'='published' AND record_id<>$3",
        4, sup_params, sup_lengths);
    if (!sup || PQresultStatus(sup) != PGRES_COMMAND_OK) {
        if (sup) PQclear(sup);
        return -1;
    }
    PQclear(sup);

    const char *pub_params[6] = {
        target_id, tenant_id ? tenant_id : "", approver_name,
        digest_hex, sig_hex, sig_alg
    };
    const int pub_lengths[6] = {
        (int)strlen(pub_params[0]), (int)strlen(pub_params[1]),
        (int)strlen(pub_params[2]), (int)strlen(pub_params[3]),
        (int)strlen(pub_params[4]), (int)strlen(pub_params[5])
    };
    PGresult *pub = db_simple(conn,
        "UPDATE console_records "
        "SET data = data || jsonb_build_object("
        "'status','published',"
        "'publishedAt',(EXTRACT(EPOCH FROM clock_timestamp())*1000)::bigint,"
        "'publishedBy',$3::text,"
        "'configDigest',$4::text,"
        "'signature',$5::text,"
        "'signatureAlgorithm',$6::text,"
        "'signatureStatus','verified'), "
        "updated_by = $3, updated_at = (EXTRACT(EPOCH FROM clock_timestamp())*1000)::bigint "
        "WHERE collection='policies' AND record_id=$1 "
        "AND institution_id IS NOT DISTINCT FROM NULLIF($2,'') "
        "AND data->>'status'='draft'",
        6, pub_params, pub_lengths);
    if (!pub || PQresultStatus(pub) != PGRES_COMMAND_OK ||
        strcmp(PQcmdTuples(pub), "1") != 0) {
        if (pub) PQclear(pub);
        return -1;
    }
    PQclear(pub);
    return 0;
}

static int approval_execute_policy_rollback(PGconn *conn, const char *target_id,
                                            const char *tenant_id,
                                            const char *approver_name) {
    if (approval_policy_rollback_target_valid(conn, target_id, tenant_id) != 1)
        return -1;

    const char *src_params[2] = { target_id, tenant_id ? tenant_id : "" };
    const int src_lengths[2] = { (int)strlen(src_params[0]), (int)strlen(src_params[1]) };
    PGresult *src = db_simple(conn,
        "SELECT data->>'name', (data->>'version')::int, (data->'config')::text "
        "FROM console_records WHERE collection='policies' AND record_id=$1 "
        "AND institution_id IS NOT DISTINCT FROM NULLIF($2,'') AND data->>'status'='superseded'",
        2, src_params, src_lengths);
    if (!src || PQresultStatus(src) != PGRES_TUPLES_OK || PQntuples(src) != 1) {
        if (src) PQclear(src);
        return -1;
    }
    char policy_name[128] = {0};
    char target_ver_text[16] = {0};
    char canonical_config[16384] = {0};
    snprintf(policy_name, sizeof(policy_name), "%s", PQgetvalue(src, 0, 0));
    snprintf(target_ver_text, sizeof(target_ver_text), "%s", PQgetvalue(src, 0, 1));
    snprintf(canonical_config, sizeof(canonical_config), "%s", PQgetvalue(src, 0, 2));
    PQclear(src);

    char digest_hex[65] = {0}, sig_hex[65] = {0}, sig_alg[32] = {0};
    if (approval_sign_policy_payload(canonical_config, digest_hex, sizeof(digest_hex),
                                     sig_hex, sizeof(sig_hex), sig_alg, sizeof(sig_alg)) != 0)
        return -1;

    char new_id[64];
    if (approval_id(new_id, sizeof(new_id), "pol_") != 0)
        return -1;

    const char *sup_params[3] = { tenant_id ? tenant_id : "", policy_name, approver_name };
    const int sup_lengths[3] = {
        (int)strlen(sup_params[0]), (int)strlen(sup_params[1]), (int)strlen(sup_params[2])
    };
    PGresult *sup = db_simple(conn,
        "UPDATE console_records "
        "SET data = jsonb_set(data, '{status}', '\"superseded\"'::jsonb), "
        "updated_by = $3, updated_at = (EXTRACT(EPOCH FROM clock_timestamp())*1000)::bigint "
        "WHERE collection='policies' "
        "AND institution_id IS NOT DISTINCT FROM NULLIF($1,'') "
        "AND data->>'name'=$2 AND data->>'status'='published'",
        3, sup_params, sup_lengths);
    if (!sup || PQresultStatus(sup) != PGRES_COMMAND_OK) {
        if (sup) PQclear(sup);
        return -1;
    }
    PQclear(sup);

    const char *ins_params[8] = {
        new_id, tenant_id ? tenant_id : "", policy_name, target_ver_text,
        canonical_config, approver_name, digest_hex, sig_hex
    };
    int ins_lengths[8];
    for (int i = 0; i < 8; i++) ins_lengths[i] = (int)strlen(ins_params[i]);
    PGresult *ins = db_simple(conn,
        "INSERT INTO console_records "
        "(collection,record_id,institution_id,data,created_by,updated_by,created_at,updated_at) "
        "SELECT 'policies',$1,NULLIF($2,''),"
        "jsonb_build_object("
        "'id',$1,'tenantId',NULLIF($2,''),'name',$3,"
        "'version',COALESCE((SELECT MAX((data->>'version')::int) FROM console_records "
        "WHERE collection='policies' AND institution_id IS NOT DISTINCT FROM NULLIF($2,'') "
        "AND data->>'name'=$3 AND (data->>'version') ~ '^[0-9]+$'),0)+1,"
        "'status','published','rolledBackFrom',$4::int,"
        "'createdBy',$6,'createdAt',(EXTRACT(EPOCH FROM clock_timestamp())*1000)::bigint,"
        "'publishedBy',$6,'publishedAt',(EXTRACT(EPOCH FROM clock_timestamp())*1000)::bigint,"
        "'config',$5::jsonb,'configDigest',$7,'signature',$8,"
        "'signatureAlgorithm','hmac-sha256','signatureStatus','verified'),"
        "$6,$6,(EXTRACT(EPOCH FROM clock_timestamp())*1000)::bigint,"
        "(EXTRACT(EPOCH FROM clock_timestamp())*1000)::bigint",
        8, ins_params, ins_lengths);
    if (!ins || PQresultStatus(ins) != PGRES_COMMAND_OK) {
        if (ins) PQclear(ins);
        return -1;
    }
    PQclear(ins);
    return 0;
}

static int approval_event(PGconn *conn, const char *request_id, const auth_session_t *actor,
                          const char *event_type, const char *reason, const char *details) {
    char event_id[64];
    if (approval_id(event_id, sizeof(event_id), "ape_") != 0) return -1;
    const char *params[7] = {
        event_id, request_id, event_type, actor->user_id, actor->username,
        security_role_to_string(actor->role), reason ? reason : ""
    };
    int lengths[7];
    for (int i = 0; i < 7; i++) lengths[i] = (int)strlen(params[i]);
    PGresult *res = db_simple(conn,
        "INSERT INTO approval_events "
        "(id,request_id,event_type,actor_id,actor_name,actor_role,reason,details) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb)",
        8, (const char *[]){ params[0], params[1], params[2], params[3], params[4],
                             params[5], params[6], details ? details : "{}" },
        (const int []){ lengths[0], lengths[1], lengths[2], lengths[3], lengths[4],
                        lengths[5], lengths[6], (int)strlen(details ? details : "{}") });
    int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
    if (res) PQclear(res);
    return ok ? 0 : -1;
}

static int approval_insert_notification(PGconn *conn, const char *tenant_id,
                                        const char *user_id, const char *role,
                                        const char *title, const char *body,
                                        const char *created_by) {
    char notification_id[64];
    if (approval_id(notification_id, sizeof(notification_id), "ntf_") != 0) return -1;
    const char *params[8] = {
        notification_id, tenant_id ? tenant_id : "", user_id ? user_id : "",
        role ? role : "", title, body, created_by, "/admin/approvals"
    };
    int lengths[8];
    for (int i = 0; i < 8; i++) lengths[i] = (int)strlen(params[i]);
    PGresult *res = db_simple(conn,
        "INSERT INTO console_records "
        "(collection,record_id,institution_id,data,created_by,updated_by,created_at,updated_at) "
        "VALUES ('notifications',$1,NULLIF($2,''),"
        "jsonb_build_object('id',$1,'tenantId',NULLIF($2,''),'userId',NULLIF($3,''),"
        "'role',NULLIF($4,''),'title',$5,'body',$6,'link',$8,'tone','info',"
        "'channel','in-app','kind','approval','readBy','[]'::jsonb,"
        "'archivedBy','[]'::jsonb,'createdAt',(EXTRACT(EPOCH FROM clock_timestamp())*1000)::bigint,"
        "'createdBy',$7),$7,$7,(EXTRACT(EPOCH FROM clock_timestamp())*1000)::bigint,"
        "(EXTRACT(EPOCH FROM clock_timestamp())*1000)::bigint) "
        "ON CONFLICT (collection,record_id) DO NOTHING",
        8, params, lengths);
    int ok = res && PQresultStatus(res) == PGRES_COMMAND_OK &&
             strcmp(PQcmdTuples(res), "1") == 0;
    if (res) PQclear(res);
    return ok ? 0 : -1;
}

static int approval_notify_approvers(PGconn *conn, const char *request_id,
                                     const auth_session_t *actor, const char *kind,
                                     int policy_version, const char *tenant_id,
                                     const char *label, const char *created_by,
                                     const char *notification_verb) {
    char version_text[16], title[141];
    const char *notification_body = strcmp(notification_verb, "Request withdrawn") == 0
        ? "This approval request was withdrawn and no longer needs review."
        : "An approval request is awaiting your review.";
    snprintf(version_text, sizeof(version_text), "%d", policy_version);
    snprintf(title, sizeof(title), "%.18s: %.120s", notification_verb, label);
    const char *params[2] = { kind, version_text };
    const int lengths[2] = { (int)strlen(kind), (int)strlen(version_text) };
    PGresult *roles = db_simple(conn,
        "SELECT DISTINCT role_name FROM approval_policies p "
        "CROSS JOIN LATERAL unnest(p.approver_roles) configured(role_id) "
        "JOIN (VALUES (1,'superadmin'),(2,'inst_admin'),(3,'exam_controller'),"
        "(4,'security_engineer'),(5,'invigilator'),(6,'ops_admin'),"
        "(7,'incident_investigator'),(8,'auditor'),(9,'support')) "
        "AS role_map(role_id,role_name) ON role_map.role_id=configured.role_id "
        "WHERE p.policy_key=$1 AND p.version=$2::integer",
        2, params, lengths);
    if (!roles || PQresultStatus(roles) != PGRES_TUPLES_OK) {
        if (roles) PQclear(roles);
        return -1;
    }
    int ok = PQntuples(roles) > 0;
    for (int i = 0; ok && i < PQntuples(roles); i++) {
        ok = approval_insert_notification(conn, tenant_id, NULL,
                PQgetvalue(roles, i, 0), title,
                notification_body, created_by) == 0;
    }
    PQclear(roles);
    if (ok) {
        const char *event_type = strcmp(notification_verb, "Request withdrawn") == 0
            ? "REQUEST_WITHDRAWAL_NOTICE_SENT" : "APPROVERS_NOTIFIED";
        ok = approval_event(conn, request_id, actor, event_type, "",
                            "{\"channel\":\"in-app\",\"delivery\":\"persisted\"}") == 0;
    }
    return ok ? 0 : -1;
}

static PGresult *approval_list(PGconn *conn, const auth_session_t *actor,
                               const char *request_id) {
    char role_num[8];
    snprintf(role_num, sizeof(role_num), "%d", (int)actor->role);
    const char *params[5] = { actor->user_id, actor->institution_id,
                              request_id ? request_id : "", role_num,
                              actor->role == ROLE_PLATFORM_OWNER ? "true" : "false" };
    int lengths[5];
    for (int i = 0; i < 5; i++) lengths[i] = (int)strlen(params[i]);
    const char *sql =
        "SELECT COALESCE(jsonb_agg(q.document ORDER BY q.created_at DESC),'[]'::jsonb)::text "
        "FROM (SELECT r.created_at, jsonb_build_object("
        "'id',r.id,'kind',r.policy_key,'label',r.label,'targetId',r.resource_id,"
        "'resourceType',r.resource_type,'tenantId',r.institution_id,"
        "'requestedBy',r.requester_id,'requesterName',r.requester_name,"
        "'requesterRole',r.requester_role,'reason',r.reason,'data',r.proposed_data,"
        "'status',r.status,'createdAt',r.created_at,'expiresAt',r.expires_at,"
        "'riskLevel',r.risk_level,'policyVersion',r.policy_version,"
        "'requiredApprovals',r.required_approvals,'conflictStatus',r.conflict_status,"
        "'executionStatus',r.execution_status,"
        "'approvalCount',(SELECT count(*) FROM approval_decisions d "
        "WHERE d.request_id=r.id AND d.decision='approved'),"
        "'decisions',COALESCE((SELECT jsonb_agg(jsonb_build_object("
        "'actorId',d.actor_id,'actorName',d.actor_name,'actorRole',d.actor_role,"
        "'decision',d.decision,'reason',d.reason,'occurredAt',d.occurred_at) "
        "ORDER BY d.occurred_at) FROM approval_decisions d WHERE d.request_id=r.id),'[]'::jsonb),"
        "'events',COALESCE((SELECT jsonb_agg(jsonb_build_object("
        "'eventType',e.event_type,'actorId',e.actor_id,'actorName',e.actor_name,"
        "'actorRole',e.actor_role,'reason',e.reason,'details',e.details,"
        "'occurredAt',e.occurred_at) ORDER BY e.occurred_at) "
        "FROM approval_events e WHERE e.request_id=r.id),'[]'::jsonb)) AS document "
        "FROM approval_requests r JOIN approval_policies p "
        "ON p.policy_key=r.policy_key AND p.version=r.policy_version "
        "WHERE ($3='' OR r.id=$3) AND (r.requester_id=$1 OR $5::boolean OR "
        "(p.approver_roles @> ARRAY[$4::smallint] "
        "AND r.institution_id IS NOT DISTINCT FROM NULLIF($2,''))) "
        "ORDER BY r.created_at DESC LIMIT 100) q";
    return db_simple(conn, sql, 5, params, lengths);
}

static void approvals_get(int fd, const auth_session_t *actor, const char *request_id,
                          const char *origin, char *extra, size_t extra_len) {
    PGconn *conn = db_acquire();
    if (!conn) {
        approval_error(fd, 503, "Approval database is unavailable", origin, extra, extra_len);
        return;
    }
    PGresult *res = approval_list(conn, actor, request_id);
    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) != 1) {
        if (res) PQclear(res);
        db_release(conn, 0);
        approval_error(fd, 503, "Approval records could not be loaded", origin, extra, extra_len);
        return;
    }
    const char *json = PQgetvalue(res, 0, 0);
    char response[131072];
    size_t json_len = strlen(json);
    if (json_len >= sizeof(response)) {
        PQclear(res);
        db_release(conn, 0);
        approval_error(fd, 413, "Approval history response exceeds the supported size", origin, extra, extra_len);
        return;
    }
    memcpy(response, json, json_len + 1);
    PQclear(res);
    db_release(conn, 0);
    approval_send(fd, 200, response, origin, extra, extra_len);
}

static void approvals_create(int fd, const char *body, const auth_session_t *actor,
                             const char *origin, char *extra, size_t extra_len) {
    char kind[65] = {0}, label[141] = {0}, target_id[129] = {0};
    char requested_tenant[65] = {0}, reason[1025] = {0}, data_json[16385] = "{}";
    ctrl_json_string(body, "kind", kind, sizeof(kind));
    ctrl_json_string(body, "label", label, sizeof(label));
    ctrl_json_string(body, "target_id", target_id, sizeof(target_id));
    ctrl_json_string(body, "tenant_id", requested_tenant, sizeof(requested_tenant));
    ctrl_json_string(body, "reason", reason, sizeof(reason));
    if (!ctrl_json_string(body, "data_json", data_json, sizeof(data_json))) {
        snprintf(data_json, sizeof(data_json), "{}");
    }
    if (!kind[0] || !label[0] || !approval_safe_id(target_id) || strlen(reason) < 8 ||
        strlen(data_json) > 16000) {
        approval_error(fd, 400, "A supported operation, target, label, and reason of at least 8 characters are required",
                       origin, extra, extra_len);
        return;
    }

    char tenant[65] = {0};
    if (actor->role == ROLE_PLATFORM_OWNER) {
        snprintf(tenant, sizeof(tenant), "%s", requested_tenant);
    } else {
        if (!actor->institution_id[0] ||
            (requested_tenant[0] && strcmp(requested_tenant, actor->institution_id) != 0)) {
            approval_error(fd, 403, "Approval request is outside the authenticated institution",
                           origin, extra, extra_len);
            return;
        }
        snprintf(tenant, sizeof(tenant), "%s", actor->institution_id);
    }

    PGconn *conn = db_acquire();
    if (!conn) {
        approval_error(fd, 503, "Approval database is unavailable", origin, extra, extra_len);
        return;
    }
    if (!approval_actor_active(conn, actor)) {
        db_release(conn, 0);
        approval_error(fd, 403, "Active user account required", origin, extra, extra_len);
        return;
    }

    const char *policy_params[1] = { kind };
    int policy_lengths[1] = { (int)strlen(kind) };
    PGresult *policy = db_simple(conn,
        "SELECT version,requester_permission,required_approvals,risk_level,minimum_reason_length "
        "FROM approval_policies WHERE policy_key=$1 AND active=TRUE FOR SHARE",
        1, policy_params, policy_lengths);
    if (!policy || PQresultStatus(policy) != PGRES_TUPLES_OK || PQntuples(policy) != 1) {
        if (policy) PQclear(policy);
        db_release(conn, 0);
        approval_error(fd, 400, "No active approval policy exists for this operation",
                       origin, extra, extra_len);
        return;
    }
    int policy_version = atoi(PQgetvalue(policy, 0, 0));
    uint32_t required_permission = (uint32_t)strtoul(PQgetvalue(policy, 0, 1), NULL, 10);
    int required_approvals = atoi(PQgetvalue(policy, 0, 2));
    char risk_level[17] = {0};
    snprintf(risk_level, sizeof(risk_level), "%s", PQgetvalue(policy, 0, 3));
    int reason_minimum = atoi(PQgetvalue(policy, 0, 4));
    PQclear(policy);
    int requester_authorized = security_role_has_permission(actor->role, required_permission);
    if (strcmp(kind, "policy-publish") == 0) {
        requester_authorized =
            security_role_has_permission(actor->role, AUTH_PERM_SECURITY_ADMIN) ||
            security_role_has_permission(actor->role, AUTH_PERM_EXAM_MUTATION) ||
            security_role_has_permission(actor->role, AUTH_PERM_FLEET_MUTATION);
    }
    if (!requester_authorized) {
        db_release(conn, 0);
        approval_error(fd, 403, "The authenticated role cannot request this operation",
                       origin, extra, extra_len);
        return;
    }
    if (strcmp(kind, "role-change") == 0) {
        char canonical_id[129] = {0};
        int requested_role_id = 0;
        int target_valid = approval_role_change_target(
            conn, target_id, tenant, data_json, actor->user_id, actor->role,
            canonical_id, sizeof(canonical_id), &requested_role_id);
        if (target_valid != 1) {
            db_release(conn, 0);
            approval_error(fd, target_valid < 0 ? 503 : 409,
                           target_valid < 0
                               ? "Role-change target could not be verified"
                               : "Role-change request is invalid, out of scope, or exceeds your authority",
                           origin, extra, extra_len);
            return;
        }
        (void)requested_role_id;
        snprintf(target_id, sizeof(target_id), "%s", canonical_id);
    }
    if (strcmp(kind, "release-approve") == 0) {
        int target_valid = approval_release_target_valid(
            conn, target_id, actor->user_id, actor->username,
            NULL, NULL, data_json);
        if (target_valid != 1) {
            db_release(conn, 0);
            approval_error(fd, target_valid < 0 ? 503 : 409,
                           target_valid < 0
                               ? "Release approval target could not be verified"
                               : "Release approval requires a signed, verified release with a matching manifest digest and an independent reviewer",
                           origin, extra, extra_len);
            return;
        }
    }
    if (strcmp(kind, "device-reauth") == 0) {
        int target_valid = tenant[0]
            ? approval_device_reauth_target_valid(conn, target_id, tenant) : 0;
        if (target_valid != 1) {
            db_release(conn, 0);
            approval_error(fd, target_valid < 0 ? 503 : 409,
                           target_valid < 0
                               ? "Device reauthorization target could not be verified"
                               : "Device reauthorization requires a revoked device in the authenticated institution",
                           origin, extra, extra_len);
            return;
        }
    }
    if ((int)strlen(reason) < reason_minimum) {
        db_release(conn, 0);
        approval_error(fd, 400, "The request reason does not meet the active policy minimum",
                       origin, extra, extra_len);
        return;
    }
    if (tenant[0]) {
        int tenant_lengths[1] = { (int)strlen(tenant) };
        PGresult *tenant_res = db_simple(conn,
                                         "SELECT EXISTS(SELECT 1 FROM tenants WHERE id=$1)::text",
                                         2, (const char *[]){ tenant, kind },
                                         (const int []){ tenant_lengths[0], (int)strlen(kind) });
        int tenant_exists = tenant_res && PQresultStatus(tenant_res) == PGRES_TUPLES_OK &&
                            PQntuples(tenant_res) == 1 &&
                            strcmp(PQgetvalue(tenant_res, 0, 0), "true") == 0;
        if (tenant_res) PQclear(tenant_res);
        if (!tenant_exists) {
            db_release(conn, 0);
            approval_error(fd, 400, "Institution does not exist", origin, extra, extra_len);
            return;
        }
    }
    if (strcmp(kind, "policy-publish") == 0) {
        int target_valid = tenant[0]
            ? approval_policy_publish_target_valid(conn, target_id, tenant, data_json) : 0;
        if (target_valid != 1) {
            db_release(conn, 0);
            approval_error(fd, target_valid < 0 ? 503 : 409,
                           target_valid < 0
                               ? "Policy publication target could not be verified"
                               : "Policy publication request does not match the current draft",
                           origin, extra, extra_len);
            return;
        }
    }
    if (strcmp(kind, "policy-rollback") == 0) {
        int target_valid = tenant[0]
            ? approval_policy_rollback_target_valid(conn, target_id, tenant) : 0;
        if (target_valid != 1) {
            db_release(conn, 0);
            approval_error(fd, target_valid < 0 ? 503 : 409,
                           target_valid < 0
                               ? "Policy rollback target could not be verified"
                               : "Policy rollback requires a previously published (superseded) version",
                           origin, extra, extra_len);
            return;
        }
    }

    char request_id[64];
    if (approval_id(request_id, sizeof(request_id), "apr_") != 0) {
        db_release(conn, 0);
        approval_error(fd, 500, "Could not generate an approval request identifier",
                       origin, extra, extra_len);
        return;
    }
    PGresult *begin = PQexec(conn, "BEGIN");
    if (!begin || PQresultStatus(begin) != PGRES_COMMAND_OK) {
        if (begin) PQclear(begin);
        db_release(conn, 0);
        approval_error(fd, 503, "Could not start approval transaction", origin, extra, extra_len);
        return;
    }
    PQclear(begin);
    char version_text[16], required_text[16];
    snprintf(version_text, sizeof(version_text), "%d", policy_version);
    snprintf(required_text, sizeof(required_text), "%d", required_approvals);
    const char *params[14] = {
        request_id, kind, version_text, kind, target_id, tenant, label, reason,
        data_json, actor->user_id, actor->username, security_role_to_string(actor->role),
        risk_level, required_text
    };
    int lengths[14];
    for (int i = 0; i < 14; i++) lengths[i] = (int)strlen(params[i]);
    PGresult *insert = db_simple(conn,
        "INSERT INTO approval_requests "
        "(id,policy_key,policy_version,resource_type,resource_id,institution_id,label,reason,"
        "proposed_data,requester_id,requester_name,requester_role,risk_level,status,"
        "conflict_status,required_approvals,execution_status) "
        "VALUES ($1,$2,$3::int,$4,$5,NULLIF($6,''),$7,$8,$9::jsonb,$10,$11,$12,$13,"
        "'pending_review','WARNING',$14::smallint,'not_started') "
        "ON CONFLICT DO NOTHING RETURNING id",
        14, params, lengths);
    if (!insert || PQresultStatus(insert) != PGRES_TUPLES_OK || PQntuples(insert) != 1) {
        if (insert) PQclear(insert);
        PQexec(conn, "ROLLBACK");
        db_release(conn, 0);
        approval_error(fd, 409, "A matching approval request is already open or the request data is invalid",
                       origin, extra, extra_len);
        return;
    }
    PQclear(insert);
    if (approval_event(conn, request_id, actor, "REQUEST_SUBMITTED", reason,
                       "{\"conflictStatus\":\"WARNING\",\"resourceStateRevalidation\":\"unavailable\"}") != 0 ||
        approval_event(conn, request_id, actor, "CONFLICT_CHECKED", "",
                       "{\"result\":\"WARNING\",\"blockingConflicts\":0,\"resourceStateRevalidated\":false}") != 0 ||
        approval_notify_approvers(conn, request_id, actor, kind, policy_version,
                                  tenant, label, actor->user_id,
                                  "Review requested") != 0) {
        PQexec(conn, "ROLLBACK");
        db_release(conn, 0);
        approval_error(fd, 503, "Request history or approver notifications could not be persisted",
                       origin, extra, extra_len);
        return;
    }
    PGresult *commit = PQexec(conn, "COMMIT");
    if (!commit || PQresultStatus(commit) != PGRES_COMMAND_OK) {
        if (commit) PQclear(commit);
        PQexec(conn, "ROLLBACK");
        db_release(conn, 0);
        approval_error(fd, 503, "Approval request transaction could not commit", origin, extra, extra_len);
        return;
    }
    PQclear(commit);
    audit_append(actor->user_id, "APPROVAL_REQUEST_SUBMITTED", request_id);
    db_release(conn, 0);
    char response[256], escaped_id[96];
    ctrl_json_escape(request_id, escaped_id, sizeof(escaped_id));
    snprintf(response, sizeof(response),
             "{\"id\":\"%s\",\"status\":\"pending_review\",\"conflict_status\":\"WARNING\","
             "\"execution_status\":\"not_started\",\"message\":\"Submitted; resource revalidation is not available.\"}",
             escaped_id);
    approval_send(fd, 201, response, origin, extra, extra_len);
}

static void approvals_decide(int fd, const char *request_id, const char *body,
                             const auth_session_t *actor, const char *origin,
                             char *extra, size_t extra_len) {
    char decision[32] = {0}, reason[1025] = {0};
    ctrl_json_string(body, "decision", decision, sizeof(decision));
    ctrl_json_string(body, "reason", reason, sizeof(reason));
    if (!((strcmp(decision, "approved") == 0) || (strcmp(decision, "rejected") == 0) ||
          (strcmp(decision, "changes_requested") == 0)) || strlen(reason) < 8) {
        approval_error(fd, 400, "A supported decision and reason of at least 8 characters are required",
                       origin, extra, extra_len);
        return;
    }
    PGconn *conn = db_acquire();
    if (!conn) {
        approval_error(fd, 503, "Approval database is unavailable", origin, extra, extra_len);
        return;
    }
    if (!approval_actor_active(conn, actor)) {
        db_release(conn, 0);
        approval_error(fd, 403, "Active user account required", origin, extra, extra_len);
        return;
    }
    PGresult *begin = PQexec(conn, "BEGIN");
    if (!begin || PQresultStatus(begin) != PGRES_COMMAND_OK) {
        if (begin) PQclear(begin);
        db_release(conn, 0);
        approval_error(fd, 503, "Could not start approval decision transaction", origin, extra, extra_len);
        return;
    }
    PQclear(begin);
    char role_num[8];
    snprintf(role_num, sizeof(role_num), "%d", (int)actor->role);
    const char *request_params[2] = { request_id, role_num };
    int request_lengths[2] = { (int)strlen(request_id), (int)strlen(role_num) };
    PGresult *request = db_simple(conn,
        "SELECT r.policy_key,r.policy_version,r.requester_id,COALESCE(r.institution_id,''),"
        "r.status,r.expires_at,r.required_approvals,r.conflict_status,"
        "(p.approver_roles @> ARRAY[$2::smallint]),p.active,r.resource_id,"
        "COALESCE(r.institution_id,''),r.proposed_data::text,r.label,r.requester_role,"
        "r.requester_name "
        "FROM approval_requests r JOIN approval_policies p "
        "ON p.policy_key=r.policy_key AND p.version=r.policy_version "
        "WHERE r.id=$1 FOR UPDATE OF r",
        2, request_params, request_lengths);
    if (!request || PQresultStatus(request) != PGRES_TUPLES_OK || PQntuples(request) != 1) {
        if (request) PQclear(request);
        PQexec(conn, "ROLLBACK");
        db_release(conn, 0);
        approval_error(fd, 404, "Approval request not found", origin, extra, extra_len);
        return;
    }
    char policy_key[65], requester_id[65], requester_role_name[41];
    char requester_name[141];
    char request_tenant[65], request_status[33];
    char target_id[129], proposed_data[16385], request_label[141];
    int policy_version = atoi(PQgetvalue(request, 0, 1));
    long long expires_at = strtoll(PQgetvalue(request, 0, 5), NULL, 10);
    int required_approvals = atoi(PQgetvalue(request, 0, 6));
    int role_allowed = strcmp(PQgetvalue(request, 0, 8), "t") == 0;
    int policy_active = strcmp(PQgetvalue(request, 0, 9), "t") == 0;
    snprintf(policy_key, sizeof(policy_key), "%s", PQgetvalue(request, 0, 0));
    snprintf(requester_id, sizeof(requester_id), "%s", PQgetvalue(request, 0, 2));
    snprintf(request_tenant, sizeof(request_tenant), "%s", PQgetvalue(request, 0, 3));
    snprintf(request_status, sizeof(request_status), "%s", PQgetvalue(request, 0, 4));
    snprintf(target_id, sizeof(target_id), "%s", PQgetvalue(request, 0, 10));
    snprintf(proposed_data, sizeof(proposed_data), "%s", PQgetvalue(request, 0, 12));
    snprintf(request_label, sizeof(request_label), "%s", PQgetvalue(request, 0, 13));
    snprintf(requester_role_name, sizeof(requester_role_name), "%s", PQgetvalue(request, 0, 14));
    snprintf(requester_name, sizeof(requester_name), "%s", PQgetvalue(request, 0, 15));
    PQclear(request);
    int requester_role_id = approval_role_id(requester_role_name);

    if (strcmp(requester_id, actor->user_id) == 0) {
        PQexec(conn, "ROLLBACK");
        db_release(conn, 0);
        approval_error(fd, 403, "Requester cannot approve or reject their own request",
                       origin, extra, extra_len);
        return;
    }
    if (actor->role != ROLE_PLATFORM_OWNER &&
        (!actor->institution_id[0] || strcmp(actor->institution_id, request_tenant) != 0)) {
        PQexec(conn, "ROLLBACK");
        db_release(conn, 0);
        approval_error(fd, 403, "Approval request is outside the authenticated institution",
                       origin, extra, extra_len);
        return;
    }
    if (!role_allowed) {
        PQexec(conn, "ROLLBACK");
        db_release(conn, 0);
        approval_error(fd, 403, "Your current role is not an authorized approver for this policy",
                       origin, extra, extra_len);
        return;
    }
    if (strcmp(request_status, "pending_review") != 0) {
        PQexec(conn, "ROLLBACK");
        db_release(conn, 0);
        approval_error(fd, 409, "Approval request is not awaiting a decision",
                       origin, extra, extra_len);
        return;
    }
    if (strcmp(policy_key, "policy-rollback") == 0 &&
        strcmp(decision, "approved") == 0) {
        int target_valid = approval_policy_rollback_target_valid(conn, target_id, request_tenant);
        if (target_valid != 1) {
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            approval_error(fd, target_valid < 0 ? 503 : 409,
                           target_valid < 0
                               ? "Policy rollback target could not be revalidated"
                               : "Policy rollback target is no longer eligible",
                           origin, extra, extra_len);
            return;
        }
    }
    if (strcmp(policy_key, "policy-publish") == 0 &&
        strcmp(decision, "approved") == 0) {
        int target_valid = approval_policy_publish_target_valid(
            conn, target_id, request_tenant, proposed_data);
        if (target_valid != 1) {
            if (target_valid < 0) {
                PQexec(conn, "ROLLBACK");
                db_release(conn, 0);
                approval_error(fd, 503, "Policy publication target could not be revalidated",
                               origin, extra, extra_len);
                return;
            }
            const char *blocked_params[1] = { request_id };
            const int blocked_lengths[1] = { (int)strlen(request_id) };
            PGresult *blocked = db_simple(conn,
                "UPDATE approval_requests SET status='blocked',conflict_status='BLOCKED',"
                "updated_at=(EXTRACT(EPOCH FROM clock_timestamp())*1000)::bigint WHERE id=$1",
                1, blocked_params, blocked_lengths);
            if (!blocked || PQresultStatus(blocked) != PGRES_COMMAND_OK ||
                approval_event(conn, request_id, actor, "CONFLICT_DETECTED",
                               "Policy draft or currently published version changed after submission",
                               "{\"result\":\"BLOCKED\",\"resourceStateRevalidated\":true}") != 0) {
                if (blocked) PQclear(blocked);
                PQexec(conn, "ROLLBACK");
                db_release(conn, 0);
                approval_error(fd, 503, "Policy publication conflict could not be recorded",
                               origin, extra, extra_len);
                return;
            }
            PQclear(blocked);
            PGresult *commit = PQexec(conn, "COMMIT");
            if (!commit || PQresultStatus(commit) != PGRES_COMMAND_OK) {
                if (commit) PQclear(commit);
                PQexec(conn, "ROLLBACK");
                db_release(conn, 0);
                approval_error(fd, 503, "Policy publication conflict could not be committed",
                               origin, extra, extra_len);
                return;
            }
            PQclear(commit);
            audit_append(actor->user_id, "APPROVAL_REQUEST_BLOCKED", request_id);
            db_release(conn, 0);
            approval_error(fd, 409, "Policy changed after submission; request is blocked",
                           origin, extra, extra_len);
            return;
        }
    }
    if (strcmp(policy_key, "role-change") == 0 &&
        strcmp(decision, "approved") == 0) {
        char canonical_id[129] = {0};
        int requested_role_id = 0;
        int target_valid = approval_role_change_target(
            conn, target_id, request_tenant, proposed_data, requester_id,
            requester_role_id, canonical_id, sizeof(canonical_id),
            &requested_role_id);
        if (!requester_role_id || target_valid != 1 ||
            strcmp(canonical_id, target_id) != 0) {
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            approval_error(fd, target_valid < 0 ? 503 : 409,
                           target_valid < 0
                               ? "Role-change target could not be revalidated"
                               : "Role-change target changed or is no longer eligible",
                           origin, extra, extra_len);
            return;
        }
        (void)requested_role_id;
    }
    if (strcmp(policy_key, "device-reauth") == 0 &&
        strcmp(decision, "approved") == 0) {
        int target_valid = approval_device_reauth_target_valid(
            conn, target_id, request_tenant);
        if (target_valid < 0) {
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            approval_error(fd, 503, "Device reauthorization target could not be revalidated",
                           origin, extra, extra_len);
            return;
        }
        if (target_valid == 0) {
            PGresult *blocked = db_simple(conn,
                "UPDATE approval_requests SET status='blocked',conflict_status='BLOCKED',"
                "updated_at=(EXTRACT(EPOCH FROM clock_timestamp())*1000)::bigint WHERE id=$1",
                1, (const char *[]){ request_id },
                (const int []){ (int)strlen(request_id) });
            if (!blocked || PQresultStatus(blocked) != PGRES_COMMAND_OK ||
                approval_event(conn, request_id, actor, "CONFLICT_DETECTED",
                    "Device is no longer revoked in the request institution",
                    "{\"result\":\"BLOCKED\",\"resourceStateRevalidated\":true}") != 0) {
                if (blocked) PQclear(blocked);
                PQexec(conn, "ROLLBACK");
                db_release(conn, 0);
                approval_error(fd, 503, "Device reauthorization conflict could not be persisted",
                               origin, extra, extra_len);
                return;
            }
            PQclear(blocked);
            PGresult *commit = PQexec(conn, "COMMIT");
            if (!commit || PQresultStatus(commit) != PGRES_COMMAND_OK) {
                if (commit) PQclear(commit);
                PQexec(conn, "ROLLBACK");
                db_release(conn, 0);
                approval_error(fd, 503, "Device reauthorization conflict could not be committed",
                               origin, extra, extra_len);
                return;
            }
            PQclear(commit);
            audit_append(actor->user_id, "APPROVAL_REQUEST_BLOCKED", request_id);
            db_release(conn, 0);
            approval_error(fd, 409, "Device state changed; the reauthorization request was blocked",
                           origin, extra, extra_len);
            return;
        }
    }
    if (strcmp(policy_key, "release-approve") == 0 &&
        strcmp(decision, "approved") == 0) {
        int target_valid = approval_release_target_valid(
            conn, target_id, requester_id, requester_name,
            actor->user_id, actor->username, proposed_data);
        if (target_valid < 0) {
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            approval_error(fd, 503, "Release approval target could not be revalidated",
                           origin, extra, extra_len);
            return;
        }
        if (target_valid == 0) {
            PGresult *blocked = db_simple(conn,
                "UPDATE approval_requests SET status='blocked',conflict_status='BLOCKED',"
                "updated_at=(EXTRACT(EPOCH FROM clock_timestamp())*1000)::bigint WHERE id=$1",
                1, (const char *[]){ request_id },
                (const int []){ (int)strlen(request_id) });
            if (!blocked || PQresultStatus(blocked) != PGRES_COMMAND_OK ||
                approval_event(conn, request_id, actor, "CONFLICT_DETECTED",
                    "Release signature, verification, signer key, or manifest digest is no longer eligible",
                    "{\"result\":\"BLOCKED\",\"resourceStateRevalidated\":true}") != 0) {
                if (blocked) PQclear(blocked);
                PQexec(conn, "ROLLBACK");
                db_release(conn, 0);
                approval_error(fd, 503, "Release approval conflict could not be persisted",
                               origin, extra, extra_len);
                return;
            }
            PQclear(blocked);
            PGresult *commit = PQexec(conn, "COMMIT");
            if (!commit || PQresultStatus(commit) != PGRES_COMMAND_OK) {
                if (commit) PQclear(commit);
                PQexec(conn, "ROLLBACK");
                db_release(conn, 0);
                approval_error(fd, 503, "Release approval conflict could not be committed",
                               origin, extra, extra_len);
                return;
            }
            PQclear(commit);
            audit_append(actor->user_id, "APPROVAL_REQUEST_BLOCKED", request_id);
            db_release(conn, 0);
            approval_error(fd, 409, "Release changed or is no longer trusted; the request was blocked",
                           origin, extra, extra_len);
            return;
        }
    }
    long long now_ms = (long long)time(NULL) * 1000;
    if (expires_at < now_ms || !policy_active) {
        const char *blocked_params[2] = { request_id, policy_active ? "expired" : "blocked" };
        int blocked_lengths[2] = { (int)strlen(request_id), (int)strlen(blocked_params[1]) };
        PGresult *blocked = db_simple(conn,
            "UPDATE approval_requests SET status=$2,conflict_status='BLOCKED',"
            "updated_at=(EXTRACT(EPOCH FROM clock_timestamp())*1000)::bigint WHERE id=$1",
            2, blocked_params, blocked_lengths);
        if (!blocked || PQresultStatus(blocked) != PGRES_COMMAND_OK ||
            approval_event(conn, request_id, actor,
                           policy_active ? "REQUEST_EXPIRED" : "CONFLICT_DETECTED",
                           "Request expired or its policy version is no longer active",
                           "{\"result\":\"BLOCKED\"}") != 0) {
            if (blocked) PQclear(blocked);
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            approval_error(fd, 503, "Expired request state and audit event could not be persisted",
                           origin, extra, extra_len);
            return;
        }
        PQclear(blocked);
        PGresult *committed = PQexec(conn, "COMMIT");
        if (!committed || PQresultStatus(committed) != PGRES_COMMAND_OK) {
            if (committed) PQclear(committed);
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            approval_error(fd, 503, "Expired request transaction could not commit",
                           origin, extra, extra_len);
            return;
        }
        PQclear(committed);
        db_release(conn, 0);
        approval_error(fd, 409, "Request expired or policy changed; submit a new request",
                       origin, extra, extra_len);
        return;
    }
    char decision_id[64];
    if (approval_id(decision_id, sizeof(decision_id), "apd_") != 0) {
        PQexec(conn, "ROLLBACK");
        db_release(conn, 0);
        approval_error(fd, 500, "Could not generate a decision identifier",
                       origin, extra, extra_len);
        return;
    }
    char policy_version_text[16];
    snprintf(policy_version_text, sizeof(policy_version_text), "%d", policy_version);
    const char *decision_params[8] = {
        decision_id, request_id, actor->user_id, actor->username,
        security_role_to_string(actor->role), decision, reason, policy_version_text
    };
    int decision_lengths[8];
    for (int i = 0; i < 8; i++) decision_lengths[i] = (int)strlen(decision_params[i]);
    PGresult *insert = db_simple(conn,
        "INSERT INTO approval_decisions "
        "(id,request_id,actor_id,actor_name,actor_role,decision,reason,policy_version) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7,$8::int) ON CONFLICT (request_id,actor_id) DO NOTHING "
        "RETURNING id", 8, decision_params, decision_lengths);
    if (!insert || PQresultStatus(insert) != PGRES_TUPLES_OK || PQntuples(insert) != 1) {
        if (insert) PQclear(insert);
        PQexec(conn, "ROLLBACK");
        db_release(conn, 0);
        approval_error(fd, 409, "This approver has already recorded a decision",
                       origin, extra, extra_len);
        return;
    }
    PQclear(insert);
    int approval_count = 0;
    if (strcmp(decision, "approved") == 0) {
        const char *count_params[1] = { request_id };
        int count_lengths[1] = { (int)strlen(request_id) };
        PGresult *count = db_simple(conn,
            "SELECT count(*)::text FROM approval_decisions WHERE request_id=$1 AND decision='approved'",
            1, count_params, count_lengths);
        if (!count || PQresultStatus(count) != PGRES_TUPLES_OK || PQntuples(count) != 1) {
            if (count) PQclear(count);
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            approval_error(fd, 503, "Approval count could not be verified",
                           origin, extra, extra_len);
            return;
        }
        approval_count = atoi(PQgetvalue(count, 0, 0));
        PQclear(count);
    }
    const char *next_status = strcmp(decision, "rejected") == 0 ? "rejected" :
                              strcmp(decision, "changes_requested") == 0 ? "changes_requested" :
                              approval_count >= required_approvals ? "execution_pending" : "pending_review";
    int role_change_executed = 0;
    int release_executed = 0;
    int policy_publish_executed = 0;
    int policy_rollback_executed = 0;
    if (strcmp(policy_key, "role-change") == 0 &&
        strcmp(next_status, "execution_pending") == 0) {
        if (approval_execute_role_change(conn, target_id, request_tenant,
                                         proposed_data, requester_id,
                                         requester_role_id) != 0) {
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            approval_error(fd, 409, "Role-change execution failed revalidation; no changes were applied",
                           origin, extra, extra_len);
            return;
        }
        role_change_executed = 1;
        next_status = "completed";
    }
    if (strcmp(policy_key, "release-approve") == 0 &&
        strcmp(next_status, "execution_pending") == 0) {
        if (approval_execute_release(conn, target_id, requester_id,
                                     requester_name, actor->user_id,
                                     actor->username, proposed_data, reason) != 0) {
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            approval_error(fd, 409,
                           "Release approval execution failed revalidation; no approval was applied",
                           origin, extra, extra_len);
            return;
        }
        release_executed = 1;
        next_status = "completed";
    }
    if (strcmp(policy_key, "policy-publish") == 0 &&
        strcmp(next_status, "execution_pending") == 0) {
        if (approval_execute_policy_publish(conn, target_id, request_tenant,
                                            actor->username, proposed_data) != 0) {
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            approval_error(fd, 409,
                           "Policy publication execution failed revalidation; no policy was published",
                           origin, extra, extra_len);
            return;
        }
        policy_publish_executed = 1;
        next_status = "completed";
    }
    if (strcmp(policy_key, "policy-rollback") == 0 &&
        strcmp(next_status, "execution_pending") == 0) {
        if (approval_execute_policy_rollback(conn, target_id, request_tenant,
                                             actor->username) != 0) {
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            approval_error(fd, 409,
                           "Policy rollback execution failed revalidation; no rollback was applied",
                           origin, extra, extra_len);
            return;
        }
        policy_rollback_executed = 1;
        next_status = "completed";
    }
    const int operation_executed = role_change_executed || release_executed ||
                                   policy_publish_executed || policy_rollback_executed;
    const char *next_execution = operation_executed ? "completed" :
        strcmp(next_status, "execution_pending") == 0
        ? "pending_integration" : "not_started";
    const char *update_params[4] = { request_id, next_status, next_execution,
                                     strcmp(decision, "rejected") == 0 ? "BLOCKED" :
                                     operation_executed ? "CLEAR" : "WARNING" };
    int update_lengths[4] = {
        (int)strlen(update_params[0]), (int)strlen(update_params[1]),
        (int)strlen(update_params[2]), (int)strlen(update_params[3])
    };
    PGresult *update = db_simple(conn,
        "UPDATE approval_requests SET status=$2,execution_status=$3,conflict_status=$4,"
        "updated_at=(EXTRACT(EPOCH FROM clock_timestamp())*1000)::bigint WHERE id=$1",
        4, update_params, update_lengths);
    if (!update || PQresultStatus(update) != PGRES_COMMAND_OK ||
        approval_event(conn, request_id, actor, "CONFLICT_CHECKED", "",
                       operation_executed
                           ? "{\"result\":\"CLEAR\",\"blockingConflicts\":0,\"resourceStateRevalidated\":true}"
                           : "{\"result\":\"WARNING\",\"blockingConflicts\":0,\"resourceStateRevalidated\":false}") != 0 ||
        approval_event(conn, request_id, actor,
                       strcmp(decision, "approved") == 0 ? "APPROVAL_GRANTED" :
                       strcmp(decision, "rejected") == 0 ? "APPROVAL_REJECTED" : "CHANGES_REQUESTED",
                       reason, operation_executed
                           ? "{\"resourceStateRevalidated\":true}"
                           : "{\"resourceStateRevalidated\":false}") != 0 ||
        (operation_executed &&
         approval_event(conn, request_id, actor, "OPERATION_EXECUTED", "",
                        role_change_executed
                            ? "{\"operation\":\"role-change\",\"result\":\"completed\"}"
                            : release_executed
                                ? "{\"operation\":\"release-approve\",\"result\":\"completed\"}"
                                : policy_publish_executed
                                    ? "{\"operation\":\"policy-publish\",\"result\":\"completed\"}"
                                    : "{\"operation\":\"policy-rollback\",\"result\":\"completed\"}") != 0) ||
        approval_insert_notification(conn, request_tenant, requester_id, NULL,
            strcmp(decision, "approved") == 0 ? "Approval update: approved" :
            strcmp(decision, "rejected") == 0 ? "Approval update: rejected" :
            "Approval update: changes requested",
            request_label, actor->user_id) != 0 ||
        approval_event(conn, request_id, actor, "REQUESTER_NOTIFIED", "",
                       "{\"channel\":\"in-app\",\"delivery\":\"persisted\"}") != 0) {
        if (update) PQclear(update);
        PQexec(conn, "ROLLBACK");
        db_release(conn, 0);
        approval_error(fd, 503, "Decision, audit history, or requester notification could not be persisted",
                       origin, extra, extra_len);
        return;
    }
    PQclear(update);
    PGresult *commit = PQexec(conn, "COMMIT");
    if (!commit || PQresultStatus(commit) != PGRES_COMMAND_OK) {
        if (commit) PQclear(commit);
        PQexec(conn, "ROLLBACK");
        db_release(conn, 0);
        approval_error(fd, 503, "Decision transaction could not commit",
                       origin, extra, extra_len);
        return;
    }
    PQclear(commit);
    audit_append(actor->user_id,
                 operation_executed ? "APPROVAL_OPERATION_EXECUTED" :
                 strcmp(decision, "approved") == 0 ? "APPROVAL_GRANTED" :
                 strcmp(decision, "rejected") == 0 ? "APPROVAL_REJECTED" : "APPROVAL_CHANGES_REQUESTED",
                 request_id);
    db_release(conn, 0);
    char response[384], escaped_id[96];
    ctrl_json_escape(request_id, escaped_id, sizeof(escaped_id));
    snprintf(response, sizeof(response),
             "{\"id\":\"%s\",\"status\":\"%s\",\"conflict_status\":\"%s\","
             "\"execution_status\":\"%s\",\"executed\":%s,"
             "\"message\":\"%s\"}",
             escaped_id, next_status, operation_executed ? "CLEAR" : "WARNING",
             next_execution, operation_executed ? "true" : "false",
             role_change_executed
                 ? "Approval recorded and the role change was executed."
                 : release_executed
                     ? "Approval recorded and the verified release was approved."
                     : policy_publish_executed
                         ? "Approval recorded and the signed policy was published."
                         : policy_rollback_executed
                             ? "Approval recorded and the policy rollback was executed."
                             : "Approval decision recorded; the requested operation was not executed.");
    approval_send(fd, 200, response, origin, extra, extra_len);
}

static void approvals_cancel(int fd, const char *request_id, const char *body,
                             const auth_session_t *actor, const char *origin,
                             char *extra, size_t extra_len) {
    char reason[1025] = {0};
    ctrl_json_string(body, "reason", reason, sizeof(reason));
    if (strlen(reason) < 5) {
        approval_error(fd, 400, "Withdrawal reason must contain at least 5 characters",
                       origin, extra, extra_len);
        return;
    }
    PGconn *conn = db_acquire();
    if (!conn) {
        approval_error(fd, 503, "Approval database is unavailable", origin, extra, extra_len);
        return;
    }
    if (!approval_actor_active(conn, actor)) {
        db_release(conn, 0);
        approval_error(fd, 403, "Active user account required", origin, extra, extra_len);
        return;
    }
    PGresult *begin = PQexec(conn, "BEGIN");
    if (!begin || PQresultStatus(begin) != PGRES_COMMAND_OK) {
        if (begin) PQclear(begin);
        db_release(conn, 0);
        approval_error(fd, 503, "Could not start withdrawal transaction", origin, extra, extra_len);
        return;
    }
    PQclear(begin);
    const char *params[2] = { request_id, actor->user_id };
    int lengths[2] = { (int)strlen(request_id), (int)strlen(actor->user_id) };
    PGresult *update = db_simple(conn,
        "UPDATE approval_requests SET status='withdrawn',updated_at="
        "(EXTRACT(EPOCH FROM clock_timestamp())*1000)::bigint "
        "WHERE id=$1 AND requester_id=$2 AND status='pending_review' "
        "RETURNING policy_key,policy_version,COALESCE(institution_id,''),label",
        2, params, lengths);
    if (!update || PQresultStatus(update) != PGRES_TUPLES_OK || PQntuples(update) != 1) {
        if (update) PQclear(update);
        PQexec(conn, "ROLLBACK");
        db_release(conn, 0);
        approval_error(fd, 409, "Only the requester can withdraw a pending request",
                       origin, extra, extra_len);
        return;
    }
    char kind[65], label[141], tenant_id[65], policy_version_text[16];
    snprintf(kind, sizeof(kind), "%s", PQgetvalue(update, 0, 0));
    snprintf(policy_version_text, sizeof(policy_version_text), "%s", PQgetvalue(update, 0, 1));
    snprintf(tenant_id, sizeof(tenant_id), "%s", PQgetvalue(update, 0, 2));
    snprintf(label, sizeof(label), "%s", PQgetvalue(update, 0, 3));
    int policy_version = atoi(policy_version_text);
    PQclear(update);
    if (approval_event(conn, request_id, actor, "REQUEST_CANCELLED", reason, "{}") != 0 ||
        approval_notify_approvers(conn, request_id, actor, kind, policy_version,
                                  tenant_id, label, actor->user_id,
                                  "Request withdrawn") != 0) {
        PQexec(conn, "ROLLBACK");
        db_release(conn, 0);
        approval_error(fd, 503, "Withdrawal history or approver notifications could not be persisted",
                       origin, extra, extra_len);
        return;
    }
    PGresult *commit = PQexec(conn, "COMMIT");
    if (!commit || PQresultStatus(commit) != PGRES_COMMAND_OK) {
        if (commit) PQclear(commit);
        PQexec(conn, "ROLLBACK");
        db_release(conn, 0);
        approval_error(fd, 503, "Withdrawal transaction could not commit",
                       origin, extra, extra_len);
        return;
    }
    PQclear(commit);
    audit_append(actor->user_id, "APPROVAL_REQUEST_CANCELLED", request_id);
    db_release(conn, 0);
    approval_send(fd, 200, "{\"status\":\"withdrawn\"}", origin, extra, extra_len);
}

void approvals_handle(int fd, const char *method, const char *path, const char *body,
                      const char *auth_header, const char *origin,
                      char *extra, size_t extra_len) {
    auth_session_t actor;
    if (ctrl_authorize(auth_header, AUTH_PERM_READ, &actor) != 0) {
        approval_error(fd, 401, "Authenticated administrative session required",
                       origin, extra, extra_len);
        return;
    }
    const char prefix[] = "/api/v1/approvals";
    const char *suffix = path + sizeof(prefix) - 1;
    if (!suffix[0] && strcmp(method, "GET") == 0) {
        approvals_get(fd, &actor, NULL, origin, extra, extra_len);
        return;
    }
    if (!suffix[0] && strcmp(method, "POST") == 0) {
        approvals_create(fd, body, &actor, origin, extra, extra_len);
        return;
    }
    if (suffix[0] != '/') {
        approval_error(fd, 404, "Approval route not found", origin, extra, extra_len);
        return;
    }
    const char *id_start = suffix + 1;
    const char *slash = strchr(id_start, '/');
    char request_id[65] = {0};
    size_t id_len = slash ? (size_t)(slash - id_start) : strlen(id_start);
    if (id_len == 0 || id_len >= sizeof(request_id)) {
        approval_error(fd, 400, "Invalid approval request identifier", origin, extra, extra_len);
        return;
    }
    memcpy(request_id, id_start, id_len);
    request_id[id_len] = '\0';
    if (!approval_safe_id(request_id)) {
        approval_error(fd, 400, "Invalid approval request identifier", origin, extra, extra_len);
        return;
    }
    if (!slash && strcmp(method, "GET") == 0) {
        approvals_get(fd, &actor, request_id, origin, extra, extra_len);
        return;
    }
    if (strcmp(slash ? slash : "", "/decision") == 0 && strcmp(method, "POST") == 0) {
        approvals_decide(fd, request_id, body, &actor, origin, extra, extra_len);
        return;
    }
    if (strcmp(slash ? slash : "", "/cancel") == 0 && strcmp(method, "POST") == 0) {
        approvals_cancel(fd, request_id, body, &actor, origin, extra, extra_len);
        return;
    }
    approval_error(fd, 404, "Approval route not found", origin, extra, extra_len);
}
