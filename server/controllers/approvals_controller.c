#include "approvals_controller.h"

#include "../audit/audit.h"
#include "../db/db.h"

#include <openssl/rand.h>
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

static int approval_policy_rollback_tenant(PGconn *conn, const char *exam_id,
                                           char *tenant_id, size_t tenant_len) {
    PGresult *res = db_simple(conn,
        "SELECT institution_id FROM examos_exams WHERE exam_id=$1",
        1, (const char *[]){ exam_id }, (const int []){ (int)strlen(exam_id) });
    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
        if (res) PQclear(res);
        return -1;
    }
    if (PQntuples(res) != 1 || strlen(PQgetvalue(res, 0, 0)) >= tenant_len) {
        PQclear(res);
        return 0;
    }
    snprintf(tenant_id, tenant_len, "%s", PQgetvalue(res, 0, 0));
    PQclear(res);
    return tenant_id[0] ? 1 : 0;
}

static int approval_policy_rollback_target_valid(PGconn *conn, const char *exam_id,
                                                 const char *tenant_id,
                                                 const char *proposed_data) {
    int target_version = 0;
    if (!ctrl_json_int(proposed_data, "targetVersion", &target_version) ||
        target_version <= 0) return 0;
    char version_text[16];
    snprintf(version_text, sizeof(version_text), "%d", target_version);
    PGresult *res = db_simple(conn,
        "SELECT EXISTS ("
        "SELECT 1 FROM examos_exams e "
        "JOIN examos_exam_policies active "
        "ON active.exam_id=e.exam_id AND active.status='ACTIVE' "
        "JOIN examos_exam_policies target "
        "ON target.exam_id=e.exam_id AND target.policy_version=$3::integer "
        "AND target.status<>'ACTIVE' AND target.signature<>'' "
        "WHERE e.exam_id=$1 AND e.institution_id=$2 "
        "AND target.policy_version < active.policy_version "
        "AND e.policy_version=active.policy_version)::text",
        3, (const char *[]){ exam_id, tenant_id, version_text },
        (const int []){ (int)strlen(exam_id), (int)strlen(tenant_id),
                        (int)strlen(version_text) });
    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) != 1) {
        if (res) PQclear(res);
        return -1;
    }
    int valid = strcmp(PQgetvalue(res, 0, 0), "true") == 0;
    PQclear(res);
    return valid;
}

static int approval_execute_policy_rollback(PGconn *conn, const char *exam_id,
                                            const char *tenant_id,
                                            const char *proposed_data) {
    int target_version = 0;
    if (!ctrl_json_int(proposed_data, "targetVersion", &target_version) ||
        target_version <= 0) return -1;
    char target_version_text[16];
    snprintf(target_version_text, sizeof(target_version_text), "%d", target_version);

    PGresult *current = db_simple(conn,
        "SELECT e.policy_version,p.policy_version "
        "FROM examos_exams e JOIN examos_exam_policies p "
        "ON p.exam_id=e.exam_id AND p.status='ACTIVE' "
        "WHERE e.exam_id=$1 AND e.institution_id=$2 FOR UPDATE OF e,p",
        2, (const char *[]){ exam_id, tenant_id },
        (const int []){ (int)strlen(exam_id), (int)strlen(tenant_id) });
    if (!current || PQresultStatus(current) != PGRES_TUPLES_OK ||
        PQntuples(current) != 1) {
        if (current) PQclear(current);
        return -1;
    }
    int exam_version = atoi(PQgetvalue(current, 0, 0));
    int active_version = atoi(PQgetvalue(current, 0, 1));
    PQclear(current);
    if (exam_version != active_version || target_version >= active_version) return -1;

    PGresult *target = db_simple(conn,
        "SELECT exam_url,allowed_origins,signature FROM examos_exam_policies "
        "WHERE exam_id=$1 AND policy_version=$2::integer "
        "AND status IN ('SUPERSEDED','ROLLBACK') AND signature<>'' FOR UPDATE",
        2, (const char *[]){ exam_id, target_version_text },
        (const int []){ (int)strlen(exam_id), (int)strlen(target_version_text) });
    if (!target || PQresultStatus(target) != PGRES_TUPLES_OK ||
        PQntuples(target) != 1) {
        if (target) PQclear(target);
        return -1;
    }
    char exam_url[4096], allowed_origins[4096], signature[129];
    snprintf(exam_url, sizeof(exam_url), "%s", PQgetvalue(target, 0, 0));
    snprintf(allowed_origins, sizeof(allowed_origins), "%s", PQgetvalue(target, 0, 1));
    snprintf(signature, sizeof(signature), "%s", PQgetvalue(target, 0, 2));
    PQclear(target);

    PGresult *supersede = db_simple(conn,
        "UPDATE examos_exam_policies SET status='SUPERSEDED' "
        "WHERE exam_id=$1 AND status='ACTIVE'",
        1, (const char *[]){ exam_id }, (const int []){ (int)strlen(exam_id) });
    if (!supersede || PQresultStatus(supersede) != PGRES_COMMAND_OK ||
        strcmp(PQcmdTuples(supersede), "1") != 0) {
        if (supersede) PQclear(supersede);
        return -1;
    }
    PQclear(supersede);

    PGresult *activate = db_simple(conn,
        "UPDATE examos_exam_policies SET status='ACTIVE' "
        "WHERE exam_id=$1 AND policy_version=$2::integer "
        "AND status IN ('SUPERSEDED','ROLLBACK')",
        2, (const char *[]){ exam_id, target_version_text },
        (const int []){ (int)strlen(exam_id), (int)strlen(target_version_text) });
    if (!activate || PQresultStatus(activate) != PGRES_COMMAND_OK ||
        strcmp(PQcmdTuples(activate), "1") != 0) {
        if (activate) PQclear(activate);
        return -1;
    }
    PQclear(activate);

    char old_version_text[16];
    snprintf(old_version_text, sizeof(old_version_text), "%d", active_version);
    PGresult *update_exam = db_simple(conn,
        "UPDATE examos_exams SET exam_url=$1,allowed_origins=$2,"
        "policy_version=$3::integer,policy_signature=$4,updated_at=clock_timestamp() "
        "WHERE exam_id=$5 AND institution_id=$6 AND policy_version=$7::integer",
        7, (const char *[]){ exam_url, allowed_origins, target_version_text,
                             signature, exam_id, tenant_id, old_version_text },
        (const int []){ (int)strlen(exam_url), (int)strlen(allowed_origins),
                        (int)strlen(target_version_text), (int)strlen(signature),
                        (int)strlen(exam_id), (int)strlen(tenant_id),
                        (int)strlen(old_version_text) });
    if (!update_exam || PQresultStatus(update_exam) != PGRES_COMMAND_OK ||
        strcmp(PQcmdTuples(update_exam), "1") != 0) {
        if (update_exam) PQclear(update_exam);
        return -1;
    }
    PQclear(update_exam);
    return 0;
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
    if (strcmp(kind, "policy-rollback") == 0 &&
        strstr(data_json, "\"targetVersion\"") != NULL) {
        int target_version = 0;
        if (!ctrl_json_int(data_json, "targetVersion", &target_version) ||
            target_version <= 0) {
            db_release(conn, 0);
            approval_error(fd, 400, "A positive rollback targetVersion is required",
                           origin, extra, extra_len);
            return;
        }
        char exam_tenant[65] = {0};
        int tenant_result = approval_policy_rollback_tenant(
            conn, target_id, exam_tenant, sizeof(exam_tenant));
        if (tenant_result != 1) {
            db_release(conn, 0);
            approval_error(fd, tenant_result < 0 ? 503 : 404,
                           tenant_result < 0
                               ? "Exam rollback tenant could not be verified"
                               : "Exam rollback target was not found",
                           origin, extra, extra_len);
            return;
        }
        if ((requested_tenant[0] &&
             strcmp(requested_tenant, exam_tenant) != 0) ||
            (actor->role != ROLE_PLATFORM_OWNER &&
             strcmp(actor->institution_id, exam_tenant) != 0)) {
            db_release(conn, 0);
            approval_error(fd, 403, "Rollback request is outside the authenticated institution",
                           origin, extra, extra_len);
            return;
        }
        snprintf(tenant, sizeof(tenant), "%s", exam_tenant);
        int target_valid = approval_policy_rollback_target_valid(
            conn, target_id, tenant, data_json);
        if (target_valid != 1) {
            db_release(conn, 0);
            approval_error(fd, target_valid < 0 ? 503 : 409,
                           target_valid < 0
                               ? "Exam policy rollback target could not be verified"
                               : "Rollback target must be an older signed policy for this exam",
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
                                         "SELECT (EXISTS(SELECT 1 FROM tenants WHERE id=$1) "
                                         "OR ($2='policy-rollback' AND EXISTS("
                                         "SELECT 1 FROM examos_institutions WHERE institution_id=$1)))::text",
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
        "COALESCE(r.institution_id,''),r.proposed_data::text,r.label,r.requester_role "
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
    if (strcmp(policy_key, "policy-rollback") == 0 &&
        strstr(proposed_data, "\"targetVersion\"") != NULL &&
        strcmp(decision, "approved") == 0) {
        int target_valid = approval_policy_rollback_target_valid(
            conn, target_id, request_tenant, proposed_data);
        if (target_valid != 1) {
            if (target_valid < 0) {
                PQexec(conn, "ROLLBACK");
                db_release(conn, 0);
                approval_error(fd, 503, "Rollback target could not be revalidated",
                               origin, extra, extra_len);
                return;
            }
            PGresult *blocked = db_simple(conn,
                "UPDATE approval_requests SET status='blocked',conflict_status='BLOCKED',"
                "updated_at=(EXTRACT(EPOCH FROM clock_timestamp())*1000)::bigint WHERE id=$1",
                1, (const char *[]){ request_id },
                (const int []){ (int)strlen(request_id) });
            if (!blocked || PQresultStatus(blocked) != PGRES_COMMAND_OK ||
                approval_event(conn, request_id, actor, "CONFLICT_DETECTED",
                    "Exam policy state changed after rollback submission",
                    "{\"result\":\"BLOCKED\",\"resourceStateRevalidated\":true}") != 0) {
                if (blocked) PQclear(blocked);
                PQexec(conn, "ROLLBACK");
                db_release(conn, 0);
                approval_error(fd, 503, "Rollback conflict could not be persisted",
                               origin, extra, extra_len);
                return;
            }
            PQclear(blocked);
            PGresult *commit = PQexec(conn, "COMMIT");
            if (!commit || PQresultStatus(commit) != PGRES_COMMAND_OK) {
                if (commit) PQclear(commit);
                PQexec(conn, "ROLLBACK");
                db_release(conn, 0);
                approval_error(fd, 503, "Rollback conflict could not be committed",
                               origin, extra, extra_len);
                return;
            }
            PQclear(commit);
            audit_append(actor->user_id, "APPROVAL_REQUEST_BLOCKED", request_id);
            db_release(conn, 0);
            approval_error(fd, 409, "Exam policy changed; the rollback request was blocked",
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
    if (strcmp(policy_key, "policy-rollback") == 0 &&
        strstr(proposed_data, "\"targetVersion\"") != NULL &&
        strcmp(next_status, "execution_pending") == 0) {
        if (approval_execute_policy_rollback(
                conn, target_id, request_tenant, proposed_data) != 0) {
            PQexec(conn, "ROLLBACK");
            db_release(conn, 0);
            approval_error(fd, 409, "Rollback execution failed revalidation; no changes were applied",
                           origin, extra, extra_len);
            return;
        }
        policy_rollback_executed = 1;
        next_status = "completed";
    }
    const int operation_executed = role_change_executed || policy_rollback_executed;
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
                 : policy_rollback_executed
                     ? "Approval recorded and the exam policy rollback was executed."
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
