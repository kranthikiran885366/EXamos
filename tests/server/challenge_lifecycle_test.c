/*
 * Tests tenant-, purpose-, expiry-, replay-, and concurrency-bound challenge
 * claims against the PostgreSQL schema built by the isolated test runner.
 */

#define _GNU_SOURCE
#include <libpq-fe.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static PGconn *g_conn;
static int test_count;
static int pass_count;
static int fail_count;

static void test_start(const char *name) {
    printf("\n[TEST] %s\n", name);
    test_count++;
}

static void test_pass(void) {
    puts("  PASS");
    pass_count++;
}

static void test_fail(const char *reason) {
    printf("  FAIL: %s\n", reason);
    fail_count++;
}

static PGconn *connect_db(void) {
    const char *host = getenv("PGHOST");
    const char *database = getenv("PGDATABASE");
    const char *isolated = getenv("EXAMOS_CHALLENGE_TEST_ISOLATED");
    const char *base = host ? strrchr(host, '/') : NULL;
    if (!host || host[0] != '/' || !base ||
        strncmp(base + 1, "examos-challenge-test.", 22) != 0 ||
        !database || strcmp(database, "examos_challenge_test") != 0 ||
        !isolated || strcmp(isolated, "1") != 0) {
        return NULL;
    }
    return PQconnectdb("");
}

static void create_nonce(char nonce[65]) {
    unsigned char raw[32];
    if (RAND_bytes(raw, sizeof(raw)) != 1) {
        fputs("Cryptographic randomness is unavailable\n", stderr);
        exit(1);
    }
    for (size_t i = 0; i < sizeof(raw); i++)
        snprintf(nonce + i * 2, 3, "%02x", raw[i]);
    nonce[64] = '\0';
}

static int insert_challenge(const char *attestation_id, const char *session_id,
                            const char *device_id, const char *release_id,
                            const char *institution_id, const char *purpose,
                            const char *nonce, int expired) {
    if (strcmp(purpose, "exam_launch") == 0) {
        const char *session_params[] = {session_id, institution_id, device_id};
        PGresult *session_result = PQexecParams(g_conn,
            "INSERT INTO exam_sessions (id,institution_id,device_id,status) "
            "VALUES ($1,$2,$3,'pending')",
            3, NULL, session_params, NULL, NULL, 0);
        int session_ok = session_result &&
            PQresultStatus(session_result) == PGRES_COMMAND_OK;
        if (session_result) PQclear(session_result);
        if (!session_ok) return -1;

        const char *checkin_params[] = {session_id, institution_id};
        PGresult *checkin_result = PQexecParams(g_conn,
            "INSERT INTO candidate_exam_checkins "
            "(exam_session_id,institution_id,status,expires_at) "
            "VALUES ($1,$2,'attesting',"
            "EXTRACT(EPOCH FROM clock_timestamp())::bigint*1000+60000)",
            2, NULL, checkin_params, NULL, NULL, 0);
        int checkin_ok = checkin_result &&
            PQresultStatus(checkin_result) == PGRES_COMMAND_OK;
        if (checkin_result) PQclear(checkin_result);
        if (!checkin_ok) return -1;
    }

    const char *params[] = {
        attestation_id, session_id, device_id, release_id, institution_id,
        purpose, "challenge-lifecycle-test", nonce
    };
    const char *sql = expired
        ? "INSERT INTO examos_attestation_challenges "
          "(attestation_id,session_id,device_id,release_id,institution_id,purpose,created_by,"
          "nonce_sha256,state,created_at,expires_at) "
          "VALUES ($1,$2,$3,$4,$5,$6,$7,encode(digest($8::bytea,'sha256'),'hex'),"
          "'PENDING',clock_timestamp()-interval '2 seconds',clock_timestamp()-interval '1 second')"
        : "INSERT INTO examos_attestation_challenges "
          "(attestation_id,session_id,device_id,release_id,institution_id,purpose,created_by,"
          "nonce_sha256,state,created_at,expires_at) "
          "VALUES ($1,$2,$3,$4,$5,$6,$7,encode(digest($8::bytea,'sha256'),'hex'),"
          "'PENDING',clock_timestamp(),clock_timestamp()+interval '30 seconds')";
    PGresult *result = PQexecParams(g_conn, sql, 8, NULL, params, NULL, NULL, 0);
    int ok = result && PQresultStatus(result) == PGRES_COMMAND_OK;
    if (result) PQclear(result);
    return ok ? 0 : -1;
}

static int insert_exam_binding(const char *session_id, const char *device_id,
                               const char *institution_id) {
    const char *session_params[] = {session_id, institution_id, device_id};
    PGresult *result = PQexecParams(g_conn,
        "INSERT INTO exam_sessions (id,institution_id,device_id,status) "
        "VALUES ($1,$2,$3,'active')",
        3, NULL, session_params, NULL, NULL, 0);
    int ok = result && PQresultStatus(result) == PGRES_COMMAND_OK;
    if (result) PQclear(result);
    if (!ok) return -1;

    const char *checkin_params[] = {session_id, institution_id};
    result = PQexecParams(g_conn,
        "INSERT INTO candidate_exam_checkins "
        "(exam_session_id,institution_id,status,expires_at) "
        "VALUES ($1,$2,'consumed',EXTRACT(EPOCH FROM clock_timestamp())::bigint*1000)",
        2, NULL, checkin_params, NULL, NULL, 0);
    ok = result && PQresultStatus(result) == PGRES_COMMAND_OK;
    if (result) PQclear(result);
    return ok ? 0 : -1;
}

static int insert_pending_exam_binding(const char *session_id,
                                      const char *device_id,
                                      const char *institution_id) {
    const char *session_params[] = {session_id, institution_id, device_id};
    PGresult *result = PQexecParams(g_conn,
        "INSERT INTO exam_sessions (id,institution_id,device_id,status) "
        "VALUES ($1,$2,$3,'pending')",
        3, NULL, session_params, NULL, NULL, 0);
    int ok = result && PQresultStatus(result) == PGRES_COMMAND_OK;
    if (result) PQclear(result);
    if (!ok) return -1;

    const char *checkin_params[] = {session_id, institution_id};
    result = PQexecParams(g_conn,
        "INSERT INTO candidate_exam_checkins "
        "(exam_session_id,institution_id,status,expires_at) "
        "VALUES ($1,$2,'attesting',"
        "EXTRACT(EPOCH FROM clock_timestamp())::bigint*1000+60000)",
        2, NULL, checkin_params, NULL, NULL, 0);
    ok = result && PQresultStatus(result) == PGRES_COMMAND_OK;
    if (result) PQclear(result);
    return ok ? 0 : -1;
}

static int insert_trusted_device_fixtures(const char *device_id,
                                          const char *institution_id,
                                          const char *decision,
                                          const char *policy_status) {
    const char *device_params[] = {device_id, institution_id};
    PGresult *result = PQexecParams(g_conn,
        "INSERT INTO devices (id,institution_id,status) VALUES ($1,$2,'enrolled')",
        2, NULL, device_params, NULL, NULL, 0);
    int ok = result && PQresultStatus(result) == PGRES_COMMAND_OK;
    if (result) PQclear(result);
    if (!ok) return -1;

    char registration_id[80], policy_id[80];
    snprintf(registration_id, sizeof(registration_id), "reg_%s", device_id);
    snprintf(policy_id, sizeof(policy_id), "policy_%s", institution_id);
    const char *registration_params[] = {
        registration_id, device_id, institution_id, decision
    };
    result = PQexecParams(g_conn,
        "INSERT INTO device_registrations "
        "(id,device_id,institution_id,decision) VALUES ($1,$2,$3,$4)",
        4, NULL, registration_params, NULL, NULL, 0);
    ok = result && PQresultStatus(result) == PGRES_COMMAND_OK;
    if (result) PQclear(result);
    if (!ok) return -1;

    const char *policy_params[] = {policy_id, institution_id, policy_status};
    result = PQexecParams(g_conn,
        "INSERT INTO device_trust_policies (id,institution_id,status) "
        "VALUES ($1,$2,$3) ON CONFLICT (id) DO UPDATE SET status=EXCLUDED.status",
        3, NULL, policy_params, NULL, NULL, 0);
    ok = result && PQresultStatus(result) == PGRES_COMMAND_OK;
    if (result) PQclear(result);
    return ok ? 0 : -1;
}

static int persist_challenge_sql(const char *attestation_id,
                                 const char *session_id, const char *device_id,
                                 const char *release_id, const char *institution_id,
                                 const char *purpose, const char *nonce) {
    char created[32];
    snprintf(created, sizeof(created), "%lld", (long long)time(NULL));
    const char *params[] = {
        attestation_id, session_id, device_id, release_id, institution_id,
        purpose, "challenge-lifecycle-test", nonce, created
    };
    PGresult *result = PQexecParams(g_conn,
        "INSERT INTO examos_attestation_challenges "
        "(attestation_id,session_id,device_id,release_id,institution_id,purpose,created_by,"
        "nonce_sha256,state,created_at,expires_at) "
        "SELECT $1::varchar(63),$2::varchar(63),$3::varchar(63),$4::varchar(63),"
        "d.institution_id,$6::varchar(32),$7::varchar(64),"
        "encode(digest($8::bytea,'sha256'),'hex'),'PENDING',"
        "to_timestamp($9::double precision),"
        "to_timestamp($9::double precision)+interval '120 seconds' "
        "FROM devices d "
        "JOIN device_registrations r ON r.device_id=d.id "
        "AND r.institution_id=d.institution_id AND r.decision='approved' "
        "JOIN device_trust_policies p ON p.institution_id=d.institution_id "
        "AND p.status='active' "
        "WHERE d.id=$3 AND d.institution_id=$5 "
        "AND d.institution_id<>'' AND d.status IN ('registered','enrolled') "
        "AND (($6='exam_launch' AND EXISTS (SELECT 1 FROM exam_sessions s "
        "JOIN candidate_exam_checkins ci ON ci.exam_session_id=s.id "
        "AND ci.institution_id=s.institution_id "
        "WHERE s.id=$2 AND s.device_id=d.id "
        "AND s.institution_id=d.institution_id AND s.status='pending' "
        "AND ci.status='attesting' "
        "AND ci.expires_at>EXTRACT(EPOCH FROM clock_timestamp())::bigint*1000)) "
        "OR ($6='re_attestation' AND (NOT EXISTS "
        "(SELECT 1 FROM exam_sessions s WHERE s.id=$2) OR EXISTS "
        "(SELECT 1 FROM exam_sessions s JOIN candidate_exam_checkins ci "
        "ON ci.exam_session_id=s.id AND ci.institution_id=s.institution_id "
        "WHERE s.id=$2 AND s.device_id=d.id "
        "AND s.institution_id=d.institution_id "
        "AND s.status IN ('authorized','launching','active','interrupted','resuming') "
        "AND ci.status='consumed'))) "
        "OR ($6='enrollment' AND NOT EXISTS "
        "(SELECT 1 FROM exam_sessions s WHERE s.id=$2))) "
        "AND NOT EXISTS (SELECT 1 FROM examos_attestation_revocations "
        "WHERE (target_type='DEVICE' AND target_id=$3) "
        "OR (target_type='RELEASE' AND target_id=$4))",
        9, NULL, params, NULL, NULL, 0);
    if (!result || PQresultStatus(result) != PGRES_COMMAND_OK) {
        fprintf(stderr, "  challenge persistence SQL failed: %s\n", PQerrorMessage(g_conn));
        if (result) PQclear(result);
        return -1;
    }
    int inserted = atoi(PQcmdTuples(result));
    PQclear(result);
    return inserted;
}

static int claim_challenge(PGconn *conn, const char *nonce, const char *device_id,
                           const char *release_id, const char *institution_id,
                           const char *purpose) {
    const char *params[] = {
        nonce, device_id, release_id, institution_id, purpose
    };
    PGresult *result = PQexecParams(conn,
        "UPDATE examos_attestation_challenges AS c "
        "SET state='VERIFYING',claimed_at=clock_timestamp() "
        "WHERE c.nonce_sha256=encode(digest($1::bytea,'sha256'),'hex') "
        "AND c.device_id=$2 AND c.release_id=$3 AND c.institution_id=$4 AND c.purpose=$5 "
        "AND c.state='PENDING' AND c.expires_at>clock_timestamp() "
        "AND (($5='exam_launch' AND EXISTS (SELECT 1 FROM exam_sessions s "
        "JOIN candidate_exam_checkins ci ON ci.exam_session_id=s.id "
        "AND ci.institution_id=s.institution_id "
        "WHERE s.id=c.session_id AND s.device_id=c.device_id "
        "AND s.institution_id=c.institution_id AND s.status='pending' "
        "AND ci.status='attesting' "
        "AND ci.expires_at>EXTRACT(EPOCH FROM clock_timestamp())::bigint*1000)) "
        "OR ($5='re_attestation' AND (NOT EXISTS "
        "(SELECT 1 FROM exam_sessions s WHERE s.id=c.session_id) OR EXISTS "
        "(SELECT 1 FROM exam_sessions s JOIN candidate_exam_checkins ci "
        "ON ci.exam_session_id=s.id AND ci.institution_id=s.institution_id "
        "WHERE s.id=c.session_id AND s.device_id=c.device_id "
        "AND s.institution_id=c.institution_id "
        "AND s.status IN ('authorized','launching','active','interrupted','resuming') "
        "AND ci.status='consumed'))) "
        "OR ($5='enrollment' AND NOT EXISTS "
        "(SELECT 1 FROM exam_sessions s WHERE s.id=c.session_id))) "
        "AND NOT EXISTS (SELECT 1 FROM examos_attestation_revocations r "
        "WHERE (r.target_type='DEVICE' AND r.target_id=c.device_id) "
        "OR (r.target_type='RELEASE' AND r.target_id=c.release_id)) "
        "RETURNING c.attestation_id, c.session_id, "
        "EXISTS (SELECT 1 FROM exam_sessions s "
        "JOIN candidate_exam_checkins ci ON ci.exam_session_id=s.id "
        "AND ci.institution_id=s.institution_id "
        "WHERE s.id=c.session_id AND s.device_id=c.device_id "
        "AND s.institution_id=c.institution_id "
        "AND ((c.purpose='exam_launch' AND s.status='pending' "
        "AND ci.status='attesting' "
        "AND ci.expires_at>EXTRACT(EPOCH FROM clock_timestamp())::bigint*1000) "
        "OR (c.purpose='re_attestation' "
        "AND s.status IN ('authorized','launching','active','interrupted','resuming') "
        "AND ci.status='consumed')))",
        5, NULL, params, NULL, NULL, 0);
    if (!result || PQresultStatus(result) != PGRES_TUPLES_OK) {
        if (result) PQclear(result);
        return -1;
    }
    int claimed = PQntuples(result) == 1;
    PQclear(result);
    return claimed;
}

static void test_valid_and_replay(void) {
    test_start("Valid challenge claim and replay rejection");
    char nonce[65];
    create_nonce(nonce);
    if (insert_challenge("attest-00000000000000000000000000000001",
                         "sess_valid", "dev_test1", "rel_test1", "test_inst",
                         "re_attestation", nonce, 0) != 0 ||
        claim_challenge(g_conn, nonce, "dev_test1", "rel_test1", "test_inst",
                        "re_attestation") != 1 ||
        claim_challenge(g_conn, nonce, "dev_test1", "rel_test1", "test_inst",
                        "re_attestation") != 0) {
        test_fail("Challenge claim or replay rejection failed");
        return;
    }
    test_pass();
}

static void test_unknown_and_expired(void) {
    test_start("Unknown and expired challenges are rejected");
    char unknown_nonce[65], expired_nonce[65];
    create_nonce(unknown_nonce);
    create_nonce(expired_nonce);
    if (claim_challenge(g_conn, unknown_nonce, "dev_test1", "rel_test1",
                        "test_inst", "re_attestation") != 0 ||
        insert_challenge("attest-00000000000000000000000000000002",
                         "sess_expired", "dev_test1", "rel_test1", "test_inst",
                         "re_attestation", expired_nonce, 1) != 0 ||
        claim_challenge(g_conn, expired_nonce, "dev_test1", "rel_test1",
                        "test_inst", "re_attestation") != 0) {
        test_fail("Unknown or expired challenge was accepted");
        return;
    }
    test_pass();
}

static void test_wrong_device_tenant_purpose(void) {
    test_start("Device, tenant, and purpose bindings are enforced");
    char nonce[65];
    create_nonce(nonce);
    if (insert_challenge("attest-00000000000000000000000000000003",
                         "sess_binding", "dev_test1", "rel_test1", "test_inst",
                         "re_attestation", nonce, 0) != 0 ||
        claim_challenge(g_conn, nonce, "dev_other", "rel_test1", "test_inst",
                        "re_attestation") != 0 ||
        claim_challenge(g_conn, nonce, "dev_test1", "rel_test1", "other_inst",
                        "re_attestation") != 0 ||
        claim_challenge(g_conn, nonce, "dev_test1", "rel_test1", "test_inst",
                        "exam_launch") != 0 ||
        claim_challenge(g_conn, nonce, "dev_test1", "rel_test1", "test_inst",
                        "re_attestation") != 1) {
        test_fail("Challenge binding was not enforced exactly");
        return;
    }
    test_pass();
}

static void test_invalid_purpose(void) {
    test_start("Schema rejects unsupported challenge purposes");
    char nonce[65];
    create_nonce(nonce);
    int insert_result = insert_challenge(
        "attest-00000000000000000000000000000006", "sess_invalid_purpose",
        "dev_test1", "rel_test1", "test_inst", "invalid_purpose", nonce, 0);
    PGresult *result = PQexec(g_conn,
        "SELECT COUNT(*) FROM examos_attestation_challenges "
        "WHERE attestation_id='attest-00000000000000000000000000000006'");
    int absent = result && PQresultStatus(result) == PGRES_TUPLES_OK &&
        strcmp(PQgetvalue(result, 0, 0), "0") == 0;
    if (result) PQclear(result);
    if (insert_result == 0 || !absent) {
        test_fail("Unsupported challenge purpose was persisted");
        return;
    }
    test_pass();
}

static void test_exam_session_binding(void) {
    test_start("Exam-launch challenge requires the pending assigned exam session");
    char nonce[65];
    create_nonce(nonce);
    if (insert_challenge("attest-00000000000000000000000000000007",
                         "sess_session_binding", "dev_test1", "rel_test1",
                         "test_inst", "exam_launch", nonce, 0) != 0) {
        test_fail("Failed to create session-bound challenge");
        return;
    }
    PGresult *result = PQexec(g_conn,
        "UPDATE exam_sessions SET device_id='dev_other' "
        "WHERE id='sess_session_binding'");
    int changed = result && PQresultStatus(result) == PGRES_COMMAND_OK &&
        strcmp(PQcmdTuples(result), "1") == 0;
    if (result) PQclear(result);
    if (!changed || claim_challenge(g_conn, nonce, "dev_test1", "rel_test1",
                                    "test_inst", "exam_launch") != 0) {
        test_fail("Challenge was accepted after its exam session binding changed");
        return;
    }
    test_pass();
}

static void test_device_boot_challenge(void) {
    test_start("Device boot attestation without an exam session remains supported");
    char nonce[65];
    create_nonce(nonce);
    if (insert_challenge("attest-00000000000000000000000000000009",
                         "sess_boot", "dev_test1", "rel_test1", "test_inst",
                         "re_attestation", nonce, 0) != 0) {
        test_fail("Failed to create device boot challenge");
        return;
    }
    PGresult *result = PQexec(g_conn,
        "DELETE FROM candidate_exam_checkins WHERE exam_session_id='sess_boot'");
    int checkin_deleted = result && PQresultStatus(result) == PGRES_COMMAND_OK;
    if (result) PQclear(result);
    result = PQexec(g_conn,
        "DELETE FROM exam_sessions WHERE id='sess_boot'");
    int session_deleted = result && PQresultStatus(result) == PGRES_COMMAND_OK;
    if (result) PQclear(result);
    if (!checkin_deleted || !session_deleted ||
        claim_challenge(g_conn, nonce, "dev_test1", "rel_test1",
                        "test_inst", "re_attestation") != 1) {
        test_fail("Device boot challenge required an exam session");
        return;
    }
    test_pass();
}

static void test_persist_write_gates(void) {
    test_start("Challenge persistence enforces tenant, approval, policy, and session");
    const char *device_id = "dev_persist";
    if (insert_trusted_device_fixtures(device_id, "test_inst", "approved", "active") != 0 ||
        insert_exam_binding("sess_persist", device_id, "test_inst") != 0 ||
        insert_pending_exam_binding("sess_exam_launch", device_id,
                                    "test_inst") != 0) {
        test_fail("Failed to prepare approved challenge fixtures");
        return;
    }

    char valid_nonce[65], wrong_tenant_nonce[65], pending_nonce[65];
    char launch_nonce[65], wrong_purpose_nonce[65], unbound_launch_nonce[65];
    char active_launch_nonce[65];
    create_nonce(valid_nonce);
    create_nonce(wrong_tenant_nonce);
    create_nonce(pending_nonce);
    create_nonce(launch_nonce);
    create_nonce(wrong_purpose_nonce);
    create_nonce(unbound_launch_nonce);
    create_nonce(active_launch_nonce);
    int persisted = persist_challenge_sql(
        "attest-00000000000000000000000000000010", "sess_persist",
        device_id, "rel_persist", "test_inst", "re_attestation", valid_nonce);
    int wrong_tenant = persist_challenge_sql(
        "attest-00000000000000000000000000000011", "sess_persist",
        device_id, "rel_persist", "other_inst", "re_attestation", wrong_tenant_nonce);
    int pending_device_setup = insert_trusted_device_fixtures(
        "dev_pending", "test_inst", "pending", "active");
    int pending_registration = pending_device_setup == 0
        ? persist_challenge_sql(
            "attest-00000000000000000000000000000012", "sess_unbound",
            "dev_pending", "rel_persist", "test_inst", "re_attestation", pending_nonce)
        : -1;
    int valid_launch = persist_challenge_sql(
        "attest-00000000000000000000000000000013", "sess_exam_launch",
        device_id, "rel_persist", "test_inst", "exam_launch", launch_nonce);
    int wrong_launch_purpose = persist_challenge_sql(
        "attest-00000000000000000000000000000014", "sess_exam_launch",
        device_id, "rel_persist", "test_inst", "re_attestation", wrong_purpose_nonce);
    int unbound_launch = persist_challenge_sql(
        "attest-00000000000000000000000000000015", "sess_unbound",
        device_id, "rel_persist", "test_inst", "exam_launch", unbound_launch_nonce);
    int active_launch = persist_challenge_sql(
        "attest-00000000000000000000000000000016", "sess_persist",
        device_id, "rel_persist", "test_inst", "exam_launch", active_launch_nonce);
    int claim_result = persisted == 1
        ? claim_challenge(g_conn, valid_nonce, device_id, "rel_persist",
                          "test_inst", "re_attestation")
        : -1;
    int launch_claim = valid_launch == 1
        ? claim_challenge(g_conn, launch_nonce, device_id, "rel_persist",
                          "test_inst", "exam_launch")
        : -1;

    if (persisted != 1 || claim_result != 1 ||
        wrong_tenant != 0 || pending_registration != 0 ||
        valid_launch != 1 || launch_claim != 1 ||
        wrong_launch_purpose != 0 || unbound_launch != 0 ||
        active_launch != 0) {
        fprintf(stderr, "  persistence results: approved=%d claim=%d wrong_tenant=%d "
                "pending=%d launch=%d launch_claim=%d wrong_purpose=%d "
                "unbound_launch=%d active_launch=%d\n",
                persisted, claim_result, wrong_tenant, pending_registration,
                valid_launch, launch_claim, wrong_launch_purpose, unbound_launch,
                active_launch);
        test_fail("Challenge persistence did not enforce database trust bindings");
        return;
    }
    test_pass();
}

static void test_revocation(void) {
    test_start("Revoked device and release challenges cannot be claimed");
    char nonce[65];
    create_nonce(nonce);
    if (insert_challenge("attest-00000000000000000000000000000008",
                         "sess_revoked", "dev_test1", "rel_revoked", "test_inst",
                         "re_attestation", nonce, 0) != 0) {
        test_fail("Failed to create revocation challenge");
        return;
    }
    const char *params[] = {"RELEASE", "rel_revoked", "lifecycle test"};
    PGresult *result = PQexecParams(g_conn,
        "INSERT INTO examos_attestation_revocations "
        "(target_type,target_id,reason) VALUES ($1,$2,$3)",
        3, NULL, params, NULL, NULL, 0);
    int revoked = result && PQresultStatus(result) == PGRES_COMMAND_OK;
    if (result) PQclear(result);
    if (!revoked || claim_challenge(g_conn, nonce, "dev_test1", "rel_revoked",
                                    "test_inst", "re_attestation") != 0) {
        test_fail("Revoked challenge was accepted");
        return;
    }
    test_pass();
}

typedef struct {
    const char *nonce;
    pthread_mutex_t *mutex;
    pthread_cond_t *condition;
    int *start;
    int connected;
    int claim_result;
} claim_thread_t;

static void *concurrent_claim(void *opaque) {
    claim_thread_t *arg = opaque;
    pthread_mutex_lock(arg->mutex);
    while (*arg->start == 0)
        pthread_cond_wait(arg->condition, arg->mutex);
    int start = *arg->start;
    pthread_mutex_unlock(arg->mutex);
    if (start < 0) return NULL;

    PGconn *conn = connect_db();
    arg->connected = conn && PQstatus(conn) == CONNECTION_OK;
    arg->claim_result = arg->connected
        ? claim_challenge(conn, arg->nonce, "dev_test1", "rel_test1",
                          "test_inst", "re_attestation")
        : -1;
    if (conn) PQfinish(conn);
    return NULL;
}

static void test_concurrent_claim(void) {
    test_start("Concurrent challenge claims are single-use");
    char nonce[65];
    create_nonce(nonce);
    if (insert_challenge("attest-00000000000000000000000000000004",
                         "sess_concurrent", "dev_test1", "rel_test1", "test_inst",
                         "re_attestation", nonce, 0) != 0) {
        test_fail("Failed to create concurrent challenge");
        return;
    }

    pthread_mutex_t mutex;
    pthread_cond_t condition;
    int start = 0;
    if (pthread_mutex_init(&mutex, NULL) != 0) {
        test_fail("Could not initialize concurrency gate");
        return;
    }
    if (pthread_cond_init(&condition, NULL) != 0) {
        pthread_mutex_destroy(&mutex);
        test_fail("Could not initialize concurrency gate");
        return;
    }
    claim_thread_t args[2] = {
        {nonce, &mutex, &condition, &start, 0, -1},
        {nonce, &mutex, &condition, &start, 0, -1}
    };
    pthread_t threads[2];
    int created_a = pthread_create(&threads[0], NULL, concurrent_claim, &args[0]) == 0;
    int created_b = created_a &&
        pthread_create(&threads[1], NULL, concurrent_claim, &args[1]) == 0;
    if (!created_a || !created_b) {
        pthread_mutex_lock(&mutex);
        start = -1;
        pthread_cond_broadcast(&condition);
        pthread_mutex_unlock(&mutex);
        if (created_a) pthread_join(threads[0], NULL);
        pthread_cond_destroy(&condition);
        pthread_mutex_destroy(&mutex);
        test_fail("Could not create concurrent claim workers");
        return;
    }

    pthread_mutex_lock(&mutex);
    start = 1;
    pthread_cond_broadcast(&condition);
    pthread_mutex_unlock(&mutex);
    pthread_join(threads[0], NULL);
    pthread_join(threads[1], NULL);
    pthread_cond_destroy(&condition);
    pthread_mutex_destroy(&mutex);
    if (!args[0].connected || !args[1].connected ||
        args[0].claim_result < 0 || args[1].claim_result < 0 ||
        args[0].claim_result + args[1].claim_result != 1) {
        test_fail("Concurrent claims did not produce exactly one winner");
        return;
    }
    test_pass();
}

static void test_transaction_failure(void) {
    test_start("Failed transaction does not persist a challenge");
    const char *params[] = {
        "attest-00000000000000000000000000000005", "sess_rollback", "dev_test1",
        "rel_test1", "test_inst", "re_attestation", "challenge-lifecycle-test",
        "transaction-nonce"
    };
    PGresult *result = PQexec(g_conn, "BEGIN");
    int ok = result && PQresultStatus(result) == PGRES_COMMAND_OK;
    if (result) PQclear(result);
    if (ok) {
        result = PQexecParams(g_conn,
            "INSERT INTO examos_attestation_challenges "
            "(attestation_id,session_id,device_id,release_id,institution_id,purpose,created_by,"
            "nonce_sha256,state,created_at,expires_at) "
            "VALUES ($1,$2,$3,$4,$5,$6,$7,encode(digest($8::bytea,'sha256'),'hex'),"
            "'PENDING',clock_timestamp(),clock_timestamp()+interval '30 seconds')",
            8, NULL, params, NULL, NULL, 0);
        ok = result && PQresultStatus(result) == PGRES_COMMAND_OK;
        if (result) PQclear(result);
    }
    if (ok) {
        result = PQexec(g_conn,
            "UPDATE examos_attestation_challenges SET state='INVALID' "
            "WHERE attestation_id='attest-00000000000000000000000000000005'");
        ok = result && PQresultStatus(result) == PGRES_FATAL_ERROR;
        if (result) PQclear(result);
    }
    result = PQexec(g_conn, "ROLLBACK");
    ok = ok && result && PQresultStatus(result) == PGRES_COMMAND_OK;
    if (result) PQclear(result);
    result = PQexec(g_conn,
        "SELECT COUNT(*) FROM examos_attestation_challenges "
        "WHERE attestation_id='attest-00000000000000000000000000000005'");
    ok = ok && result && PQresultStatus(result) == PGRES_TUPLES_OK &&
         strcmp(PQgetvalue(result, 0, 0), "0") == 0;
    if (result) PQclear(result);
    if (!ok) {
        test_fail("Failed transaction left a challenge row behind");
        return;
    }
    test_pass();
}

static void test_db_unavailable(void) {
    test_start("Database unavailable is rejected");
    const char *keywords[] = {"host", "port", "dbname", "connect_timeout", NULL};
    const char *values[] = {
        "/nonexistent/examos-challenge-test.invalid", "1",
        "examos_challenge_test", "1", NULL
    };
    PGconn *conn = PQconnectdbParams(keywords, values, 0);
    int rejected = !conn || PQstatus(conn) != CONNECTION_OK;
    if (conn) PQfinish(conn);
    if (!rejected) {
        test_fail("Unavailable database unexpectedly accepted a connection");
        return;
    }
    test_pass();
}

int main(void) {
    puts("=== Authoritative Challenge Lifecycle Tests ===");
    g_conn = connect_db();
    if (!g_conn || PQstatus(g_conn) != CONNECTION_OK) {
        fputs("Refusing to run: isolated temporary PostgreSQL is required\n", stderr);
        if (g_conn) PQfinish(g_conn);
        return 1;
    }

    test_valid_and_replay();
    test_unknown_and_expired();
    test_wrong_device_tenant_purpose();
    test_invalid_purpose();
    test_exam_session_binding();
    test_device_boot_challenge();
    test_persist_write_gates();
    test_revocation();
    test_concurrent_claim();
    test_transaction_failure();
    test_db_unavailable();
    PQfinish(g_conn);

    printf("\n=== Test Summary ===\nTotal: %d, Pass: %d, Fail: %d\n",
           test_count, pass_count, fail_count);
    return fail_count ? 1 : 0;
}
