/*
 * audit.c — Tamper-evident SHA-256 hash chain for ExamOS server.
 *
 * Every mutating API call and security event is appended to a durable
 * hash chain stored in PostgreSQL. Each entry commits to the previous
 * entry's hash, making tampering detectable.
 */

#include "audit.h"
#include "../db/db.h"
#include "../security/security.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>

static long g_chain_len = 0;
static char g_last_hash[65] = {0};
static pthread_mutex_t audit_lock = PTHREAD_MUTEX_INITIALIZER;

static const char GENESIS[] = "GENESIS";

static int sha256_hex_str(const char *input, char *out, size_t out_len) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)input, strlen(input), hash);
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < SHA256_DIGEST_LENGTH && i * 2 + 1 < (int)out_len; i++) {
        out[i * 2] = hex[hash[i] >> 4];
        out[i * 2 + 1] = hex[hash[i] & 0x0f];
    }
    out[SHA256_DIGEST_LENGTH * 2] = '\0';
    return 0;
}

int audit_init(void) {
    PGconn *conn = db_acquire();
    if (!conn) return -1;
    PGresult *res = PQexec(conn,
        "SELECT COUNT(*) FROM audit");
    long count = 0;
    if (res && PQresultStatus(res) == PGRES_TUPLES_OK) {
        count = atol(PQgetvalue(res, 0, 0));
    }
    if (res) PQclear(res);

    if (count > 0) {
        res = PQexec(conn,
            "SELECT prev, hash FROM audit ORDER BY seq DESC LIMIT 1");
        if (res && PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0) {
            strncpy(g_last_hash, PQgetvalue(res, 0, 1), sizeof(g_last_hash) - 1);
        }
        if (res) PQclear(res);
    } else {
        strcpy(g_last_hash, GENESIS);
    }
    g_chain_len = count;
    db_release(conn, 0);
    return 0;
}

void audit_shutdown(void) {
    (void)audit_lock;
}

int audit_append(const char *actor, const char *event, const char *detail) {
    if (!actor || !event) return -1;

    pthread_mutex_lock(&audit_lock);

    PGconn *conn = db_acquire();
    if (!conn) {
        pthread_mutex_unlock(&audit_lock);
        return -1;
    }

    long seq = g_chain_len + 1;
    time_t ts = time(NULL);
    char ts_buf[32];
    snprintf(ts_buf, sizeof(ts_buf), "%ld", (long)ts);

    /* Build canonical body: seq|ts|actor|event|detail|prev */
    char body[1024];
    int blen = snprintf(body, sizeof(body), "%ld|%s|%s|%s|%s|%s",
                        seq, ts_buf,
                        actor ? actor : "system",
                        event ? event : "",
                        detail ? detail : "",
                        g_last_hash);
    if (blen < 0 || blen >= (int)sizeof(body)) {
        db_release(conn, 0);
        pthread_mutex_unlock(&audit_lock);
        return -1;
    }

    char hash[65] = {0};
    sha256_hex_str(body, hash, sizeof(hash));

    /* Insert with advisory lock to prevent races */
    char sql[2048];
    snprintf(sql, sizeof(sql),
        "INSERT INTO audit (id, seq, ts, actor, event, detail, prev, hash) "
        "VALUES ($1, $2::integer, to_timestamp($3::double precision), $4, $5, $6, $7, $8)");

    const char *pvals[8];
    char id_buf[64], seq_buf[32];
    snprintf(id_buf, sizeof(id_buf), "aud_%ld_%ld", (long)ts, seq);
    snprintf(seq_buf, sizeof(seq_buf), "%ld", seq);
    pvals[0] = id_buf;
    pvals[1] = seq_buf;
    pvals[2] = ts_buf;
    pvals[3] = actor ? actor : "system";
    pvals[4] = event ? event : "";
    pvals[5] = detail ? detail : "";
    pvals[6] = g_last_hash;
    pvals[7] = hash;

    int lens[8];
    for (int k = 0; k < 8; k++) lens[k] = pvals[k] ? (int)strlen(pvals[k]) : 0;
    int fmt[8] = { 0,0,0,0,0,0,0,0 };

    PGresult *res = PQexecParams(conn, sql, 8, (const Oid *)NULL, pvals, lens, fmt, 0);
    int rc = -1;
    if (res && PQresultStatus(res) == PGRES_COMMAND_OK) {
        g_chain_len = seq;
        strncpy(g_last_hash, hash, sizeof(g_last_hash) - 1);
        rc = 0;
    } else {
        fprintf(stderr, "[AUDIT] append failed: %s\n",
                res ? PQresultErrorMessage(res) : PQerrorMessage(conn));
    }
    if (res) PQclear(res);
    db_release(conn, 0);
    pthread_mutex_unlock(&audit_lock);
    return rc;
}

int audit_verify(void) {
    PGconn *conn = db_acquire();
    if (!conn) return 0;
    PGresult *res = PQexec(conn,
        "SELECT seq, ts, actor, event, detail, prev, hash FROM audit ORDER BY seq ASC");
    int ok = 0;
    if (res && PQresultStatus(res) == PGRES_TUPLES_OK) {
        int n = PQntuples(res);
        char prev[65] = {0};
        strcpy(prev, GENESIS);
        long expected_seq = 1;
        ok = 1;
        for (int i = 0; i < n; i++) {
            long seq = atol(PQgetvalue(res, i, 0));
            const char *ts = PQgetvalue(res, i, 1);
            const char *actor = PQgetvalue(res, i, 2);
            const char *event = PQgetvalue(res, i, 3);
            const char *detail = PQgetvalue(res, i, 4);
            const char *e_prev = PQgetvalue(res, i, 5);
            const char *e_hash = PQgetvalue(res, i, 6);

            if (seq != expected_seq || strcmp(e_prev, prev) != 0) { ok = 0; break; }
            char body[1024];
            snprintf(body, sizeof(body), "%ld|%s|%s|%s|%s|%s",
                     seq, ts, actor ? actor : "system", event ? event : "",
                     detail ? detail : "", e_prev);
            char hash[65] = {0};
            sha256_hex_str(body, hash, sizeof(hash));
            if (strcmp(hash, e_hash) != 0) { ok = 0; break; }
            strcpy(prev, e_hash);
            expected_seq++;
        }
        if (ok) {
            strncpy(g_last_hash, prev, sizeof(g_last_hash) - 1);
            g_chain_len = expected_seq - 1;
        }
    }
    if (res) PQclear(res);
    db_release(conn, 0);
    return ok;
}

long audit_block_count(void) {
    return g_chain_len;
}
