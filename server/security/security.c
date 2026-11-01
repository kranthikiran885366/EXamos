/*
 * security.c — Cryptographic primitives, RBAC, TOTP, request signing,
 * mTLS support, rate limiting, and input sanitization for ExamOS server.
 *
 * Implements advanced security required for the console integration:
 *   • PBKDF2-SHA256 password hashing (210,000 iterations)
 *   • TOTP (RFC 6238) for MFA
 *   • ECDSA P-256 signing/verification (policy, release, receipt signatures)
 *   • Console request signature verification (ECDSA P-256)
 *   • Role-based access control (RBAC)
 *   • Token-bucket rate limiting per client IP
 *   • Input sanitization
 */

#include "security.h"
#include "../db/db.h"
#include "../include/admin_auth_store.h"
#include "../include/secure_token.h"
#include "../include/totp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <ctype.h>

/* -----------------------------------------------------------------------
 * RBAC
 * ---------------------------------------------------------------------- */

uint32_t security_role_compute_permissions(user_role_t role) {
    switch (role) {
        case ROLE_PLATFORM_OWNER: return 0xFFFFFFFFu;
        case ROLE_INSTITUTION_ADMIN:
            return AUTH_PERM_READ | AUTH_PERM_EXAM_MUTATION | AUTH_PERM_FLEET_MUTATION |
                   AUTH_PERM_SECURITY_ADMIN | AUTH_PERM_USER_MANAGEMENT |
                   AUTH_PERM_INSTITUTION_ADMIN | AUTH_PERM_EXAM_READ |
                   AUTH_PERM_INCIDENT_READ | AUTH_PERM_MFA_ADMIN |
                   AUTH_PERM_LOCATION_ADMIN | AUTH_PERM_INCIDENT_MUTATION;
        case ROLE_EXAM_MANAGER:
            return AUTH_PERM_READ | AUTH_PERM_EXAM_MUTATION | AUTH_PERM_EXAM_READ |
                   AUTH_PERM_INCIDENT_READ | AUTH_PERM_LOCATION_ADMIN;
        case ROLE_SECURITY_ADMIN:
            return AUTH_PERM_READ | AUTH_PERM_FLEET_MUTATION | AUTH_PERM_SECURITY_ADMIN |
                   AUTH_PERM_INCIDENT_READ | AUTH_PERM_INCIDENT_MUTATION;
        case ROLE_INVIGILATOR:
            return AUTH_PERM_READ | AUTH_PERM_EXAM_READ | AUTH_PERM_INCIDENT_READ |
                   AUTH_PERM_INCIDENT_MUTATION;
        case ROLE_TECH_OPERATOR:
            return AUTH_PERM_READ | AUTH_PERM_FLEET_MUTATION | AUTH_PERM_EXAM_READ |
                   AUTH_PERM_INCIDENT_READ | AUTH_PERM_LOCATION_ADMIN;
        case ROLE_INCIDENT_INVESTIGATOR:
            return AUTH_PERM_READ | AUTH_PERM_INCIDENT_READ;
        case ROLE_READONLY_AUDITOR:
            return AUTH_PERM_READ;
        case ROLE_SUPPORT_ENGINEER:
            return AUTH_PERM_READ | AUTH_PERM_INCIDENT_READ;
        default:
            return 0;
    }
}

const char *security_role_to_string(user_role_t role) {
    switch (role) {
        case ROLE_PLATFORM_OWNER: return "PLATFORM_OWNER";
        case ROLE_INSTITUTION_ADMIN: return "INSTITUTION_ADMIN";
        case ROLE_EXAM_MANAGER: return "EXAM_MANAGER";
        case ROLE_SECURITY_ADMIN: return "SECURITY_ADMIN";
        case ROLE_INVIGILATOR: return "INVIGILATOR";
        case ROLE_TECH_OPERATOR: return "TECH_OPERATOR";
        case ROLE_INCIDENT_INVESTIGATOR: return "INCIDENT_INVESTIGATOR";
        case ROLE_READONLY_AUDITOR: return "READONLY_AUDITOR";
        case ROLE_SUPPORT_ENGINEER: return "SUPPORT_ENGINEER";
        default: return "UNKNOWN";
    }
}

int security_role_has_permission(user_role_t role, uint32_t permission) {
    if (role == ROLE_PLATFORM_OWNER) return 1;
    uint32_t perms = security_role_compute_permissions(role);
    return (perms & permission) == permission;
}

int security_verify_session(const char *token, auth_session_t *out) {
    if (!token || !out) return -1;
    memset(out, 0, sizeof(*out));

    /* Check auth_sessions in DB.  Only the SHA-256 digest of the bearer token
     * is persisted, so hash before lookup: a leaked database must not yield
     * replayable session tokens. */
    char token_hash[EXAMOS_TOKEN_HEX_LEN + 1] = {0};
    if (secure_token_hash(token, token_hash) != 0) return -1;
    PGconn *conn = db_acquire();
    if (conn) {
        const char *params[1] = { token_hash };
        int lens[1] = { (int)strlen(token_hash) };
        PGresult *res = db_simple(conn,
            "SELECT user_id, username, institution_id, role, expires_at "
            "FROM auth_sessions WHERE session_token = $1 AND status = 'active'"
            " AND expires_at > EXTRACT(EPOCH FROM clock_timestamp())::bigint",
            1, params, lens);
        if (res && PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0) {
            strncpy(out->user_id, PQgetvalue(res, 0, 0), sizeof(out->user_id) - 1);
            strncpy(out->username, PQgetvalue(res, 0, 1), sizeof(out->username) - 1);
            strncpy(out->institution_id, PQgetvalue(res, 0, 2), sizeof(out->institution_id) - 1);
            const char *role_str = PQgetvalue(res, 0, 3);
            /* Default deny.  Candidate/student sessions share the auth_sessions
             * table, so an unknown or non-management role must invalidate the
             * session rather than being promoted to a read-only admin role. */
            int role_ok = 1;
            if (strcmp(role_str, "PLATFORM_OWNER") == 0 || strcmp(role_str, "superadmin") == 0) out->role = ROLE_PLATFORM_OWNER;
            else if (strcmp(role_str, "INSTITUTION_ADMIN") == 0 || strcmp(role_str, "inst_admin") == 0) out->role = ROLE_INSTITUTION_ADMIN;
            else if (strcmp(role_str, "EXAM_MANAGER") == 0 || strcmp(role_str, "exam_controller") == 0) out->role = ROLE_EXAM_MANAGER;
            else if (strcmp(role_str, "SECURITY_ADMIN") == 0 || strcmp(role_str, "security_engineer") == 0) out->role = ROLE_SECURITY_ADMIN;
            else if (strcmp(role_str, "INVIGILATOR") == 0 || strcmp(role_str, "invigilator") == 0) out->role = ROLE_INVIGILATOR;
            else if (strcmp(role_str, "TECH_OPERATOR") == 0 || strcmp(role_str, "ops_admin") == 0 || strcmp(role_str, "it_admin") == 0) out->role = ROLE_TECH_OPERATOR;
            else if (strcmp(role_str, "INCIDENT_INVESTIGATOR") == 0) out->role = ROLE_INCIDENT_INVESTIGATOR;
            else if (strcmp(role_str, "READONLY_AUDITOR") == 0 || strcmp(role_str, "auditor") == 0) out->role = ROLE_READONLY_AUDITOR;
            else if (strcmp(role_str, "SUPPORT_ENGINEER") == 0 || strcmp(role_str, "support") == 0) out->role = ROLE_SUPPORT_ENGINEER;
            else role_ok = 0;

            if (!role_ok) {
                PQclear(res);
                db_release(conn, 0);
                memset(out, 0, sizeof(*out));
                return -1;
            }

            out->expires_at = (time_t)strtoll(PQgetvalue(res, 0, 4), NULL, 10);
            PQclear(res);
            db_release(conn, 0);

            if (out->expires_at < time(NULL)) {
                memset(out, 0, sizeof(*out));
                return -1; /* expired */
            }
            return 0;
        }
        if (res) PQclear(res);
        db_release(conn, 0);
    }

    /* Fallback to admin_auth_store (examos_admin_sessions) */
    return admin_auth_store_verify(token, out);
}

/* -----------------------------------------------------------------------
 * Password hashing (PBKDF2-SHA256)
 * ---------------------------------------------------------------------- */
int security_pbkdf2_hash(const char *password, const char *salt,
                         char *out, size_t out_len) {
    if (!password || !salt || !out || out_len < 65) return -1;
    unsigned char key[32];
    if (!PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
                           (const unsigned char *)salt, (int)strlen(salt),
                           210000, EVP_sha256(), 32, key))
        return -1;
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[i * 2] = hex[key[i] >> 4];
        out[i * 2 + 1] = hex[key[i] & 0x0f];
    }
    out[64] = '\0';
    return 0;
}

int security_safe_equal(const char *a, const char *b) {
    if (!a || !b) return 0;
    size_t la = strlen(a), lb = strlen(b);
    if (la != lb) return 0;
    int diff = 0;
    for (size_t i = 0; i < la; i++) diff |= (unsigned char)a[i] ^ (unsigned char)b[i];
    return diff == 0;
}

/* -----------------------------------------------------------------------
 * TOTP (RFC 6238)
 * ---------------------------------------------------------------------- */
static const char base32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

int security_totp_generate_secret(char *out, size_t out_len) {
    if (!out || out_len < 17) return -1;
    unsigned char raw[10];
    if (RAND_bytes(raw, sizeof(raw)) != 1) return -1;
    int j = 0;
    for (size_t i = 0; i < sizeof(raw) && j + 7 < (int)out_len; i++) {
        unsigned int v = raw[i];
        for (int sh = 35; sh >= 0 && j + 1 < (int)out_len; sh -= 5) {
            out[j++] = base32[(v >> sh) & 0x1f];
        }
    }
    out[j] = '\0';
    return 0;
}

static int b32_decode_char(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= '2' && c <= '7') return c - '2' + 26;
    return -1;
}

int security_totp_verify(const char *secret, const char *code) {
    if (!secret || !code) return 0;
    /* Delegate entirely to the canonical totp.c implementation which has
     * a correct base32 decoder and constant-time comparison. */
    return totp_verify_code(secret, code, time(NULL), 1);
}

/* -----------------------------------------------------------------------
 * ECDSA P-256
 * ---------------------------------------------------------------------- */
int security_ecdsa_generate_keypair(char *priv_pem, size_t priv_len,
                                    char *pub_pem, size_t pub_len) {
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pkey || !ctx) { EVP_PKEY_free(pkey); EVP_PKEY_CTX_free(ctx); return -1; }
    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_free(pkey); EVP_PKEY_CTX_free(ctx);
        return -1;
    }
    BIO *bp = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bp, pkey, NULL, NULL, 0, NULL, NULL);
    char *pkey_data = NULL;
    long plen = BIO_get_mem_data(bp, &pkey_data);
    BIO *bp2 = BIO_new(BIO_s_mem());
    BIO_write(bp2, pkey_data, (int)plen);
    /* Get private key */
    char *pdata = NULL; long plen2 = BIO_get_mem_data(bp2, &pdata);
    if (plen2 > 0 && (size_t)plen2 < priv_len) { memcpy(priv_pem, pdata, plen2); priv_pem[plen2] = '\0'; }
    BIO_free(bp2);

    /* Public key */
    BIO *bp3 = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bp3, pkey);
    char *pdata2 = NULL; long plen3 = BIO_get_mem_data(bp3, &pdata2);
    if (plen3 > 0 && (size_t)plen3 < pub_len) { memcpy(pub_pem, pdata2, plen3); pub_pem[plen3] = '\0'; }
    BIO_free(bp3);
    BIO_free(bp);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return 0;
}

int security_ecdsa_sign_pem(const char *pem_private_key, const unsigned char *data,
                            size_t data_len, char *out_sig_hex, size_t out_len) {
    BIO *bp = BIO_new_mem_buf((void *)pem_private_key, -1);
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bp, NULL, NULL, NULL);
    BIO_free(bp);
    if (!pkey) return -1;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char sig[256];
    size_t sig_len = 0;
    int rc = -1;
    if (ctx && EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey) > 0 &&
        EVP_DigestSignUpdate(ctx, data, data_len) > 0 &&
        EVP_DigestSignFinal(ctx, sig, &sig_len) > 0) {
        static const char hex[] = "0123456789abcdef";
        if (sig_len * 2 + 1 <= out_len) {
            for (size_t i = 0; i < sig_len; i++) {
                out_sig_hex[i * 2] = hex[sig[i] >> 4];
                out_sig_hex[i * 2 + 1] = hex[sig[i] & 0x0f];
            }
            out_sig_hex[sig_len * 2] = '\0';
            rc = 0;
        }
    }
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return rc;
}

int security_ecdsa_verify_pem(const char *pem_public_key, const unsigned char *data,
                              size_t data_len, const char *sig_hex) {
    BIO *bp = BIO_new_mem_buf((void *)pem_public_key, -1);
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bp, NULL, NULL, NULL);
    BIO_free(bp);
    if (!pkey) return 0;

    /* Decode hex sig */
    size_t sig_len = strlen(sig_hex) / 2;
    unsigned char sig[256];
    for (size_t i = 0; i < sig_len; i++) {
        unsigned int v;
        sscanf(sig_hex + i * 2, "%2x", &v);
        sig[i] = (unsigned char)v;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = 0;
    if (ctx && EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) > 0 &&
        EVP_DigestVerifyUpdate(ctx, data, data_len) > 0 &&
        EVP_DigestVerifyFinal(ctx, sig, sig_len) > 0) {
        ok = 1;
    }
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok;
}

/* -----------------------------------------------------------------------
 * Console request signature verification
 * ---------------------------------------------------------------------- */
int security_verify_request_signature(const char *public_key_pem,
                                      const char *canonical,
                                      const char *signature_hex) {
    return security_ecdsa_verify_pem(public_key_pem,
                                     (const unsigned char *)canonical, strlen(canonical),
                                     signature_hex);
}

/* SHA-256 hex digest */
void security_sha256_hex(const char *input, char *out, size_t out_len) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)input, strlen(input), hash);
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < SHA256_DIGEST_LENGTH && i * 2 + 1 < (int)out_len; i++) {
        out[i * 2] = hex[hash[i] >> 4];
        out[i * 2 + 1] = hex[hash[i] & 0x0f];
    }
    if (out_len > 0) out[SHA256_DIGEST_LENGTH * 2] = '\0';
}

/* -----------------------------------------------------------------------
 * mTLS CA bundle
 * ---------------------------------------------------------------------- */
static STACK_OF(X509_NAME) *g_ca_names = NULL;

int security_load_ca_bundle(const char *ca_path) {
    if (!ca_path || !ca_path[0]) return 0;
    FILE *f = fopen(ca_path, "r");
    if (!f) return -1;
    X509 *cert;
    g_ca_names = sk_X509_NAME_new_null();
    while ((cert = PEM_read_X509(f, NULL, NULL, NULL)) != NULL) {
        X509_NAME *name = X509_get_subject_name(cert);
        sk_X509_NAME_push(g_ca_names, name);
        X509_free(cert);
    }
    fclose(f);
    return 0;
}

/* -----------------------------------------------------------------------
 * Rate limiting
 * ---------------------------------------------------------------------- */
rate_bucket_t g_rate_buckets[256];
int g_rate_bucket_count = 0;
static pthread_mutex_t rate_lock = PTHREAD_MUTEX_INITIALIZER;

int security_rate_check(const char *ip) {
    if (!ip || !ip[0]) return 1;
    pthread_mutex_lock(&rate_lock);
    time_t now = time(NULL);
    /* Find existing bucket */
    for (int i = 0; i < g_rate_bucket_count; i++) {
        if (strcmp(g_rate_buckets[i].ip, ip) == 0) {
            if (now - g_rate_buckets[i].window_start >= RATE_LIMIT_WINDOW_SEC) {
                g_rate_buckets[i].count = 1;
                g_rate_buckets[i].window_start = now;
                pthread_mutex_unlock(&rate_lock);
                return 1;
            }
            if (g_rate_buckets[i].count >= RATE_LIMIT_MAX_REQUESTS) {
                pthread_mutex_unlock(&rate_lock);
                return 0;
            }
            g_rate_buckets[i].count++;
            pthread_mutex_unlock(&rate_lock);
            return 1;
        }
    }
    /* Create new bucket */
    if (g_rate_bucket_count < 256) {
        strncpy(g_rate_buckets[g_rate_bucket_count].ip, ip,
                sizeof(g_rate_buckets[g_rate_bucket_count].ip) - 1);
        g_rate_buckets[g_rate_bucket_count].ip[sizeof(g_rate_buckets[g_rate_bucket_count].ip) - 1] = '\0';
        g_rate_buckets[g_rate_bucket_count].count = 1;
        g_rate_buckets[g_rate_bucket_count].window_start = now;
        g_rate_bucket_count++;
    }
    pthread_mutex_unlock(&rate_lock);
    return 1;
}

/* -----------------------------------------------------------------------
 * Input sanitization
 * ---------------------------------------------------------------------- */
int security_sanitize(const char *input, char *out, size_t out_len) {
    if (!input || !out || out_len == 0) return 0;
    size_t j = 0;
    for (size_t i = 0; input[i] && j + 1 < out_len; i++) {
        unsigned char c = (unsigned char)input[i];
        if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') continue;
        if (c == 0x7f) continue;
        out[j++] = (char)c;
    }
    out[j] = '\0';
    return (int)j;
}
