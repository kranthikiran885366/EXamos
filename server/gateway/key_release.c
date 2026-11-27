#define _GNU_SOURCE
#include "../include/key_release.h"
#include "../include/attestation_service.h"
#include "../include/ledger.h"
#include "../db/db.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int key_release_get_session_key(const char *session_id,
                                char *out_exam_key, size_t max_len,
                                const char *device_id,
                                char *out_error_code) {
    (void)session_id;
    (void)device_id;
    (void)max_len;
    if (out_exam_key) out_exam_key[0] = '\0';
    if (out_error_code)
        snprintf(out_error_code, 64, "P3_DEVICE_BOUND_TRANSPORT_UNAVAILABLE");
    return -1;
}

int key_release_check_eligibility(const char *session_id,
                                  const char *device_id,
                                  char *out_reason) {
    (void)session_id;
    (void)device_id;
    if (out_reason)
        snprintf(out_reason, 64, "P3_DEVICE_BOUND_TRANSPORT_UNAVAILABLE");
    return -1;
}

int key_release_wrap_session_key(const char *candidate_id,
                                 const char *session_id,
                                 const char *device_id,
                                 char *out_envelope,
                                 size_t envelope_len,
                                 char *out_error_code) {
    if (!candidate_id || !candidate_id[0] || !session_id || !session_id[0] ||
        !device_id || !device_id[0] || !out_envelope || envelope_len < 512) {
        if (out_error_code) snprintf(out_error_code, 64, "P3_INVALID_REQUEST");
        return -1;
    }
    out_envelope[0] = '\0';
    if (out_error_code) out_error_code[0] = '\0';

    PGconn *conn = db_acquire();
    if (!conn) {
        if (out_error_code) snprintf(out_error_code, 64, "P3_DATABASE_UNAVAILABLE");
        return -1;
    }
    const char *params[3] = { session_id, device_id, candidate_id };
    int lengths[3] = { (int)strlen(session_id), (int)strlen(device_id),
                       (int)strlen(candidate_id) };
    PGresult *res = db_simple(conn,
        "SELECT ek.ek_public_key_pem,ek.ek_public_key_fingerprint,"
        "       ek.trust_status,c.state,c.purpose,c.verified_at,c.attestation_id "
        "FROM exam_sessions s "
        "JOIN candidates cnd ON cnd.id=$3 AND cnd.exam_id=s.examination_id "
        "JOIN examos_attestation_challenges c ON c.session_id=s.id "
        "JOIN device_ek_certificates ek ON ek.device_id=s.device_id "
        "WHERE s.id=$1 AND s.device_id=$2 "
        "AND s.status IN ('authorized','launching','active','interrupted','resuming') "
        "AND c.purpose='exam_launch' AND c.state='TRUSTED' "
        "AND c.verified_at>clock_timestamp()-interval '10 minutes' "
        "AND ek.trust_status='verified' "
        "AND NOT EXISTS (SELECT 1 FROM examos_attestation_revocations r "
        "WHERE r.target_type='DEVICE' AND r.target_id=s.device_id) "
        "ORDER BY ek.updated_at DESC,c.verified_at DESC LIMIT 1",
        3, params, lengths);
    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK ||
        PQntuples(res) != 1) {
        if (res) PQclear(res);
        db_release(conn, 0);
        if (out_error_code) snprintf(out_error_code, 64, "P3_SESSION_NOT_ELIGIBLE");
        return -1;
    }
    const char *ek_pem = PQgetvalue(res, 0, 0);
    const char *ek_fingerprint = PQgetvalue(res, 0, 1);
    const char *attestation_id = PQgetvalue(res, 0, 6);
    char ek_pem_copy[4096];
    char ek_fingerprint_copy[256];
    char attestation_id_copy[128];
    if (!ek_pem || !ek_pem[0] || strlen(ek_pem) >= sizeof(ek_pem_copy) ||
        !ek_fingerprint || !ek_fingerprint[0] || strlen(ek_fingerprint) >= sizeof(ek_fingerprint_copy) ||
        !attestation_id || !attestation_id[0] || strlen(attestation_id) >= sizeof(attestation_id_copy)) {
        PQclear(res); db_release(conn, 0);
        if (out_error_code) snprintf(out_error_code, 64, "P3_EK_INVALID");
        return -1;
    }
    snprintf(ek_pem_copy, sizeof(ek_pem_copy), "%s", ek_pem);
    snprintf(ek_fingerprint_copy, sizeof(ek_fingerprint_copy), "%s", ek_fingerprint);
    snprintf(attestation_id_copy, sizeof(attestation_id_copy), "%s", attestation_id);
    PQclear(res);
    db_release(conn, 0);

    char exam_key_hex[65] = {0};
    if (attestation_get_exam_key(session_id, device_id,
                                 exam_key_hex, sizeof(exam_key_hex)) != 0 ||
        strlen(exam_key_hex) != 64) {
        OPENSSL_cleanse(exam_key_hex, sizeof(exam_key_hex));
        if (out_error_code) snprintf(out_error_code, 64, "P3_KEY_UNAVAILABLE");
        return -1;
    }
    unsigned char plain[32];
    for (size_t i = 0; i < 32; i++) {
        unsigned int value = 0;
        if (sscanf(exam_key_hex + i * 2, "%2x", &value) != 1) {
            OPENSSL_cleanse(exam_key_hex, sizeof(exam_key_hex));
            if (out_error_code) snprintf(out_error_code, 64, "P3_KEY_INVALID");
            return -1;
        }
        plain[i] = (unsigned char)value;
    }

    BIO *bio = BIO_new_mem_buf(ek_pem_copy, -1);
    EVP_PKEY *ek = bio ? PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL) : NULL;
    if (bio) BIO_free(bio);
    if (!ek || EVP_PKEY_base_id(ek) != EVP_PKEY_RSA ||
        EVP_PKEY_bits(ek) < 2048) {
        if (ek) EVP_PKEY_free(ek);
        OPENSSL_cleanse(ek_pem_copy, sizeof(ek_pem_copy));
        OPENSSL_cleanse(exam_key_hex, sizeof(exam_key_hex));
        OPENSSL_cleanse(plain, sizeof(plain));
        if (out_error_code) snprintf(out_error_code, 64, "P3_EK_INVALID");
        return -1;
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(ek, NULL);
    size_t wrapped_len = 0;
    unsigned char *wrapped = NULL;
    int ok = ctx &&
             EVP_PKEY_encrypt_init(ctx) == 1 &&
             EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) > 0 &&
             EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) > 0 &&
             EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) > 0 &&
             EVP_PKEY_encrypt(ctx, NULL, &wrapped_len, plain, sizeof(plain)) == 1 &&
             wrapped_len <= 4096;
    if (ok) {
        wrapped = malloc(wrapped_len);
        ok = wrapped &&
             EVP_PKEY_encrypt(ctx, wrapped, &wrapped_len, plain,
                              sizeof(plain)) == 1;
    }
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(ek);
    if (!ok || !wrapped) {
        free(wrapped);
        OPENSSL_cleanse(ek_pem_copy, sizeof(ek_pem_copy));
        OPENSSL_cleanse(exam_key_hex, sizeof(exam_key_hex));
        OPENSSL_cleanse(plain, sizeof(plain));
        if (out_error_code) snprintf(out_error_code, 64, "P3_ENVELOPE_FAILED");
        return -1;
    }

    size_t base64_capacity = 4 * ((wrapped_len + 2) / 3) + 1;
    char *base64 = malloc(base64_capacity);
    if (!base64) {
        free(wrapped);
        OPENSSL_cleanse(ek_pem_copy, sizeof(ek_pem_copy));
        OPENSSL_cleanse(exam_key_hex, sizeof(exam_key_hex));
        OPENSSL_cleanse(plain, sizeof(plain));
        if (out_error_code) snprintf(out_error_code, 64, "P3_ENVELOPE_FAILED");
        return -1;
    }
    int base64_len = EVP_EncodeBlock((unsigned char *)base64, wrapped,
                                     (int)wrapped_len);
    free(wrapped);
    if (base64_len <= 0 || (size_t)base64_len + 1 > envelope_len) {
        free(base64);
        OPENSSL_cleanse(ek_pem_copy, sizeof(ek_pem_copy));
        OPENSSL_cleanse(exam_key_hex, sizeof(exam_key_hex));
        OPENSSL_cleanse(plain, sizeof(plain));
        if (out_error_code) snprintf(out_error_code, 64, "P3_ENVELOPE_TOO_LARGE");
        return -1;
    }
    int written = snprintf(out_envelope, envelope_len,
        "{\"status\":\"WRAPPED\",\"algorithm\":\"rsa-oaep-sha256\","
        "\"device_id\":\"%s\",\"session_id\":\"%s\","
        "\"recipient_fingerprint\":\"%s\",\"wrapped_key\":\"%.*s\"}",
        device_id, session_id, ek_fingerprint_copy, base64_len, base64);
    if (written > 0 && (size_t)written < envelope_len) {
        unsigned char envelope_digest[SHA256_DIGEST_LENGTH];
        unsigned int envelope_digest_len = 0;
        char envelope_digest_text[72] = "sha256:";
        if (EVP_Digest((const unsigned char *)out_envelope,
                       (size_t)written, envelope_digest,
                       &envelope_digest_len, EVP_sha256(), NULL) == 1 &&
            envelope_digest_len == SHA256_DIGEST_LENGTH) {
            static const char hex[] = "0123456789abcdef";
            for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++) {
                envelope_digest_text[7 + i * 2] = hex[envelope_digest[i] >> 4];
                envelope_digest_text[8 + i * 2] = hex[envelope_digest[i] & 15];
            }
            envelope_digest_text[71] = '\0';
            unsigned char random[16];
            char transport_id[64] = "ket_";
            if (RAND_bytes(random, sizeof(random)) == 1) {
                for (size_t i = 0; i < sizeof(random); i++) {
                    static const char idhex[] = "0123456789abcdef";
                    transport_id[4 + i * 2] = idhex[random[i] >> 4];
                    transport_id[5 + i * 2] = idhex[random[i] & 15];
                }
                transport_id[36] = '\0';
                OPENSSL_cleanse(random, sizeof(random));
                conn = db_acquire();
                if (conn) {
                    char base64_wrapped[4096] = {0};
                    snprintf(base64_wrapped, sizeof(base64_wrapped),
                             "%.*s", base64_len, base64);
                    const char *tp[9] = {
                        transport_id, attestation_id_copy, session_id, candidate_id,
                        device_id, ek_fingerprint_copy,
                        envelope_digest_text, base64_wrapped, "wrapped"
                    };
                    int tl[9];
                    for (int i = 0; i < 9; i++) tl[i] = (int)strlen(tp[i]);
                    PGresult *insert = db_simple(conn,
                        "INSERT INTO examos_exam_key_transports "
                        "(transport_id,attestation_id,session_id,candidate_id,"
                        "device_id,recipient_fingerprint,algorithm,"
                        "envelope_sha256,envelope_base64,state) "
                        "VALUES ($1,$2,$3,$4,$5,$6,'rsa-oaep-sha256',"
                        "$7,$8,$9)",
                        9, tp, tl);
                    if (!insert || PQresultStatus(insert) != PGRES_COMMAND_OK) {
                        if (insert) PQclear(insert);
                        db_release(conn, 1);
                        free(base64);
                        out_envelope[0] = '\0';
                        OPENSSL_cleanse(ek_pem_copy, sizeof(ek_pem_copy));
                        OPENSSL_cleanse(exam_key_hex, sizeof(exam_key_hex));
                        OPENSSL_cleanse(plain, sizeof(plain));
                        if (out_error_code) snprintf(out_error_code, 64,
                                                     "P3_TRANSPORT_PERSISTENCE_FAILED");
                        return -1;
                    }
                    PQclear(insert);
                    db_release(conn, 0);
                } else {
                    free(base64);
                    out_envelope[0] = '\0';
                    if (out_error_code) snprintf(out_error_code, 64,
                                                 "P3_DATABASE_UNAVAILABLE");
                    return -1;
                }
            }
        }
    }
    free(base64);
    OPENSSL_cleanse(ek_pem_copy, sizeof(ek_pem_copy));
    OPENSSL_cleanse(exam_key_hex, sizeof(exam_key_hex));
    OPENSSL_cleanse(plain, sizeof(plain));
    if (written < 0 || (size_t)written >= envelope_len) {
        out_envelope[0] = '\0';
        if (out_error_code) snprintf(out_error_code, 64, "P3_ENVELOPE_TOO_LARGE");
        return -1;
    }
    return 0;
}
