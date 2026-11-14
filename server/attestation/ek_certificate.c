/*
 * ek_certificate.c - EK Certificate Validation for TPM 2.0 Provenance
 *
 * Implements EK certificate chain validation, trust anchor verification,
 * and certificate expiration checking for genuine TPM identity verification.
 */

#define _GNU_SOURCE
#include "../include/ek_certificate.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_CERT_CHAIN_DEPTH 10

typedef struct {
    char anchor_id[64];
    char anchor_name[128];
    char certificate_pem[4096];
    char certificate_fingerprint[65];
    char parent_anchor_id[64];
    char status[32];
    long long valid_from;
    long long valid_until;
} trust_anchor_t;

static trust_anchor_t g_anchors[32];
static int g_anchor_count = 0;

/* Compute SHA-256 fingerprint of a certificate */
static int certificate_fingerprint(X509 *cert, char *out_fingerprint) {
    unsigned char *der = NULL;
    int der_len = i2d_X509(cert, NULL);
    if (der_len <= 0) return -1;
    
    der = malloc(der_len);
    if (!der) return -1;
    
    unsigned char *der_ptr = der;
    i2d_X509(cert, &der_ptr);
    
    unsigned char hash[32];
    unsigned int hash_len = 0;
    if (EVP_Digest(der, der_len, hash, &hash_len, EVP_sha256(), NULL) != 1 || hash_len != 32) {
        free(der);
        return -1;
    }
    
    for (int i = 0; i < 32; i++) {
        sprintf(out_fingerprint + i * 2, "%02x", hash[i]);
    }
    out_fingerprint[64] = '\0';
    
    free(der);
    return 0;
}

/* Validate certificate chain against trust anchors */
static int validate_certificate_chain(STACK_OF(X509) *chain,
                                       const char *ek_fingerprint,
                                       char *out_anchor_id,
                                       char *out_error) {
    if (!chain || sk_X509_num(chain) == 0) {
        if (out_error) snprintf(out_error, 256, "Empty certificate chain");
        return -1;
    }
    
    X509 *ek_cert = sk_X509_value(chain, 0);
    char actual_fp[65];
    if (certificate_fingerprint(ek_cert, actual_fp) != 0) {
        if (out_error) snprintf(out_error, 256, "Failed to compute EK certificate fingerprint");
        return -1;
    }
    
    /* Verify the EK certificate matches the provided fingerprint */
    if (ek_fingerprint && strcasecmp(actual_fp, ek_fingerprint) != 0) {
        if (out_error) snprintf(out_error, 256, "EK certificate fingerprint mismatch");
        return -1;
    }
    
    /* Build X509 store with trust anchors */
    X509_STORE *store = X509_STORE_new();
    if (!store) {
        if (out_error) snprintf(out_error, 256, "Failed to create X509 store");
        return -1;
    }
    
    /* Add all active trust anchors */
    for (int i = 0; i < g_anchor_count; i++) {
        if (strcmp(g_anchors[i].status, "active") != 0) continue;
        
        BIO *bio = BIO_new_mem_buf(g_anchors[i].certificate_pem, -1);
        X509 *anchor_cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        BIO_free(bio);
        
        if (anchor_cert) {
            X509_STORE_add_cert(store, anchor_cert);
            X509_free(anchor_cert);
        }
    }
    
    /* Verify the chain */
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (!ctx) {
        X509_STORE_free(store);
        if (out_error) snprintf(out_error, 256, "Failed to create verification context");
        return -1;
    }
    
    int result = X509_STORE_CTX_init(ctx, store, ek_cert, chain);
    if (result != 1) {
        X509_STORE_CTX_free(ctx);
        X509_STORE_free(store);
        if (out_error) snprintf(out_error, 256, "Failed to initialize verification context");
        return -1;
    }
    
    result = X509_verify_cert(ctx);
    int err = X509_STORE_CTX_get_error(ctx);
    
    if (result != 1) {
        if (out_error) {
            snprintf(out_error, 256, "Certificate verification failed: %s",
                     X509_verify_cert_error_string(err));
        }
        X509_STORE_CTX_free(ctx);
        X509_STORE_free(store);
        return -1;
    }
    
    /* Record the actual root selected by path validation. */
    STACK_OF(X509) *verified_chain = X509_STORE_CTX_get1_chain(ctx);
    X509 *trusted = verified_chain && sk_X509_num(verified_chain) > 0
        ? sk_X509_value(verified_chain, sk_X509_num(verified_chain) - 1) : NULL;
    if (trusted) {
        char trusted_fp[65];
        if (certificate_fingerprint(trusted, trusted_fp) == 0) {
            for (int i = 0; i < g_anchor_count; i++) {
                if (strcmp(g_anchors[i].certificate_fingerprint, trusted_fp) == 0) {
                    if (out_anchor_id) {
                        snprintf(out_anchor_id, 64, "%s", g_anchors[i].anchor_id);
                    }
                    break;
                }
            }
        }
    }
    
    if (verified_chain) sk_X509_pop_free(verified_chain, X509_free);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    return 0;
}

/* Check certificate expiration */
static int check_certificate_expiration(X509 *cert, long long current_time_ms,
                                        char *out_error) {
    const ASN1_TIME *not_before = X509_get0_notBefore(cert);
    const ASN1_TIME *not_after = X509_get0_notAfter(cert);
    
    if (!not_before || !not_after) {
        if (out_error) snprintf(out_error, 256, "Certificate missing validity dates");
        return -1;
    }
    
    /* Use ASN1_TIME_cmp_time_t for modern OpenSSL */
    time_t current = current_time_ms / 1000;
    
    int nb_cmp = ASN1_TIME_cmp_time_t(not_before, current);
    int na_cmp = ASN1_TIME_cmp_time_t(not_after, current);
    
    if (nb_cmp > 0) {
        if (out_error) snprintf(out_error, 256, "Certificate not yet valid");
        return -1;
    }
    
    if (na_cmp < 0) {
        if (out_error) snprintf(out_error, 256, "Certificate expired");
        return -1;
    }
    
    return 0;
}

/* Parse PEM certificate chain */
static STACK_OF(X509)* parse_certificate_chain(const char *pem_chain) {
    BIO *bio = BIO_new_mem_buf(pem_chain, -1);
    if (!bio) return NULL;
    
    STACK_OF(X509) *chain = sk_X509_new_null();
    if (!chain) {
        BIO_free(bio);
        return NULL;
    }
    
    X509 *cert;
    while ((cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        sk_X509_push(chain, cert);
    }
    
    BIO_free(bio);
    
    if (sk_X509_num(chain) == 0) {
        sk_X509_free(chain);
        return NULL;
    }
    
    return chain;
}

/* Extract public key PEM from certificate */
static int extract_public_key_pem(X509 *cert, char *out_pem, size_t max_len) {
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    if (!pkey) return -1;
    
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, pkey);
    EVP_PKEY_free(pkey);
    
    char *data = NULL;
    long len = BIO_get_mem_data(bio, &data);
    
    if (len > 0 && (size_t)len < max_len) {
        memcpy(out_pem, data, len);
        out_pem[len] = '\0';
    }
    
    BIO_free(bio);
    return (len > 0 && (size_t)len < max_len) ? 0 : -1;
}

int ek_certificate_validate(const char *ek_certificate_pem,
                            const char *ek_certificate_chain,
                            const char *ek_fingerprint,
                            char *out_anchor_id,
                            char *out_error,
                            char *out_public_key_pem,
                            size_t max_pem_len) {
    if (!ek_certificate_pem || !ek_certificate_pem[0]) {
        if (out_error) snprintf(out_error, 256, "EK certificate PEM is required");
        return -1;
    }
    
    if (out_anchor_id) out_anchor_id[0] = '\0';
    if (out_error) out_error[0] = '\0';
    if (out_public_key_pem) out_public_key_pem[0] = '\0';
    
    /* Parse certificate chain */
    char full_chain[8192];
    snprintf(full_chain, sizeof(full_chain), "%s\n%s",
             ek_certificate_pem,
             ek_certificate_chain ? ek_certificate_chain : "");
    
    STACK_OF(X509) *chain = parse_certificate_chain(full_chain);
    if (!chain) {
        if (out_error) snprintf(out_error, 256, "Failed to parse certificate chain");
        return -1;
    }
    
    X509 *ek_cert = sk_X509_value(chain, 0);
    
    /* Check expiration */
    long long now = (long long)time(NULL) * 1000;
    if (check_certificate_expiration(ek_cert, now, out_error) != 0) {
        sk_X509_pop_free(chain, X509_free);
        return -1;
    }
    
    /* Validate chain against trust anchors */
    if (validate_certificate_chain(chain, ek_fingerprint, out_anchor_id, out_error) != 0) {
        sk_X509_pop_free(chain, X509_free);
        return -1;
    }
    
    /* Extract public key */
    if (out_public_key_pem && max_pem_len > 0) {
        if (extract_public_key_pem(ek_cert, out_public_key_pem, max_pem_len) != 0) {
            if (out_error) snprintf(out_error, 256, "Failed to extract public key from certificate");
            sk_X509_pop_free(chain, X509_free);
            return -1;
        }
    }
    
    sk_X509_pop_free(chain, X509_free);
    return 0;
}

int ek_certificate_load_trust_anchors(void) {
    g_anchor_count = 0;
    const char *directory = getenv("EXAMOS_EK_TRUST_ANCHORS_DIR");
    const char *mode = getenv("EXAMOS_TPM_MODE");
    int production = mode && strcmp(mode, "production") == 0;
    if (!directory || !directory[0]) {
        if (production) {
            fprintf(stderr,
                    "[EKCert] Production trust is blocked until a provisioned, signed SPPIO TPM trust feed is verified and installed.\n");
            return -1;
        }
        return 0;
    }

    struct stat directory_stat;
    if (lstat(directory, &directory_stat) != 0 ||
        !S_ISDIR(directory_stat.st_mode) || S_ISLNK(directory_stat.st_mode) ||
        (directory_stat.st_mode & 0022) != 0 || directory_stat.st_uid != 0)
        return -1;

    DIR *dir = opendir(directory);
    if (!dir) return -1;
    struct dirent *entry;
    int invalid = 0;
    while ((entry = readdir(dir)) != NULL) {
        size_t name_len = strlen(entry->d_name);
        if (name_len < 5 || strcmp(entry->d_name + name_len - 4, ".pem") != 0)
            continue;
        if (g_anchor_count >= (int)(sizeof(g_anchors) / sizeof(g_anchors[0]))) {
            invalid = 1;
            break;
        }
        char path[PATH_MAX];
        int path_len = snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name);
        if (path_len <= 0 || (size_t)path_len >= sizeof(path)) {
            invalid = 1;
            break;
        }
        struct stat file_stat;
        if (lstat(path, &file_stat) != 0 || !S_ISREG(file_stat.st_mode) ||
            S_ISLNK(file_stat.st_mode) || (file_stat.st_mode & 0022) != 0 ||
            file_stat.st_uid != 0 || file_stat.st_size <= 0 ||
            file_stat.st_size >= (off_t)sizeof(g_anchors[0].certificate_pem)) {
            invalid = 1;
            break;
        }
        FILE *file = fopen(path, "rb");
        if (!file) {
            invalid = 1;
            break;
        }
        char certificate[4096];
        size_t length = fread(certificate, 1, sizeof(certificate) - 1, file);
        int read_error = ferror(file);
        if (fclose(file) != 0 || read_error || length == 0) {
            OPENSSL_cleanse(certificate, sizeof(certificate));
            invalid = 1;
            break;
        }
        certificate[length] = '\0';
        char anchor_id[64];
        if (snprintf(anchor_id, sizeof(anchor_id), "file_%.*s",
                     (int)(sizeof(anchor_id) - 6), entry->d_name) >=
                (int)sizeof(anchor_id) ||
            ek_certificate_add_trust_anchor(anchor_id, entry->d_name,
                                            certificate, NULL) != 0) {
            OPENSSL_cleanse(certificate, sizeof(certificate));
            invalid = 1;
            break;
        }
        OPENSSL_cleanse(certificate, sizeof(certificate));
    }
    if (closedir(dir) != 0) invalid = 1;
    if (invalid || (production && g_anchor_count == 0)) {
        OPENSSL_cleanse(g_anchors, sizeof(g_anchors));
        g_anchor_count = 0;
        return -1;
    }
    return 0;
}

int ek_certificate_add_trust_anchor(const char *anchor_id,
                                    const char *anchor_name,
                                    const char *certificate_pem,
                                    const char *parent_anchor_id) {
    if (!anchor_id || !anchor_id[0] || !anchor_name || !certificate_pem ||
        g_anchor_count >= (int)(sizeof(g_anchors) / sizeof(g_anchors[0])))
        return -1;
    
    BIO *bio = BIO_new_mem_buf(certificate_pem, -1);
    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    
    if (!cert || X509_check_ca(cert) <= 0) {
        X509_free(cert);
        return -1;
    }
    
    trust_anchor_t *anchor = &g_anchors[g_anchor_count];
    snprintf(anchor->anchor_id, sizeof(anchor->anchor_id), "%s", anchor_id);
    snprintf(anchor->anchor_name, sizeof(anchor->anchor_name), "%s", anchor_name);
    snprintf(anchor->certificate_pem, sizeof(anchor->certificate_pem), "%s", certificate_pem);
    snprintf(anchor->parent_anchor_id, sizeof(anchor->parent_anchor_id), "%s",
             parent_anchor_id ? parent_anchor_id : "");
    snprintf(anchor->status, sizeof(anchor->status), "active");
    
    if (certificate_fingerprint(cert, anchor->certificate_fingerprint) != 0) {
        X509_free(cert);
        return -1;
    }
    
    X509_free(cert);
    g_anchor_count++;
    return 0;
}
