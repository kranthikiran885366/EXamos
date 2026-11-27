#define _GNU_SOURCE
#include "../include/offline_buffer.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define WAL_MAGIC 0x45584F42U /* "EXOB" */
#define WAL_IV_LEN 12
#define WAL_TAG_LEN 16
#define WAL_HMAC_LEN 32
#define WAL_MAX_RECORD (64 * 1024)

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t type_len;
    uint32_t payload_len;
    uint8_t iv[WAL_IV_LEN];
    uint8_t tag[WAL_TAG_LEN];
    uint8_t hmac[WAL_HMAC_LEN];
} wal_record_hdr_t;

static pthread_mutex_t g_wal_lock = PTHREAD_MUTEX_INITIALIZER;
static char g_wal_path[512] = "/var/lib/examos/offline-events.wal";
static unsigned char g_enc_key[32];
static unsigned char g_mac_key[32];
static int g_wal_ready = 0;

static int derive_subkey(const unsigned char master[32], const char *label,
                         unsigned char out[32]) {
    unsigned int out_len = 0;
    if (!HMAC(EVP_sha256(), master, 32, (const unsigned char *)label,
              strlen(label), out, &out_len) ||
        out_len != 32) {
        return -1;
    }
    return 0;
}

static int compute_record_hmac(const wal_record_hdr_t *hdr,
                               const uint8_t *ciphertext, size_t ct_len,
                               uint8_t out_mac[WAL_HMAC_LEN]) {
    HMAC_CTX *ctx = HMAC_CTX_new();
    if (!ctx) return -1;
    unsigned int mac_len = 0;
    int ok = HMAC_Init_ex(ctx, g_mac_key, sizeof(g_mac_key), EVP_sha256(), NULL) == 1 &&
             HMAC_Update(ctx, (const uint8_t *)&hdr->magic, sizeof(hdr->magic)) == 1 &&
             HMAC_Update(ctx, (const uint8_t *)&hdr->type_len, sizeof(hdr->type_len)) == 1 &&
             HMAC_Update(ctx, (const uint8_t *)&hdr->payload_len, sizeof(hdr->payload_len)) == 1 &&
             HMAC_Update(ctx, hdr->iv, WAL_IV_LEN) == 1 &&
             HMAC_Update(ctx, hdr->tag, WAL_TAG_LEN) == 1 &&
             HMAC_Update(ctx, ciphertext, ct_len) == 1 &&
             HMAC_Final(ctx, out_mac, &mac_len) == 1 &&
             mac_len == WAL_HMAC_LEN;
    HMAC_CTX_free(ctx);
    return ok ? 0 : -1;
}

int offline_buffer_init(const char *wal_path, const unsigned char key32[32]) {
    if (!wal_path || !wal_path[0] || !key32) return -1;
    pthread_mutex_lock(&g_wal_lock);
    snprintf(g_wal_path, sizeof(g_wal_path), "%s", wal_path);
    if (derive_subkey(key32, "examos-wal-aes256gcm", g_enc_key) != 0 ||
        derive_subkey(key32, "examos-wal-hmacsha256", g_mac_key) != 0) {
        pthread_mutex_unlock(&g_wal_lock);
        return -1;
    }
    g_wal_ready = 1;
    pthread_mutex_unlock(&g_wal_lock);
    return 0;
}

int offline_buffer_enqueue(const char *event_type, const char *payload_json) {
    if (!event_type || !payload_json) return -1;
    size_t tlen = strlen(event_type);
    size_t plen = strlen(payload_json);
    if (tlen == 0 || tlen > 256 || plen + tlen + 2 > WAL_MAX_RECORD) return -1;

    pthread_mutex_lock(&g_wal_lock);
    if (!g_wal_ready) {
        pthread_mutex_unlock(&g_wal_lock);
        return -1;
    }

    size_t plain_len = tlen + 1 + plen;
    uint8_t *plain = malloc(plain_len);
    uint8_t *ct = malloc(plain_len);
    if (!plain || !ct) {
        free(plain);
        free(ct);
        pthread_mutex_unlock(&g_wal_lock);
        return -1;
    }
    memcpy(plain, event_type, tlen);
    plain[tlen] = '\0';
    memcpy(plain + tlen + 1, payload_json, plen);

    wal_record_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = WAL_MAGIC;
    hdr.type_len = (uint32_t)tlen;
    hdr.payload_len = (uint32_t)plen;
    if (RAND_bytes(hdr.iv, WAL_IV_LEN) != 1) {
        OPENSSL_cleanse(plain, plain_len);
        free(plain);
        free(ct);
        pthread_mutex_unlock(&g_wal_lock);
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, total = 0;
    int ok = ctx &&
             EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
             EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, WAL_IV_LEN, NULL) == 1 &&
             EVP_EncryptInit_ex(ctx, NULL, NULL, g_enc_key, hdr.iv) == 1 &&
             EVP_EncryptUpdate(ctx, ct, &len, plain, (int)plain_len) == 1 &&
             (total = len, EVP_EncryptFinal_ex(ctx, ct + total, &len) == 1) &&
             (total += len, (size_t)total == plain_len) &&
             EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, WAL_TAG_LEN, hdr.tag) == 1;
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(plain, plain_len);
    free(plain);

    if (!ok || compute_record_hmac(&hdr, ct, plain_len, hdr.hmac) != 0) {
        free(ct);
        pthread_mutex_unlock(&g_wal_lock);
        return -1;
    }

    int fd = open(g_wal_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0) {
        free(ct);
        pthread_mutex_unlock(&g_wal_lock);
        return -1;
    }
    ssize_t w1 = write(fd, &hdr, sizeof(hdr));
    ssize_t w2 = write(fd, ct, plain_len);
    int sync_rc = fsync(fd);
    close(fd);
    free(ct);
    pthread_mutex_unlock(&g_wal_lock);

    return (w1 == (ssize_t)sizeof(hdr) && w2 == (ssize_t)plain_len && sync_rc == 0) ? 0 : -1;
}

int offline_buffer_flush(offline_buffer_flush_cb cb, void *user_ctx) {
    if (!cb) return -1;
    pthread_mutex_lock(&g_wal_lock);
    if (!g_wal_ready) {
        pthread_mutex_unlock(&g_wal_lock);
        return -1;
    }

    int fd = open(g_wal_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        int rc = (errno == ENOENT) ? 0 : -1;
        pthread_mutex_unlock(&g_wal_lock);
        return rc;
    }

    char tmp_path[528];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", g_wal_path);
    int tmp_fd = -1;
    int flushed = 0;
    int stop_flushing = 0;

    for (;;) {
        wal_record_hdr_t hdr;
        ssize_t n = read(fd, &hdr, sizeof(hdr));
        if (n == 0) break;
        if (n != (ssize_t)sizeof(hdr) || hdr.magic != WAL_MAGIC ||
            hdr.type_len == 0 || hdr.type_len > 256 ||
            (size_t)hdr.type_len + 1 + (size_t)hdr.payload_len > WAL_MAX_RECORD) {
            break;
        }
        size_t ct_len = (size_t)hdr.type_len + 1 + (size_t)hdr.payload_len;
        uint8_t *ct = malloc(ct_len);
        uint8_t *plain = malloc(ct_len + 1);
        if (!ct || !plain || read(fd, ct, ct_len) != (ssize_t)ct_len) {
            free(ct);
            free(plain);
            break;
        }

        if (!stop_flushing) {
            uint8_t expected_mac[WAL_HMAC_LEN];
            if (compute_record_hmac(&hdr, ct, ct_len, expected_mac) == 0 &&
                CRYPTO_memcmp(expected_mac, hdr.hmac, WAL_HMAC_LEN) == 0) {
                EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
                int len = 0, total = 0;
                int ok = ctx &&
                         EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
                         EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, WAL_IV_LEN, NULL) == 1 &&
                         EVP_DecryptInit_ex(ctx, NULL, NULL, g_enc_key, hdr.iv) == 1 &&
                         EVP_DecryptUpdate(ctx, plain, &len, ct, (int)ct_len) == 1 &&
                         (total = len, EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, WAL_TAG_LEN, hdr.tag) == 1) &&
                         EVP_DecryptFinal_ex(ctx, plain + total, &len) == 1 &&
                         (total += len, (size_t)total == ct_len);
                if (ctx) EVP_CIPHER_CTX_free(ctx);

                if (ok) {
                    plain[ct_len] = '\0';
                    const char *etype = (const char *)plain;
                    const char *epayload = (const char *)(plain + hdr.type_len + 1);
                    if (cb(etype, epayload, user_ctx) == 0) {
                        flushed++;
                        OPENSSL_cleanse(plain, ct_len + 1);
                        free(ct);
                        free(plain);
                        continue;
                    }
                    stop_flushing = 1;
                }
            }
        }

        /* Keep unflushed record in temp WAL */
        if (tmp_fd < 0) {
            tmp_fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        }
        if (tmp_fd >= 0) {
            (void)write(tmp_fd, &hdr, sizeof(hdr));
            (void)write(tmp_fd, ct, ct_len);
        }
        OPENSSL_cleanse(plain, ct_len + 1);
        free(ct);
        free(plain);
    }

    close(fd);
    if (tmp_fd >= 0) {
        fsync(tmp_fd);
        close(tmp_fd);
        rename(tmp_path, g_wal_path);
    } else if (!stop_flushing && flushed > 0) {
        unlink(g_wal_path);
    }
    pthread_mutex_unlock(&g_wal_lock);
    return flushed;
}

size_t offline_buffer_pending_count(void) {
    pthread_mutex_lock(&g_wal_lock);
    int fd = open(g_wal_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        pthread_mutex_unlock(&g_wal_lock);
        return 0;
    }
    size_t count = 0;
    wal_record_hdr_t hdr;
    while (read(fd, &hdr, sizeof(hdr)) == (ssize_t)sizeof(hdr)) {
        if (hdr.magic != WAL_MAGIC) break;
        off_t skip = (off_t)hdr.type_len + 1 + (off_t)hdr.payload_len;
        if (lseek(fd, skip, SEEK_CUR) < 0) break;
        count++;
    }
    close(fd);
    pthread_mutex_unlock(&g_wal_lock);
    return count;
}

void offline_buffer_shutdown(void) {
    pthread_mutex_lock(&g_wal_lock);
    OPENSSL_cleanse(g_enc_key, sizeof(g_enc_key));
    OPENSSL_cleanse(g_mac_key, sizeof(g_mac_key));
    g_wal_ready = 0;
    pthread_mutex_unlock(&g_wal_lock);
}
