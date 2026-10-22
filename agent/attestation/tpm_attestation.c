#define _GNU_SOURCE
#include "../include/attestation.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <ctype.h>
#include <limits.h>

static int g_tpm_detected = 0;

int tpm_attestation_init(void) {
    struct stat device_stat;
    const char *device = stat("/dev/tpmrm0", &device_stat) == 0 &&
                         S_ISCHR(device_stat.st_mode) ? "/dev/tpmrm0" : "/dev/tpm0";
    g_tpm_detected = stat(device, &device_stat) == 0 && S_ISCHR(device_stat.st_mode);
    const char *ak_handle = getenv("EXAMOS_TPM_AK_HANDLE");
    if (!ak_handle || strlen(ak_handle) != 10 || ak_handle[0] != '0' ||
        (ak_handle[1] != 'x' && ak_handle[1] != 'X')) return -1;
    for (size_t i = 2; i < 10; ++i)
        if (!isxdigit((unsigned char)ak_handle[i])) return -1;
    unsigned long handle = strtoul(ak_handle, NULL, 16);
    if (handle < 0x81000000UL || handle > 0x81ffffffUL) return -1;
    return g_tpm_detected ? 0 : -1;
}

static int run_tpm_quote(const char *handle, const char *nonce,
                         const char *message_path, const char *signature_path) {
    pid_t child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        if (setenv("TPM2TOOLS_TCTI", "tabrmd", 1) != 0) _exit(126);
        char *const argv[] = {
            "tpm2_quote", "--key-context", (char *)handle,
            "--pcr-list", "sha256:0,4,7,11",
            "--qualification", (char *)nonce,
            "--message", (char *)message_path,
            "--signature", (char *)signature_path,
            "--hash-algorithm", "sha256", NULL
        };
        execvp(argv[0], argv);
        _exit(127);
    }
    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static int read_quote_output(const char *path, unsigned char *buffer,
                             size_t capacity, size_t *out_length) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
        (size_t)st.st_size > capacity) {
        close(fd);
        return -1;
    }
    size_t used = 0;
    while (used < (size_t)st.st_size) {
        ssize_t n = read(fd, buffer + used, (size_t)st.st_size - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { close(fd); return -1; }
        used += (size_t)n;
    }
    if (close(fd) != 0) return -1;
    *out_length = used;
    return 0;
}

static void bytes_to_hex(const unsigned char *bytes, size_t length, char *out) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < length; ++i) {
        out[i * 2] = digits[bytes[i] >> 4];
        out[i * 2 + 1] = digits[bytes[i] & 15];
    }
    out[length * 2] = '\0';
}

static int compute_event_log_hash(char *out_hash) {
    const char *paths[] = {
        "/sys/kernel/security/tpm0/binary_bios_measurements",
        "/sys/kernel/security/tpm/binary_bios_measurements",
        NULL
    };

    FILE *f = NULL;
    for (int i = 0; paths[i] != NULL; i++) {
        f = fopen(paths[i], "rb");
        if (f) break;
    }

    if (!f) return -1;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        if (ctx) EVP_MD_CTX_free(ctx);
        fclose(f);
        return -1;
    }

    unsigned char buf[4096];
    size_t n = 0;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        if (EVP_DigestUpdate(ctx, buf, n) != 1) {
            EVP_MD_CTX_free(ctx);
            fclose(f);
            return -1;
        }
    }
    if (ferror(f)) { EVP_MD_CTX_free(ctx); fclose(f); return -1; }
    fclose(f);

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    int digest_ok = EVP_DigestFinal_ex(ctx, hash, &hash_len) == 1 && hash_len == SHA256_DIGEST_LENGTH;
    EVP_MD_CTX_free(ctx);
    if (!digest_ok) return -1;

    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(out_hash + (i * 2), "%02x", hash[i]);
    }
    out_hash[64] = '\0';
    return 0;
}

int tpm_attestation_generate_report(const char *device_id, const char *release_id, const char *nonce, attestation_report_t *report) {
    if (!report || !device_id || !*device_id || !release_id || !*release_id || !nonce || !*nonce) return -1;
    if (!g_tpm_detected) return -1;
    memset(report, 0, sizeof(attestation_report_t));

    report->timestamp = (long)time(NULL);
    if (strlen(device_id) >= sizeof(report->device_id) || strlen(release_id) >= sizeof(report->release_id) || strlen(nonce) >= sizeof(report->nonce)) return -1;
    if (strlen(nonce) != 64) return -1;
    for (size_t i = 0; i < 64; ++i)
        if (!isxdigit((unsigned char)nonce[i])) return -1;
    snprintf(report->device_id, sizeof(report->device_id), "%s", device_id);
    snprintf(report->release_id, sizeof(report->release_id), "%s", release_id);
    snprintf(report->nonce, sizeof(report->nonce), "%s", nonce);
    report->tpm_hardware_detected = g_tpm_detected;

    const char *handle = getenv("EXAMOS_TPM_AK_HANDLE");
    char work_dir[] = "/tmp/examos-tpm-quote.XXXXXX";
    if (!handle || !mkdtemp(work_dir)) return -1;
    chmod(work_dir, 0700);
    char message_path[PATH_MAX], signature_path[PATH_MAX];
    int a = snprintf(message_path, sizeof(message_path), "%s/quote.attest", work_dir);
    int b = snprintf(signature_path, sizeof(signature_path), "%s/quote.signature", work_dir);
    if (a < 0 || (size_t)a >= sizeof(message_path) ||
        b < 0 || (size_t)b >= sizeof(signature_path)) {
        rmdir(work_dir);
        return -1;
    }
    if (run_tpm_quote(handle, nonce, message_path, signature_path) != 0) {
        unlink(message_path); unlink(signature_path); rmdir(work_dir);
        return -1;
    }
    unsigned char message[4096], signature[1024];
    size_t message_len = 0, signature_len = 0;
    int loaded = read_quote_output(message_path, message, sizeof(message), &message_len) == 0 &&
                 read_quote_output(signature_path, signature, sizeof(signature), &signature_len) == 0;
    unlink(message_path); unlink(signature_path); rmdir(work_dir);
    if (!loaded || message_len * 2 + 1 > sizeof(report->quote_message_hex) ||
        signature_len * 2 + 1 > sizeof(report->quote_signature_hex)) return -1;
    bytes_to_hex(message, message_len, report->quote_message_hex);
    bytes_to_hex(signature, signature_len, report->quote_signature_hex);
    OPENSSL_cleanse(message, sizeof(message));
    OPENSSL_cleanse(signature, sizeof(signature));
    (void)compute_event_log_hash(report->event_log_hash);
    return 0;
}

int tpm_attestation_format_json(const attestation_report_t *report, char *out_buf, size_t max_len) {
    if (!report || !out_buf || max_len == 0) return -1;

    int written = snprintf(out_buf, max_len,
             "{"
             "\"timestamp\":%ld,"
             "\"device_id\":\"%s\","
             "\"release_id\":\"%s\","
             "\"nonce\":\"%s\","
             "\"tpm_hardware\":%s,"
             "\"ek_fingerprint\":\"%s\","
             "\"ak_pub\":\"%s\","
             "\"quote_message_hex\":\"%s\","
             "\"quote_signature_hex\":\"%s\","
             "\"event_log_hash\":\"%s\","
             "\"pcrs\":{},"
             "\"composite_digest\":\"%s\""
             "}",
             report->timestamp,
             report->device_id,
             report->release_id,
             report->nonce,
             report->tpm_hardware_detected ? "true" : "false",
             report->ek_fingerprint,
             report->ak_pub_hex,
             report->quote_message_hex,
             report->quote_signature_hex,
             report->event_log_hash,
             report->composite_digest);

    return written >= 0 && (size_t)written < max_len ? 0 : -1;
}
