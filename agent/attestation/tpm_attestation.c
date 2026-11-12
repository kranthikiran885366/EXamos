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
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <ctype.h>
#include <limits.h>

static int g_tpm_detected = 0;

/* Validate a 10-char 0x-prefixed persistent handle in the 0x81000000-0x81ffffff range. */
static int valid_tpm_handle(const char *h) {
    if (!h || strlen(h) != 10 || h[0] != '0' || (h[1] != 'x' && h[1] != 'X')) return 0;
    for (size_t i = 2; i < 10; ++i)
        if (!isxdigit((unsigned char)h[i])) return 0;
    unsigned long v = strtoul(h, NULL, 16);
    return v >= 0x81000000UL && v <= 0x81ffffffUL;
}

int tpm_attestation_init(void) {
    struct stat device_stat;
    const char *device = stat("/dev/tpmrm0", &device_stat) == 0 &&
                         S_ISCHR(device_stat.st_mode) ? "/dev/tpmrm0" : "/dev/tpm0";
    g_tpm_detected = stat(device, &device_stat) == 0 && S_ISCHR(device_stat.st_mode);
    if (!valid_tpm_handle(getenv("EXAMOS_TPM_AK_HANDLE"))) return -1;
    /* EK handle is optional but must be valid if set */
    const char *ek_handle = getenv("EXAMOS_TPM_EK_HANDLE");
    if (ek_handle && ek_handle[0] && !valid_tpm_handle(ek_handle)) return -1;
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

static void bytes_to_hex(const unsigned char *bytes, size_t length, char *out);

static int run_tpm_tool(char *const arguments[]) {
    pid_t child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        int null_fd = open("/dev/null", O_WRONLY);
        if (null_fd >= 0) {
            dup2(null_fd, STDOUT_FILENO);
            dup2(null_fd, STDERR_FILENO);
            close(null_fd);
        }
        if (setenv("TPM2TOOLS_TCTI", "tabrmd", 1) != 0) _exit(126);
        execvp(arguments[0], arguments);
        _exit(127);
    }
    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static int decode_hex(const char *input, unsigned char *output, size_t output_capacity,
                      size_t *out_length) {
    if (!input || !output || !out_length) return -1;
    size_t input_length = strlen(input);
    if (input_length == 0 || (input_length & 1) != 0 ||
        input_length / 2 > output_capacity) return -1;
    for (size_t i = 0; i < input_length / 2; ++i) {
        unsigned int byte = 0;
        if (sscanf(input + i * 2, "%2x", &byte) != 1 ||
            !isxdigit((unsigned char)input[i * 2]) ||
            !isxdigit((unsigned char)input[i * 2 + 1])) return -1;
        output[i] = (unsigned char)byte;
    }
    *out_length = input_length / 2;
    return 0;
}

static int write_tpm_private_file(const char *path, const void *data, size_t length) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;
    const unsigned char *bytes = data;
    size_t written = 0;
    while (written < length) {
        ssize_t count = write(fd, bytes + written, length - written);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            close(fd);
            return -1;
        }
        written += (size_t)count;
    }
    return close(fd);
}

int tpm_attestation_get_ak_name(char *out_name_hex, size_t out_size) {
    if (!out_name_hex || out_size < 69 || !g_tpm_detected) return -1;
    out_name_hex[0] = '\0';
    const char *handle = getenv("EXAMOS_TPM_AK_HANDLE");
    if (!valid_tpm_handle(handle)) return -1;
    char work_dir[] = "/tmp/examos-tpm-name.XXXXXX";
    char name_path[PATH_MAX];
    if (!mkdtemp(work_dir)) return -1;
    if (chmod(work_dir, 0700) != 0) {
        rmdir(work_dir);
        return -1;
    }
    int path_len = snprintf(name_path, sizeof(name_path), "%s/ak.name", work_dir);
    if (path_len < 0 || (size_t)path_len >= sizeof(name_path)) {
        rmdir(work_dir);
        return -1;
    }
    char *const arguments[] = {
        "tpm2_readpublic", "--object-context", (char *)handle,
        "--name", name_path, NULL
    };
    unsigned char name[64] = {0};
    size_t name_len = 0;
    int result = run_tpm_tool(arguments) == 0 &&
                 read_quote_output(name_path, name, sizeof(name), &name_len) == 0 &&
                 name_len == 34 && name[0] == 0x00 && name[1] == 0x0b;
    if (result) bytes_to_hex(name, name_len, out_name_hex);
    unlink(name_path);
    rmdir(work_dir);
    OPENSSL_cleanse(name, sizeof(name));
    return result ? 0 : -1;
}

int tpm_attestation_activate_credential(const char *credential_blob_hex,
                                        char *out_response_hex,
                                        size_t out_response_size) {
    if (!credential_blob_hex || !out_response_hex || out_response_size < 65 ||
        !g_tpm_detected) return -1;
    out_response_hex[0] = '\0';
    const char *ak_handle = getenv("EXAMOS_TPM_AK_HANDLE");
    const char *ek_handle = getenv("EXAMOS_TPM_EK_HANDLE");
    if (!valid_tpm_handle(ak_handle) || !valid_tpm_handle(ek_handle)) return -1;

    unsigned char blob[4096] = {0}, secret[64] = {0};
    size_t blob_len = 0, secret_len = 0;
    if (decode_hex(credential_blob_hex, blob, sizeof(blob), &blob_len) != 0) {
        OPENSSL_cleanse(blob, sizeof(blob));
        return -1;
    }
    char work_dir[] = "/tmp/examos-tpm-activate.XXXXXX";
    char blob_path[PATH_MAX] = {0}, session_path[PATH_MAX] = {0};
    char secret_path[PATH_MAX] = {0};
    if (!mkdtemp(work_dir)) {
        OPENSSL_cleanse(blob, sizeof(blob));
        return -1;
    }
    if (chmod(work_dir, 0700) != 0) {
        rmdir(work_dir);
        OPENSSL_cleanse(blob, sizeof(blob));
        return -1;
    }
    int a = snprintf(blob_path, sizeof(blob_path), "%s/credential.blob", work_dir);
    int b = snprintf(session_path, sizeof(session_path), "%s/policy.ctx", work_dir);
    int c = snprintf(secret_path, sizeof(secret_path), "%s/secret.bin", work_dir);
    int paths_valid = a > 0 && (size_t)a < sizeof(blob_path) &&
                      b > 0 && (size_t)b < sizeof(session_path) &&
                      c > 0 && (size_t)c < sizeof(secret_path);
    int result = paths_valid &&
        write_tpm_private_file(blob_path, blob, blob_len) == 0;
    if (result) {
        char *const start_arguments[] = {
            "tpm2_startauthsession", "--policy-session", "-S", session_path, NULL
        };
        result = run_tpm_tool(start_arguments) == 0;
    }
    if (result) {
        char *const policy_arguments[] = {
            "tpm2_policysecret", "-S", session_path, "-c", (char *)ek_handle, NULL
        };
        result = run_tpm_tool(policy_arguments) == 0;
    }
    if (result) {
        char password_session[PATH_MAX + 9];
        int auth_len = snprintf(password_session, sizeof(password_session),
                                "session:%s", session_path);
        if (auth_len < 0 || (size_t)auth_len >= sizeof(password_session)) {
            result = 0;
        } else {
            char *const activate_arguments[] = {
                "tpm2_activatecredential", "-c", (char *)ak_handle,
                "-C", (char *)ek_handle, "-i", blob_path, "-o", secret_path,
                "-P", password_session, NULL
            };
            result = run_tpm_tool(activate_arguments) == 0;
        }
        OPENSSL_cleanse(password_session, sizeof(password_session));
    }
    if (result)
        result = read_quote_output(secret_path, secret, sizeof(secret), &secret_len) == 0 &&
                 secret_len == 32;
    if (session_path[0]) {
        char *const flush_arguments[] = {
            "tpm2_flushcontext", session_path, NULL
        };
        (void)run_tpm_tool(flush_arguments);
    }
    if (blob_path[0]) unlink(blob_path);
    if (session_path[0]) unlink(session_path);
    if (secret_path[0]) unlink(secret_path);
    rmdir(work_dir);
    if (result) bytes_to_hex(secret, secret_len, out_response_hex);
    OPENSSL_cleanse(blob, sizeof(blob));
    OPENSSL_cleanse(secret, sizeof(secret));
    if (!result) OPENSSL_cleanse(out_response_hex, out_response_size);
    return result ? 0 : -1;
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
    char ak_pub_path[PATH_MAX], ak_pem_path[PATH_MAX];
    char ek_pub_path[PATH_MAX];
    int a = snprintf(message_path,   sizeof(message_path),   "%s/quote.attest",    work_dir);
    int b = snprintf(signature_path, sizeof(signature_path), "%s/quote.signature", work_dir);
    int c = snprintf(ak_pub_path,    sizeof(ak_pub_path),    "%s/ak.pub",          work_dir);
    int d = snprintf(ak_pem_path,    sizeof(ak_pem_path),    "%s/ak.pem",          work_dir);
    int e = snprintf(ek_pub_path,    sizeof(ek_pub_path),    "%s/ek.pub",          work_dir);
    if (a < 0 || (size_t)a >= sizeof(message_path) ||
        b < 0 || (size_t)b >= sizeof(signature_path) ||
        c < 0 || (size_t)c >= sizeof(ak_pub_path) ||
        d < 0 || (size_t)d >= sizeof(ak_pem_path) ||
        e < 0 || (size_t)e >= sizeof(ek_pub_path)) {
        rmdir(work_dir);
        return -1;
    }

    /* --- Read AK public key and derive its PEM + SHA-256 fingerprint --- */
    {
        pid_t child = fork();
        if (child < 0) { rmdir(work_dir); return -1; }
        if (child == 0) {
            if (setenv("TPM2TOOLS_TCTI", "tabrmd", 1) != 0) _exit(126);
            char *const argv[] = {
                "tpm2_readpublic", "--object-context", (char *)handle,
                "--output", ak_pub_path,
                "--format", "pem",
                NULL
            };
            execvp(argv[0], argv);
            _exit(127);
        }
        int status = 0;
        while (waitpid(child, &status, 0) < 0) { if (errno != EINTR) { rmdir(work_dir); return -1; } }
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            rmdir(work_dir);
            return -1;
        }
    }
    /* Read PEM into report */
    {
        int fd = open(ak_pub_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd >= 0) {
            ssize_t n = read(fd, report->ak_pub_hex, sizeof(report->ak_pub_hex) - 1);
            close(fd);
            if (n > 0) report->ak_pub_hex[n] = '\0';
            else report->ak_pub_hex[0] = '\0';
        }
        unlink(ak_pub_path);
    }

    /* --- Read EK public key and compute its SHA-256 fingerprint --- */
    const char *ek_handle = getenv("EXAMOS_TPM_EK_HANDLE");
    if (ek_handle && ek_handle[0]) {
        pid_t child = fork();
        if (child == 0) {
            if (setenv("TPM2TOOLS_TCTI", "tabrmd", 1) != 0) _exit(126);
            char *const argv[] = {
                "tpm2_readpublic", "--object-context", (char *)ek_handle,
                "--output", ek_pub_path,
                "--format", "pem",
                NULL
            };
            execvp(argv[0], argv);
            _exit(127);
        }
        if (child > 0) {
            int status = 0;
            while (waitpid(child, &status, 0) < 0) { if (errno != EINTR) break; }
            if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                /* Hash the DER-encoded EK public key */
                unsigned char ek_pem_buf[4096];
                size_t ek_pem_len = 0;
                int fd = open(ek_pub_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
                if (fd >= 0) {
                    ssize_t n = read(fd, ek_pem_buf, sizeof(ek_pem_buf) - 1);
                    close(fd);
                    if (n > 0) {
                        ek_pem_buf[n] = '\0';
                        ek_pem_len = (size_t)n;
                        BIO *bio = BIO_new_mem_buf(ek_pem_buf, (int)ek_pem_len);
                        EVP_PKEY *pkey = bio ? PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL) : NULL;
                        BIO_free(bio);
                        if (pkey) {
                            unsigned char *der = NULL;
                            int der_len = i2d_PUBKEY(pkey, &der);
                            if (der_len > 0 && der) {
                                unsigned char digest[32];
                                unsigned int dlen = 0;
                                if (EVP_Digest(der, (size_t)der_len, digest, &dlen,
                                               EVP_sha256(), NULL) == 1 && dlen == 32) {
                                    bytes_to_hex(digest, 32, report->ek_fingerprint);
                                }
                                OPENSSL_clear_free(der, (size_t)der_len);
                            }
                            EVP_PKEY_free(pkey);
                        }
                    }
                    OPENSSL_cleanse(ek_pem_buf, sizeof(ek_pem_buf));
                }
            }
            unlink(ek_pub_path);
        }
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
