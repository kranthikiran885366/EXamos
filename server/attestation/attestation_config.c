/*
 * attestation_config.c — ExamOS P3 Dynamic Config Loader
 *
 * Reads devices.json and releases.json at server startup and registers
 * each entry with the attestation service.  No values are compiled in;
 * every device and release comes from the on-disk JSON files.
 *
 * JSON parsing is done with a minimal hand-rolled parser (same approach
 * as the rest of the codebase — no external JSON library dependency).
 */
#define _GNU_SOURCE
#include "../include/attestation_config.h"
#include "../include/attestation_service.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <errno.h>
#include <sys/stat.h>

/* -----------------------------------------------------------------------
 * Minimal JSON helpers — extract string field from a JSON object fragment
 * ----------------------------------------------------------------------- */
static void cfg_json_str(const char *buf, const char *key,
                          char *out, size_t max_out) {
    out[0] = '\0';
    if (!buf || !key) return;

    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *pos = strstr(buf, pattern);
    if (!pos) return;

    pos += strlen(pattern);
    while (*pos == ' ' || *pos == '\t' || *pos == '\r' || *pos == '\n') pos++;
    if (*pos++ != ':') return;
    while (*pos == ' ' || *pos == '\t' || *pos == '\r' || *pos == '\n') pos++;
    if (*pos != '"') return;
    pos++;

    size_t i = 0;
    while (*pos && *pos != '"') {
        unsigned char value = (unsigned char)*pos++;
        if (value == '\\') {
            switch (*pos++) {
                case '"': value = '"'; break;
                case '\\': value = '\\'; break;
                case '/': value = '/'; break;
                case 'b': value = '\b'; break;
                case 'f': value = '\f'; break;
                case 'n': value = '\n'; break;
                case 'r': value = '\r'; break;
                case 't': value = '\t'; break;
                case 'u': {
                    unsigned int codepoint = 0;
                    for (int digit = 0; digit < 4; ++digit) {
                        unsigned char c = (unsigned char)*pos++;
                        if (!isxdigit(c)) { out[0] = '\0'; return; }
                        codepoint = (codepoint << 4) |
                            (unsigned int)(isdigit(c) ? c - '0' :
                            (tolower(c) - 'a' + 10));
                    }
                    if (codepoint > 0x7f) { out[0] = '\0'; return; }
                    value = (unsigned char)codepoint;
                    break;
                }
                default: out[0] = '\0'; return;
            }
        }
        if (i + 1 >= max_out || value == '\0') { out[0] = '\0'; return; }
        out[i++] = (char)value;
    }
    if (*pos != '"') { out[0] = '\0'; return; }
    out[i] = '\0';
}

static int cfg_json_bool_strict(const char *buf, const char *key) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *pos = strstr(buf, pattern);
    if (!pos) return -1;
    pos += strlen(pattern);
    while (*pos == ' ' || *pos == ':' || *pos == '\t' ||
           *pos == '\r' || *pos == '\n') pos++;
    const char *end = pos + (strncmp(pos, "true", 4) == 0 ? 4 :
                             strncmp(pos, "false", 5) == 0 ? 5 : 0);
    if (end == pos) return -1;
    while (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')
        end++;
    if (*end != ',' && *end != '}') return -1;
    if (strncmp(pos, "true", 4) == 0) return 1;
    if (strncmp(pos, "false", 5) == 0) return 0;
    return -1;
}

static int is_sha256_hex(const char *value, int require_nonzero) {
    if (!value || strlen(value) != 64) return 0;
    int has_nonzero = 0;
    for (size_t i = 0; i < 64; i++) {
        if (!isxdigit((unsigned char)value[i])) return 0;
        if (value[i] != '0') has_nonzero = 1;
    }
    return !require_nonzero || has_nonzero;
}

/* Read entire file into a heap-allocated buffer.  Caller must free(). */
static char *read_file_all(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    long fsize = ftell(f);
    if (fsize <= 0 || fsize > 2 * 1024 * 1024 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }
    char *buf = malloc((size_t)fsize + 1);
    if (!buf) { fclose(f); return NULL; }

    size_t n = fread(buf, 1, (size_t)fsize, f);
    if (n != (size_t)fsize) {
        free(buf);
        fclose(f);
        return NULL;
    }
    buf[n] = '\0';
    fclose(f);

    if (out_len) *out_len = n;
    return buf;
}

static int verify_manifest_signature(const unsigned char *data, size_t data_len,
                                    const char *signature_env,
                                    const char *key_env,
                                    const char *key_fingerprint_env,
                                    const char *default_signature,
                                    const char *default_key,
                                    const char *manifest_name) {
    const char *signature_path = getenv(signature_env);
    const char *public_key_path = getenv(key_env);
    if (!signature_path || !signature_path[0]) signature_path = default_signature;
    if (!public_key_path || !public_key_path[0]) public_key_path = default_key;

    size_t signature_len = 0;
    unsigned char *signature = (unsigned char *)read_file_all(
        signature_path, &signature_len);
    if (!signature || signature_len == 0) {
        fprintf(stderr, "[AttestConfig] Production %s signature missing or unreadable: %s\n",
                manifest_name, signature_path);
        free(signature);
        return -1;
    }

    BIO *key_bio = BIO_new_file(public_key_path, "r");
    EVP_PKEY *public_key = key_bio
        ? PEM_read_bio_PUBKEY(key_bio, NULL, NULL, NULL) : NULL;
    BIO_free(key_bio);
    if (!public_key) {
        fprintf(stderr, "[AttestConfig] Production %s verification key is missing or invalid: %s\n",
                manifest_name, public_key_path);
        free(signature);
        return -1;
    }

    const char *expected_fingerprint = getenv(key_fingerprint_env);
    if (!expected_fingerprint || strlen(expected_fingerprint) != 64) {
        fprintf(stderr, "[AttestConfig] Production %s trusted-key fingerprint is unset or malformed.\n",
                manifest_name);
        EVP_PKEY_free(public_key);
        free(signature);
        return -1;
    }
    for (size_t i = 0; i < 64; i++) {
        if (!isxdigit((unsigned char)expected_fingerprint[i])) {
            fprintf(stderr, "[AttestConfig] Production %s trusted-key fingerprint is malformed.\n",
                    manifest_name);
            EVP_PKEY_free(public_key);
            free(signature);
            return -1;
        }
    }
    int der_len = i2d_PUBKEY(public_key, NULL);
    unsigned char *der = der_len > 0 ? malloc((size_t)der_len) : NULL;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    unsigned char *der_cursor = der;
    const int fingerprint_ok = der &&
        i2d_PUBKEY(public_key, &der_cursor) == der_len &&
        EVP_Digest(der, (size_t)der_len, digest, &digest_len, EVP_sha256(), NULL) == 1 &&
        digest_len == 32;
    free(der);
    static const char hex[] = "0123456789abcdef";
    char actual_fingerprint[65] = {0};
    if (fingerprint_ok) {
        for (size_t i = 0; i < 32; i++) {
            actual_fingerprint[i * 2] = hex[digest[i] >> 4];
            actual_fingerprint[i * 2 + 1] = hex[digest[i] & 0x0f];
        }
    }
    int pin_matches = fingerprint_ok;
    for (size_t i = 0; pin_matches && i < 64; i++) {
        if ((unsigned char)tolower((unsigned char)expected_fingerprint[i]) !=
            (unsigned char)actual_fingerprint[i]) pin_matches = 0;
    }
    OPENSSL_cleanse(digest, sizeof(digest));
    if (!pin_matches) {
        fprintf(stderr, "[AttestConfig] Production %s key does not match its externally pinned SHA-256 fingerprint.\n",
                manifest_name);
        EVP_PKEY_free(public_key);
        free(signature);
        return -1;
    }

    const int key_type = EVP_PKEY_base_id(public_key);
    const int key_bits = EVP_PKEY_bits(public_key);
    if (!((key_type == EVP_PKEY_RSA && key_bits >= 3072) ||
          (key_type == EVP_PKEY_EC && key_bits >= 256))) {
        fprintf(stderr, "[AttestConfig] %s verification key must be RSA-3072+ or EC-256+.\n",
                manifest_name);
        EVP_PKEY_free(public_key);
        free(signature);
        return -1;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const int verified = ctx &&
        EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, public_key) == 1 &&
        EVP_DigestVerifyUpdate(ctx, data, data_len) == 1 &&
        EVP_DigestVerifyFinal(ctx, signature, signature_len) == 1;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(public_key);
    free(signature);

    if (!verified) {
        fprintf(stderr, "[AttestConfig] Production %s signature verification failed.\n",
                manifest_name);
        return -1;
    }
    fprintf(stdout, "[AttestConfig] Production %s signature verified.\n", manifest_name);
    return 0;
}

static int verify_release_registry_signature(const unsigned char *data,
                                            size_t data_len) {
    return verify_manifest_signature(data, data_len,
                                     "EXAMOS_RELEASES_SIGNATURE",
                                     "EXAMOS_RELEASES_PUBLIC_KEY",
                                     "EXAMOS_RELEASES_PUBLIC_KEY_SHA256",
                                     "/etc/examos/releases.json.sig",
                                     "/etc/examos/release-registry.pub",
                                     "release registry");
}

static int verify_device_registry_signature(const unsigned char *data,
                                           size_t data_len) {
    return verify_manifest_signature(data, data_len,
                                     "EXAMOS_DEVICES_SIGNATURE",
                                     "EXAMOS_DEVICES_PUBLIC_KEY",
                                     "EXAMOS_DEVICES_PUBLIC_KEY_SHA256",
                                     "/etc/examos/devices.json.sig",
                                     "/etc/examos/device-registry.pub",
                                     "device registry");
}

/* -----------------------------------------------------------------------
 * attestation_config_load_devices
 * ----------------------------------------------------------------------- */
int attestation_config_load_devices(const char *json_path) {
    if (!json_path) return -1;

    size_t len = 0;
    char *buf = read_file_all(json_path, &len);
    if (!buf) {
        fprintf(stderr, "[AttestConfig] Cannot read devices config: %s\n", json_path);
        return -1;
    }

    const char *mode = getenv("EXAMOS_TPM_MODE");
    const int production = mode && strcmp(mode, "production") == 0;
    if (production) {
        char schema[64] = {0};
        char environment[32] = {0};
        cfg_json_str(buf, "_schema", schema, sizeof(schema));
        cfg_json_str(buf, "environment", environment, sizeof(environment));
        if (strcmp(schema, "examos-device-registry-v1") != 0 ||
            strcmp(environment, "production") != 0 ||
            verify_device_registry_signature((const unsigned char *)buf, len) != 0) {
            fprintf(stderr, "[AttestConfig] Refusing unsigned, non-production, or unsupported device registry.\n");
            free(buf);
            return -1;
        }
    }

    fprintf(stdout, "[AttestConfig] Loading devices from: %s\n", json_path);

    /* Find the "devices" array */
    const char *arr = strstr(buf, "\"devices\"");
    if (!arr) {
        free(buf);
        return production ? -1 : 0;
    }
    arr = strchr(arr, '[');
    if (!arr) {
        free(buf);
        return production ? -1 : 0;
    }

    int count = 0;
    int invalid_production_entry = 0;
    const char *p = arr + 1;

    while (*p) {
        /* Find next object opening */
        const char *obj_start = strchr(p, '{');
        if (!obj_start) break;

        /* Find matching closing brace */
        int depth = 1;
        const char *obj_end = obj_start + 1;
        while (*obj_end && depth > 0) {
            if (*obj_end == '{') depth++;
            else if (*obj_end == '}') depth--;
            obj_end++;
        }
        if (depth != 0) break;

        /* Extract a temporary copy of this object */
        size_t obj_len = (size_t)(obj_end - obj_start);
        char *obj = malloc(obj_len + 1);
        if (!obj) break;
        memcpy(obj, obj_start, obj_len);
        obj[obj_len] = '\0';

        /* Extract fields */
        char device_id[64]    = {0};
        char ek_fp[65]        = {0};
        char ak_qualified_name[69] = {0};
        char ak_pub_sha256[65] = {0};
        char ak_public_pem[2048] = {0};
        char allowed_rel[64]  = {0};
        char status_str[32]   = {0};

        cfg_json_str(obj, "device_id",       device_id,   sizeof(device_id));
        cfg_json_str(obj, "ek_fingerprint",  ek_fp,       sizeof(ek_fp));
        cfg_json_str(obj, "ak_qualified_name", ak_qualified_name,
                     sizeof(ak_qualified_name));
        cfg_json_str(obj, "ak_pub_sha256",    ak_pub_sha256, sizeof(ak_pub_sha256));
        cfg_json_str(obj, "ak_public_pem",    ak_public_pem, sizeof(ak_public_pem));
        cfg_json_str(obj, "allowed_release", allowed_rel, sizeof(allowed_rel));
        cfg_json_str(obj, "status",          status_str,  sizeof(status_str));

        if (production &&
            (!device_id[0] || !is_sha256_hex(ek_fp, 1) ||
             strlen(ak_qualified_name) != 68 ||
             strncmp(ak_qualified_name, "000b", 4) != 0 ||
             !is_sha256_hex(ak_qualified_name + 4, 1) ||
             !is_sha256_hex(ak_pub_sha256, 1) ||
             !ak_public_pem[0] ||
             !allowed_rel[0] ||
             (strcmp(status_str, "ENROLLED") != 0 &&
              strcmp(status_str, "TRUSTED") != 0 &&
              strcmp(status_str, "SUSPENDED") != 0 &&
              strcmp(status_str, "REVOKED") != 0 &&
              strcmp(status_str, "RETIRED") != 0))) {
            fprintf(stderr, "[AttestConfig] Production device entry is incomplete or invalid.\n");
            invalid_production_entry = 1;
            free(obj);
            p = obj_end;
            continue;
        }

        const int active = !production ||
            strcmp(status_str, "ENROLLED") == 0 ||
            strcmp(status_str, "TRUSTED") == 0;
        if (device_id[0] && ek_fp[0] && allowed_rel[0] && active) {
            int rc = production
                ? attestation_register_device_identity(
                    device_id, ek_fp, ak_qualified_name, ak_public_pem,
                    ak_pub_sha256, allowed_rel)
                : attestation_register_device(device_id, ek_fp, allowed_rel);
            if (rc == 0) {
                count++;
                fprintf(stdout, "[AttestConfig]   + device: %s (%s)\n",
                        device_id, status_str[0] ? status_str : "ENROLLED");
            } else if (production) {
                fprintf(stderr, "[AttestConfig] Failed to register production device %s.\n", device_id);
                invalid_production_entry = 1;
            }
        }

        free(obj);
        p = obj_end;
    }

    free(buf);
    fprintf(stdout, "[AttestConfig] Loaded %d device(s).\n", count);
    if (production && (invalid_production_entry || count == 0))
        return -1;
    return count;
}

/* -----------------------------------------------------------------------
 * attestation_config_load_releases
 * ----------------------------------------------------------------------- */
int attestation_config_load_releases(const char *json_path) {
    if (!json_path) return -1;

    size_t len = 0;
    char *buf = read_file_all(json_path, &len);
    if (!buf) {
        fprintf(stderr, "[AttestConfig] Cannot read releases config: %s\n", json_path);
        return -1;
    }

    const char *mode = getenv("EXAMOS_TPM_MODE");
    const int production = mode && strcmp(mode, "production") == 0;
    if (production) {
        char schema[64] = {0};
        char environment[32] = {0};
        cfg_json_str(buf, "_schema", schema, sizeof(schema));
        cfg_json_str(buf, "environment", environment, sizeof(environment));
        if (strcmp(schema, "examos-release-registry-v1") != 0 ||
            strcmp(environment, "production") != 0 ||
            verify_release_registry_signature((const unsigned char *)buf, len) != 0) {
            fprintf(stderr, "[AttestConfig] Refusing unsigned, non-production, or unsupported release registry.\n");
            free(buf);
            return -1;
        }
    }

    fprintf(stdout, "[AttestConfig] Loading releases from: %s\n", json_path);

    /* Find the "releases" array */
    const char *arr = strstr(buf, "\"releases\"");
    if (!arr) { free(buf); return 0; }
    arr = strchr(arr, '[');
    if (!arr) { free(buf); return 0; }

    int count = 0;
    int invalid_production_entry = 0;
    const char *p = arr + 1;

    while (*p) {
        const char *obj_start = strchr(p, '{');
        if (!obj_start) break;

        int depth = 1;
        const char *obj_end = obj_start + 1;
        while (*obj_end && depth > 0) {
            if (*obj_end == '{') depth++;
            else if (*obj_end == '}') depth--;
            obj_end++;
        }
        if (depth != 0) break;

        size_t obj_len = (size_t)(obj_end - obj_start);
        char *obj = malloc(obj_len + 1);
        if (!obj) break;
        memcpy(obj, obj_start, obj_len);
        obj[obj_len] = '\0';

        char release_id[64] = {0};
        char uki_hash[65]   = {0};
        char pcr0[65]       = {0};
        char pcr4[65]       = {0};
        char pcr7[65]       = {0};
        char pcr11[65]      = {0};
        char approval_status[32] = {0};
        char pcr_bank[16]        = {0};
        int  revoked_field  = cfg_json_bool_strict(obj, "revoked");
        int  revoked        = revoked_field == 1;

        cfg_json_str(obj, "release_id", release_id, sizeof(release_id));
        cfg_json_str(obj, "uki_hash",   uki_hash,   sizeof(uki_hash));
        cfg_json_str(obj, "pcr0",       pcr0,       sizeof(pcr0));
        cfg_json_str(obj, "pcr4",       pcr4,       sizeof(pcr4));
        cfg_json_str(obj, "pcr7",       pcr7,       sizeof(pcr7));
        cfg_json_str(obj, "pcr11",      pcr11,      sizeof(pcr11));
        cfg_json_str(obj, "approval_status", approval_status,
                     sizeof(approval_status));
        cfg_json_str(obj, "pcr_bank", pcr_bank, sizeof(pcr_bank));

        if (production &&
            (strcmp(approval_status, "APPROVED_PRODUCTION") != 0 ||
             revoked_field < 0 ||
             (strcmp(pcr_bank, "SHA256") != 0 &&
              strcmp(pcr_bank, "sha256") != 0) ||
             !is_sha256_hex(uki_hash, 1) ||
             !is_sha256_hex(pcr0, 1) || !is_sha256_hex(pcr4, 1) ||
             !is_sha256_hex(pcr7, 1) || !is_sha256_hex(pcr11, 1))) {
            fprintf(stderr,
                    "[AttestConfig] Production release %s lacks approved identity, "
                    "non-placeholder UKI hash, or complete SHA-256 PCR measurements.\n",
                    release_id[0] ? release_id : "<unnamed>");
            invalid_production_entry = 1;
            free(obj);
            p = obj_end;
            continue;
        }

        if (release_id[0] && pcr0[0]) {
            int rc = attestation_register_release(
                release_id, uki_hash, pcr0, pcr4, pcr7, pcr11);
            if (rc == 0) {
                count++;
                fprintf(stdout, "[AttestConfig]   + release: %s (revoked=%s)\n",
                        release_id, revoked ? "true" : "false");
                if (revoked && attestation_revoke_release(release_id) != 0 && production) {
                    fprintf(stderr, "[AttestConfig] Could not persist production release revocation for %s.\n",
                            release_id);
                    invalid_production_entry = 1;
                }
            } else if (production) {
                fprintf(stderr, "[AttestConfig] Failed to register production release %s.\n", release_id);
                invalid_production_entry = 1;
            }
        } else if (production) {
            fprintf(stderr, "[AttestConfig] Production registry has a malformed release entry.\n");
            invalid_production_entry = 1;
        }

        free(obj);
        p = obj_end;
    }

    free(buf);
    fprintf(stdout, "[AttestConfig] Loaded %d release(s).\n", count);
    if (production && (invalid_production_entry || count == 0))
        return -1;
    return count;
}

/* -----------------------------------------------------------------------
 * attestation_config_load_all
 *
 * Resolution order for devices config:
 *   1. $EXAMOS_DEVICES_CONFIG
 *   2. /etc/examos/devices.json
 *   3. <binary_dir>/../config/devices.json   (dev mode)
 *   4. <binary_dir>/config/devices.json      (dev mode alt)
 *
 * Same pattern for releases.
 * ----------------------------------------------------------------------- */
int attestation_config_load_all(const char *binary_dir) {
    const char *mode = getenv("EXAMOS_TPM_MODE");
    const int production = mode && strcmp(mode, "production") == 0;

    /* --- Devices --- */
    const char *dev_cfg = getenv("EXAMOS_DEVICES_CONFIG");
    char dev_path[512] = {0};

    if (production && dev_cfg && dev_cfg[0] && access(dev_cfg, R_OK) != 0) {
        fprintf(stderr, "[AttestConfig] Configured production device registry is unreadable: %s\n",
                dev_cfg);
        return -1;
    }
    if (dev_cfg && access(dev_cfg, R_OK) == 0) {
        snprintf(dev_path, sizeof(dev_path), "%s", dev_cfg);
    } else if (access("/etc/examos/devices.json", R_OK) == 0) {
        snprintf(dev_path, sizeof(dev_path), "/etc/examos/devices.json");
    } else if (!production && binary_dir) {
        /* Try dev-mode relative paths */
        snprintf(dev_path, sizeof(dev_path), "%s/../config/devices.json", binary_dir);
        if (access(dev_path, R_OK) != 0) {
            snprintf(dev_path, sizeof(dev_path), "%s/config/devices.json", binary_dir);
            if (access(dev_path, R_OK) != 0)
                dev_path[0] = '\0';
        }
    }

    /* --- Releases --- */
    const char *rel_cfg = getenv("EXAMOS_RELEASES_CONFIG");
    char rel_path[512] = {0};

    if (production && rel_cfg && rel_cfg[0] && access(rel_cfg, R_OK) != 0) {
        fprintf(stderr, "[AttestConfig] Configured production release registry is unreadable: %s\n",
                rel_cfg);
        return -1;
    }
    if (rel_cfg && access(rel_cfg, R_OK) == 0) {
        snprintf(rel_path, sizeof(rel_path), "%s", rel_cfg);
    } else if (access("/etc/examos/releases.json", R_OK) == 0) {
        snprintf(rel_path, sizeof(rel_path), "/etc/examos/releases.json");
    } else if (!production && binary_dir) {
        snprintf(rel_path, sizeof(rel_path), "%s/../config/releases.json", binary_dir);
        if (access(rel_path, R_OK) != 0) {
            snprintf(rel_path, sizeof(rel_path), "%s/config/releases.json", binary_dir);
            if (access(rel_path, R_OK) != 0)
                rel_path[0] = '\0';
        }
    }

    int devices_loaded  = dev_path[0] ? attestation_config_load_devices(dev_path)  : 0;
    int releases_loaded = rel_path[0] ? attestation_config_load_releases(rel_path) : 0;

    /* Parse errors (negative rc) are always fatal regardless of mode. */
    if (devices_loaded < 0 || releases_loaded < 0) {
        fprintf(stderr, "[AttestConfig] FATAL: error parsing config "
                "(devices_rc=%d releases_rc=%d).\n",
                devices_loaded, releases_loaded);
        return -1;
    }

    if (devices_loaded == 0 || releases_loaded == 0) {
        fprintf(stderr, "[AttestConfig] %s: config not found, invalid, or empty "
                "(devices=%d releases=%d).\n",
                production ? "FATAL production config error" : "WARNING",
                devices_loaded, releases_loaded);
        if (production) {
            /* Production MUST have >=1 enrolled device and >=1 known release. */
            return -1;
        }
        /* Development: proceed with empty registries. Attestation API calls
         * will return NOT_FOUND for unknown devices; event ingestion,
         * proctoring, and admin routes are unaffected. */
        return 0;
    }

    return 0;
}

/* -----------------------------------------------------------------------
 * Runtime persistence is disabled until AK identity material is retained.
 * ----------------------------------------------------------------------- */
int attestation_config_save_devices(const char *json_path)
{
    (void)json_path;
    fprintf(stderr, "[AttestConfig] Device registry persistence is unavailable: the runtime registry does not retain validated AK identity material.\n");
    errno = ENOTSUP;
    return -1;
}
