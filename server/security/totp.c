#define _GNU_SOURCE
#include "../include/totp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

static const char BASE32_ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static int base32_char_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a';
    if (c >= '2' && c <= '7') return c - '2' + 26;
    return -1;
}

static int base32_encode(const unsigned char *data, size_t data_len, char *out, size_t out_max) {
    size_t out_len = (data_len * 8 + 4) / 5;
    if (out_len + 1 > out_max) return -1;

    size_t bit_buffer = 0;
    int bit_count = 0;
    size_t out_idx = 0;

    for (size_t i = 0; i < data_len; ++i) {
        bit_buffer = (bit_buffer << 8) | data[i];
        bit_count += 8;
        while (bit_count >= 5) {
            bit_count -= 5;
            int val = (int)((bit_buffer >> bit_count) & 0x1f);
            out[out_idx++] = BASE32_ALPHABET[val];
        }
    }
    if (bit_count > 0) {
        int val = (int)((bit_buffer << (5 - bit_count)) & 0x1f);
        out[out_idx++] = BASE32_ALPHABET[val];
    }
    out[out_idx] = '\0';
    return (int)out_idx;
}

static int base32_decode(const char *encoded, unsigned char *out, size_t out_max) {
    if (!encoded) return -1;
    size_t in_len = strlen(encoded);
    size_t bit_buffer = 0;
    int bit_count = 0;
    size_t out_idx = 0;

    for (size_t i = 0; i < in_len; ++i) {
        char c = encoded[i];
        if (c == ' ' || c == '-' || c == '=') continue;
        int val = base32_char_value(c);
        if (val < 0) return -1;

        bit_buffer = (bit_buffer << 5) | (size_t)val;
        bit_count += 5;
        if (bit_count >= 8) {
            bit_count -= 8;
            if (out_idx >= out_max) return -1;
            out[out_idx++] = (unsigned char)((bit_buffer >> bit_count) & 0xff);
        }
    }
    return (int)out_idx;
}

int totp_generate_secret(char out_base32[TOTP_BASE32_LEN + 1]) {
    if (!out_base32) return -1;
    unsigned char raw[TOTP_SECRET_BYTES];
    if (RAND_bytes(raw, sizeof(raw)) != 1) return -1;

    int res = base32_encode(raw, sizeof(raw), out_base32, TOTP_BASE32_LEN + 1);
    OPENSSL_cleanse(raw, sizeof(raw));
    return (res == TOTP_BASE32_LEN) ? 0 : -1;
}

int totp_generate_code(const char *base32_secret, time_t timestamp, char out_code[TOTP_CODE_LEN + 1]) {
    if (!base32_secret || !out_code) return -1;

    unsigned char secret_bytes[64];
    int secret_len = base32_decode(base32_secret, secret_bytes, sizeof(secret_bytes));
    if (secret_len < 10) {
        OPENSSL_cleanse(secret_bytes, sizeof(secret_bytes));
        return -1;
    }

    uint64_t step = (uint64_t)timestamp / TOTP_PERIOD;
    unsigned char step_bytes[8];
    for (int i = 7; i >= 0; --i) {
        step_bytes[i] = (unsigned char)(step & 0xff);
        step >>= 8;
    }

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;

    HMAC(EVP_sha1(), secret_bytes, secret_len, step_bytes, sizeof(step_bytes), md, &md_len);
    OPENSSL_cleanse(secret_bytes, sizeof(secret_bytes));

    if (md_len < 20) return -1;

    int offset = md[19] & 0x0f;
    uint32_t truncated = ((uint32_t)(md[offset] & 0x7f) << 24) |
                         ((uint32_t)(md[offset + 1] & 0xff) << 16) |
                         ((uint32_t)(md[offset + 2] & 0xff) << 8) |
                         ((uint32_t)(md[offset + 3] & 0xff));

    uint32_t otp = truncated % 1000000;
    snprintf(out_code, TOTP_CODE_LEN + 1, "%06u", otp);
    OPENSSL_cleanse(md, sizeof(md));
    return 0;
}

int totp_verify_code(const char *base32_secret, const char *code, time_t now, int window_steps) {
    if (!base32_secret || !code || strlen(code) != TOTP_CODE_LEN) return 0;
    for (int i = 0; i < TOTP_CODE_LEN; ++i) {
        if (!isdigit((unsigned char)code[i])) return 0;
    }

    if (window_steps < 0) window_steps = 0;
    if (window_steps > 3) window_steps = 3;

    for (int step = -window_steps; step <= window_steps; ++step) {
        time_t check_time = now + (step * TOTP_PERIOD);
        char expected[TOTP_CODE_LEN + 1];
        if (totp_generate_code(base32_secret, check_time, expected) != 0) continue;

        if (CRYPTO_memcmp(code, expected, TOTP_CODE_LEN) == 0) {
            OPENSSL_cleanse(expected, sizeof(expected));
            return 1;
        }
        OPENSSL_cleanse(expected, sizeof(expected));
    }
    return 0;
}

int totp_generate_uri(const char *username, const char *issuer, const char *base32_secret,
                      char *out_uri, size_t max_len) {
    if (!username || !issuer || !base32_secret || !out_uri) return -1;
    int written = snprintf(out_uri, max_len,
                           "otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
                           issuer, username, base32_secret, issuer);
    return (written > 0 && (size_t)written < max_len) ? 0 : -1;
}

int totp_hash_recovery_code(const char *code, char out_hash[65]) {
    if (!code || !out_hash) return -1;
    char normalized[32] = {0};
    size_t norm_idx = 0;
    for (size_t i = 0; code[i] && norm_idx + 1 < sizeof(normalized); ++i) {
        if (isalnum((unsigned char)code[i])) {
            normalized[norm_idx++] = (char)toupper((unsigned char)code[i]);
        }
    }
    if (norm_idx < 6) return -1;

    unsigned char digest[32];
    unsigned int len = 0;
    if (EVP_Digest(normalized, norm_idx, digest, &len, EVP_sha256(), NULL) != 1 || len != 32) {
        return -1;
    }

    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; ++i) {
        out_hash[i * 2]     = digits[digest[i] >> 4];
        out_hash[i * 2 + 1] = digits[digest[i] & 0x0f];
    }
    out_hash[64] = '\0';
    OPENSSL_cleanse(normalized, sizeof(normalized));
    OPENSSL_cleanse(digest, sizeof(digest));
    return 0;
}

int totp_generate_recovery_codes(char out_codes[TOTP_NUM_RECOVERY_CODES][TOTP_RECOVERY_CODE_LEN + 1],
                                 char out_hashes[TOTP_NUM_RECOVERY_CODES][65]) {
    if (!out_codes || !out_hashes) return -1;
    static const char charset[] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; /* avoid ambiguous 0/O 1/I */

    for (int i = 0; i < TOTP_NUM_RECOVERY_CODES; ++i) {
        unsigned char rand_bytes[8];
        if (RAND_bytes(rand_bytes, sizeof(rand_bytes)) != 1) return -1;

        char code[TOTP_RECOVERY_CODE_LEN + 1];
        for (int j = 0; j < 4; ++j) {
            code[j] = charset[rand_bytes[j] % (sizeof(charset) - 1)];
        }
        code[4] = '-';
        for (int j = 0; j < 4; ++j) {
            code[5 + j] = charset[rand_bytes[4 + j] % (sizeof(charset) - 1)];
        }
        code[TOTP_RECOVERY_CODE_LEN] = '\0';

        memcpy(out_codes[i], code, sizeof(code));
        if (totp_hash_recovery_code(code, out_hashes[i]) != 0) return -1;
        OPENSSL_cleanse(code, sizeof(code));
    }
    return 0;
}
