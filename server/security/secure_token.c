#include "../include/secure_token.h"

#include <ctype.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

static void bytes_to_hex(const unsigned char *bytes, size_t length, char *hex) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < length; ++i) {
        hex[i * 2] = digits[bytes[i] >> 4];
        hex[i * 2 + 1] = digits[bytes[i] & 0x0f];
    }
    hex[length * 2] = '\0';
}

static int hex_to_bytes(const char *hex, unsigned char *bytes, size_t length) {
    if (!hex || strnlen(hex, length * 2 + 1) != length * 2) return -1;
    for (size_t i = 0; i < length * 2; i += 2) {
        unsigned char high = (unsigned char)hex[i];
        unsigned char low = (unsigned char)hex[i + 1];
        if (!isxdigit(high) || !isxdigit(low)) return -1;
        high = (unsigned char)tolower(high);
        low = (unsigned char)tolower(low);
        unsigned char high_value = high <= '9' ? (unsigned char)(high - '0')
                                                : (unsigned char)(high - 'a' + 10);
        unsigned char low_value = low <= '9' ? (unsigned char)(low - '0')
                                              : (unsigned char)(low - 'a' + 10);
        bytes[i / 2] = (unsigned char)((high_value << 4) | low_value);
    }
    return 0;
}

int secure_token_hash(const char *token,
                      char token_hash[EXAMOS_TOKEN_HEX_LEN + 1]) {
    if (!token || !token_hash) return -1;

    unsigned char token_bytes[EXAMOS_TOKEN_BYTES];
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_length = 0;
    int result = -1;

    if (hex_to_bytes(token, token_bytes, sizeof(token_bytes)) != 0) goto cleanup;
    if (EVP_Digest(token_bytes, sizeof(token_bytes), digest, &digest_length,
                   EVP_sha256(), NULL) != 1 ||
        digest_length != EXAMOS_TOKEN_BYTES) goto cleanup;

    bytes_to_hex(digest, digest_length, token_hash);
    result = 0;

cleanup:
    OPENSSL_cleanse(token_bytes, sizeof(token_bytes));
    OPENSSL_cleanse(digest, sizeof(digest));
    if (result != 0) token_hash[0] = '\0';
    return result;
}

int secure_token_create(char token[EXAMOS_TOKEN_HEX_LEN + 1],
                        char token_hash[EXAMOS_TOKEN_HEX_LEN + 1]) {
    if (!token || !token_hash) return -1;

    unsigned char token_bytes[EXAMOS_TOKEN_BYTES];
    int result = -1;
    if (RAND_bytes(token_bytes, sizeof(token_bytes)) != 1) goto cleanup;

    bytes_to_hex(token_bytes, sizeof(token_bytes), token);
    if (secure_token_hash(token, token_hash) != 0) {
        token[0] = '\0';
        goto cleanup;
    }
    result = 0;

cleanup:
    OPENSSL_cleanse(token_bytes, sizeof(token_bytes));
    if (result != 0) {
        token[0] = '\0';
        token_hash[0] = '\0';
    }
    return result;
}

int secure_token_matches_hash(const char *token, const char *expected_hash) {
    if (!expected_hash ||
        strnlen(expected_hash, EXAMOS_TOKEN_HEX_LEN + 1) != EXAMOS_TOKEN_HEX_LEN)
        return 0;

    unsigned char expected[EXAMOS_TOKEN_BYTES];
    char calculated[EXAMOS_TOKEN_HEX_LEN + 1];
    unsigned char supplied[EXAMOS_TOKEN_BYTES];
    int matches = 0;

    if (hex_to_bytes(expected_hash, expected, sizeof(expected)) != 0 ||
        secure_token_hash(token, calculated) != 0 ||
        hex_to_bytes(calculated, supplied, sizeof(supplied)) != 0)
        goto cleanup;
    matches = CRYPTO_memcmp(expected, supplied, sizeof(expected)) == 0;

cleanup:
    OPENSSL_cleanse(expected, sizeof(expected));
    OPENSSL_cleanse(calculated, sizeof(calculated));
    OPENSSL_cleanse(supplied, sizeof(supplied));
    return matches;
}
