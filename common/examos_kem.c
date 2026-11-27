#include "include/examos_kem.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>

int examos_kem_encapsulate(const char *pem,
                          unsigned char ciphertext[EXAMOS_KEM_CIPHERTEXT_BYTES],
                          unsigned char secret[EXAMOS_KEM_SECRET_BYTES]) {
    if (ciphertext) OPENSSL_cleanse(ciphertext, EXAMOS_KEM_CIPHERTEXT_BYTES);
    if (secret) OPENSSL_cleanse(secret, EXAMOS_KEM_SECRET_BYTES);
    if (!pem || !ciphertext || !secret) return -1;
    BIO *bio = BIO_new_mem_buf(pem, -1);
    EVP_PKEY *key = bio ? PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL) : NULL;
    BIO_free(bio);
    EVP_PKEY_CTX *ctx = key && EVP_PKEY_is_a(key, "ML-KEM-768")
        ? EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL) : NULL;
    size_t ciphertext_len = EXAMOS_KEM_CIPHERTEXT_BYTES;
    size_t secret_len = EXAMOS_KEM_SECRET_BYTES;
    int ok = ctx && EVP_PKEY_encapsulate_init(ctx, NULL) == 1 &&
        EVP_PKEY_encapsulate(ctx, ciphertext, &ciphertext_len, secret, &secret_len) == 1 &&
        ciphertext_len == EXAMOS_KEM_CIPHERTEXT_BYTES && secret_len == EXAMOS_KEM_SECRET_BYTES;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    if (!ok) {
        OPENSSL_cleanse(ciphertext, EXAMOS_KEM_CIPHERTEXT_BYTES);
        OPENSSL_cleanse(secret, EXAMOS_KEM_SECRET_BYTES);
    }
    return ok ? 0 : -1;
}

int examos_kem_decapsulate(const char *pem, const unsigned char *ciphertext,
                          size_t ciphertext_len,
                          unsigned char secret[EXAMOS_KEM_SECRET_BYTES]) {
    if (secret) OPENSSL_cleanse(secret, EXAMOS_KEM_SECRET_BYTES);
    if (!pem || !ciphertext || !secret || ciphertext_len != EXAMOS_KEM_CIPHERTEXT_BYTES)
        return -1;
    BIO *bio = BIO_new_mem_buf(pem, -1);
    EVP_PKEY *key = bio ? PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL) : NULL;
    BIO_free(bio);
    EVP_PKEY_CTX *ctx = key && EVP_PKEY_is_a(key, "ML-KEM-768")
        ? EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL) : NULL;
    size_t secret_len = EXAMOS_KEM_SECRET_BYTES;
    int ok = ctx && EVP_PKEY_decapsulate_init(ctx, NULL) == 1 &&
        EVP_PKEY_decapsulate(ctx, secret, &secret_len, ciphertext, ciphertext_len) == 1 &&
        secret_len == EXAMOS_KEM_SECRET_BYTES;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    if (!ok) OPENSSL_cleanse(secret, EXAMOS_KEM_SECRET_BYTES);
    return ok ? 0 : -1;
}
