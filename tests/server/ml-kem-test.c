#include "../../common/include/examos_kem.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static char *pem(EVP_PKEY *key, int private_key) {
    BIO *b = BIO_new(BIO_s_mem());
    assert(b);
    assert((private_key ? PEM_write_bio_PrivateKey(b, key, NULL, NULL, 0, NULL, NULL)
                        : PEM_write_bio_PUBKEY(b, key)) == 1);
    char *data = NULL;
    long n = BIO_get_mem_data(b, &data);
    char *result = malloc((size_t)n + 1);
    assert(result);
    memcpy(result, data, (size_t)n); result[n] = 0;
    BIO_free(b); return result;
}

int main(void) {
    EVP_PKEY *key = EVP_PKEY_Q_keygen(NULL, NULL, "ML-KEM-768");
    assert(key); /* Required test: missing provider is a failure, never a PASS. */
    char *pub = pem(key, 0), *priv = pem(key, 1);
    unsigned char ct[EXAMOS_KEM_CIPHERTEXT_BYTES], a[32], b[32];
    assert(examos_kem_encapsulate(pub, ct, a) == 0);
    assert(examos_kem_decapsulate(priv, ct, sizeof(ct), b) == 0);
    assert(CRYPTO_memcmp(a, b, sizeof(a)) == 0);
    ct[0] ^= 1;
    /* ML-KEM implicit rejection yields a different secret, not an error. */
    assert(examos_kem_decapsulate(priv, ct, sizeof(ct), b) == 0);
    assert(CRYPTO_memcmp(a, b, sizeof(a)) != 0);
    assert(examos_kem_decapsulate(priv, ct, sizeof(ct)-1, b) == -1);
    unsigned char zero[32] = {0};
    assert(CRYPTO_memcmp(b, zero, sizeof(b)) == 0);
    assert(examos_kem_encapsulate("invalid", ct, b) == -1);
    assert(CRYPTO_memcmp(b, zero, sizeof(b)) == 0);
    EVP_PKEY *wrong = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    assert(wrong);
    char *wrong_pub = pem(wrong, 0);
    assert(examos_kem_encapsulate(wrong_pub, ct, b) == -1);
    OPENSSL_cleanse(priv, strlen(priv)); free(priv); free(pub); free(wrong_pub);
    OPENSSL_cleanse(a, sizeof(a)); OPENSSL_cleanse(b, sizeof(b));
    EVP_PKEY_free(key); EVP_PKEY_free(wrong);
    puts("PASS: ML-KEM-768 roundtrip, implicit rejection, length and key-type rejection");
}
