#include "../../server/include/secure_token.h"

#include <stdio.h>
#include <string.h>

int main(void) {
    char token[EXAMOS_TOKEN_HEX_LEN + 1];
    char hash[EXAMOS_TOKEN_HEX_LEN + 1];
    char second_token[EXAMOS_TOKEN_HEX_LEN + 1];
    char second_hash[EXAMOS_TOKEN_HEX_LEN + 1];
    char malformed_hash[EXAMOS_TOKEN_HEX_LEN + 1];

    if (secure_token_create(token, hash) != 0 ||
        strlen(token) != EXAMOS_TOKEN_HEX_LEN ||
        strlen(hash) != EXAMOS_TOKEN_HEX_LEN ||
        !secure_token_matches_hash(token, hash)) {
        fprintf(stderr, "FAIL: token generation or verification failed\n");
        return 1;
    }

    if (secure_token_create(second_token, second_hash) != 0 ||
        strcmp(token, second_token) == 0 ||
        secure_token_matches_hash(second_token, hash)) {
        fprintf(stderr, "FAIL: tokens were repeated or cross-verified\n");
        return 1;
    }

    if (secure_token_hash("not-a-token", malformed_hash) == 0 ||
        secure_token_matches_hash("not-a-token", hash)) {
        fprintf(stderr, "FAIL: malformed token was accepted\n");
        return 1;
    }

    if (secure_token_create(NULL, hash) == 0 ||
        secure_token_create(token, NULL) == 0) {
        fprintf(stderr, "FAIL: null token output was accepted\n");
        return 1;
    }

    puts("PASS: CSPRNG tokens are opaque, hashed, and strictly validated");
    return 0;
}
