#ifndef EXAMOS_SECURE_TOKEN_H
#define EXAMOS_SECURE_TOKEN_H

#define EXAMOS_TOKEN_BYTES 32
#define EXAMOS_TOKEN_HEX_LEN (EXAMOS_TOKEN_BYTES * 2)

int secure_token_create(char token[EXAMOS_TOKEN_HEX_LEN + 1],
                        char token_hash[EXAMOS_TOKEN_HEX_LEN + 1]);
int secure_token_hash(const char *token,
                      char token_hash[EXAMOS_TOKEN_HEX_LEN + 1]);
int secure_token_matches_hash(const char *token, const char *expected_hash);

#endif
