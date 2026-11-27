#include "../include/tpm_trust_feed.h"

#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define JSON_NODE_LIMIT 32768U
#define JSON_DEPTH_LIMIT 32U
#define TRUST_KEY_PEM_MAX 4096U
#define TRUST_SIGNATURE_MAX 8192U

typedef enum {
    JSON_OBJECT,
    JSON_ARRAY,
    JSON_STRING,
    JSON_NUMBER,
    JSON_TRUE,
    JSON_FALSE,
    JSON_NULL
} json_type_t;

typedef struct {
    json_type_t type;
    char *text;
    size_t text_len;
    int first_child;
    int next_sibling;
} json_node_t;

typedef struct {
    const unsigned char *input;
    size_t input_len;
    size_t offset;
    json_node_t *nodes;
    size_t node_count;
    size_t node_capacity;
    int failed;
} json_parser_t;

static void json_free(json_parser_t *parser) {
    if (!parser) return;
    for (size_t i = 0; i < parser->node_count; ++i)
        free(parser->nodes[i].text);
    free(parser->nodes);
    parser->nodes = NULL;
    parser->node_count = 0;
}

static void skip_space(json_parser_t *parser) {
    while (parser->offset < parser->input_len) {
        unsigned char c = parser->input[parser->offset];
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') break;
        parser->offset++;
    }
}

static int new_node(json_parser_t *parser, json_type_t type) {
    if (parser->node_count >= parser->node_capacity) {
        parser->failed = 1;
        return -1;
    }
    int index = (int)parser->node_count++;
    json_node_t *node = &parser->nodes[index];
    memset(node, 0, sizeof(*node));
    node->type = type;
    node->first_child = -1;
    node->next_sibling = -1;
    return index;
}

static int append_child(json_parser_t *parser, int parent, int child) {
    if (parent < 0 || child < 0) return -1;
    int *next = &parser->nodes[parent].first_child;
    while (*next >= 0) next = &parser->nodes[*next].next_sibling;
    *next = child;
    return 0;
}

static int hex_digit(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_string(json_parser_t *parser, int *out_index) {
    if (parser->offset >= parser->input_len ||
        parser->input[parser->offset++] != '"') return -1;

    size_t capacity = parser->input_len - parser->offset + 1;
    char *decoded = malloc(capacity);
    if (!decoded) return -1;
    size_t used = 0;
    int closed = 0;

    while (parser->offset < parser->input_len) {
        unsigned char c = parser->input[parser->offset++];
        if (c == '"') {
            closed = 1;
            break;
        }
        if (c < 0x20 || c >= 0x80) {
            free(decoded);
            return -1;
        }
        if (c == '\\') {
            if (parser->offset >= parser->input_len) {
                free(decoded);
                return -1;
            }
            c = parser->input[parser->offset++];
            switch (c) {
                case '"': case '\\': case '/': break;
                case 'b': c = '\b'; break;
                case 'f': c = '\f'; break;
                case 'n': c = '\n'; break;
                case 'r': c = '\r'; break;
                case 't': c = '\t'; break;
                case 'u': {
                    if (parser->input_len - parser->offset < 4) {
                        free(decoded);
                        return -1;
                    }
                    unsigned int codepoint = 0;
                    for (int i = 0; i < 4; ++i) {
                        int value = hex_digit(parser->input[parser->offset++]);
                        if (value < 0) {
                            free(decoded);
                            return -1;
                        }
                        codepoint = (codepoint << 4) | (unsigned int)value;
                    }
                    if (codepoint == 0 || codepoint >= 0x80) {
                        free(decoded);
                        return -1;
                    }
                    c = (unsigned char)codepoint;
                    break;
                }
                default:
                    free(decoded);
                    return -1;
            }
        }
        if (c == '\0' || used + 1 >= capacity) {
            free(decoded);
            return -1;
        }
        decoded[used++] = (char)c;
    }
    if (!closed) {
        free(decoded);
        return -1;
    }
    decoded[used] = '\0';
    int index = new_node(parser, JSON_STRING);
    if (index < 0) {
        free(decoded);
        return -1;
    }
    parser->nodes[index].text = decoded;
    parser->nodes[index].text_len = used;
    *out_index = index;
    return 0;
}

static int parse_value(json_parser_t *parser, unsigned int depth, int *out_index);

static int object_has_key(const json_parser_t *parser, int object,
                          const char *key, size_t key_len) {
    for (int child = parser->nodes[object].first_child;
         child >= 0; child = parser->nodes[child].next_sibling) {
        int value = parser->nodes[child].next_sibling;
        if (value < 0) return 1;
        const json_node_t *key_node = &parser->nodes[child];
        if (key_node->type == JSON_STRING && key_node->text_len == key_len &&
            memcmp(key_node->text, key, key_len) == 0)
            return 1;
        child = value;
    }
    return 0;
}

static int parse_object(json_parser_t *parser, unsigned int depth,
                        int *out_index) {
    parser->offset++;
    int object = new_node(parser, JSON_OBJECT);
    if (object < 0) return -1;
    skip_space(parser);
    if (parser->offset < parser->input_len &&
        parser->input[parser->offset] == '}') {
        parser->offset++;
        *out_index = object;
        return 0;
    }
    for (;;) {
        skip_space(parser);
        int key = -1;
        if (parse_string(parser, &key) != 0 ||
            object_has_key(parser, object, parser->nodes[key].text,
                           parser->nodes[key].text_len) ||
            append_child(parser, object, key) != 0)
            return -1;
        skip_space(parser);
        if (parser->offset >= parser->input_len ||
            parser->input[parser->offset++] != ':') return -1;
        skip_space(parser);
        int value = -1;
        if (parse_value(parser, depth + 1, &value) != 0 ||
            append_child(parser, object, value) != 0)
            return -1;
        skip_space(parser);
        if (parser->offset >= parser->input_len) return -1;
        unsigned char separator = parser->input[parser->offset++];
        if (separator == '}') break;
        if (separator != ',') return -1;
    }
    *out_index = object;
    return 0;
}

static int parse_array(json_parser_t *parser, unsigned int depth,
                       int *out_index) {
    parser->offset++;
    int array = new_node(parser, JSON_ARRAY);
    if (array < 0) return -1;
    skip_space(parser);
    if (parser->offset < parser->input_len &&
        parser->input[parser->offset] == ']') {
        parser->offset++;
        *out_index = array;
        return 0;
    }
    for (;;) {
        skip_space(parser);
        int value = -1;
        if (parse_value(parser, depth + 1, &value) != 0 ||
            append_child(parser, array, value) != 0)
            return -1;
        skip_space(parser);
        if (parser->offset >= parser->input_len) return -1;
        unsigned char separator = parser->input[parser->offset++];
        if (separator == ']') break;
        if (separator != ',') return -1;
    }
    *out_index = array;
    return 0;
}

static int parse_number(json_parser_t *parser, int *out_index) {
    size_t start = parser->offset;
    if (parser->input[parser->offset] == '-') parser->offset++;
    if (parser->offset >= parser->input_len) return -1;
    if (parser->input[parser->offset] == '0') {
        parser->offset++;
        if (parser->offset < parser->input_len &&
            isdigit(parser->input[parser->offset])) return -1;
    } else {
        if (parser->input[parser->offset] < '1' ||
            parser->input[parser->offset] > '9') return -1;
        while (parser->offset < parser->input_len &&
               isdigit(parser->input[parser->offset])) parser->offset++;
    }
    if (parser->offset < parser->input_len &&
        parser->input[parser->offset] == '.') {
        parser->offset++;
        size_t fraction = parser->offset;
        while (parser->offset < parser->input_len &&
               isdigit(parser->input[parser->offset])) parser->offset++;
        if (fraction == parser->offset) return -1;
    }
    if (parser->offset < parser->input_len &&
        (parser->input[parser->offset] == 'e' ||
         parser->input[parser->offset] == 'E')) {
        parser->offset++;
        if (parser->offset < parser->input_len &&
            (parser->input[parser->offset] == '+' ||
             parser->input[parser->offset] == '-')) parser->offset++;
        size_t exponent = parser->offset;
        while (parser->offset < parser->input_len &&
               isdigit(parser->input[parser->offset])) parser->offset++;
        if (exponent == parser->offset) return -1;
    }
    size_t length = parser->offset - start;
    int index = new_node(parser, JSON_NUMBER);
    if (index < 0) return -1;
    parser->nodes[index].text = malloc(length + 1);
    if (!parser->nodes[index].text) return -1;
    memcpy(parser->nodes[index].text, parser->input + start, length);
    parser->nodes[index].text[length] = '\0';
    parser->nodes[index].text_len = length;
    *out_index = index;
    return 0;
}

static int parse_value(json_parser_t *parser, unsigned int depth, int *out_index) {
    if (depth > JSON_DEPTH_LIMIT || parser->offset >= parser->input_len) return -1;
    unsigned char c = parser->input[parser->offset];
    if (c == '{') return parse_object(parser, depth, out_index);
    if (c == '[') return parse_array(parser, depth, out_index);
    if (c == '"') return parse_string(parser, out_index);
    if (c == '-' || (c >= '0' && c <= '9'))
        return parse_number(parser, out_index);

    static const struct {
        const char *text;
        size_t length;
        json_type_t type;
    } literals[] = {
        {"true", 4, JSON_TRUE}, {"false", 5, JSON_FALSE}, {"null", 4, JSON_NULL}
    };
    for (size_t i = 0; i < sizeof(literals) / sizeof(literals[0]); ++i) {
        if (parser->input_len - parser->offset >= literals[i].length &&
            memcmp(parser->input + parser->offset, literals[i].text,
                   literals[i].length) == 0) {
            parser->offset += literals[i].length;
            int index = new_node(parser, literals[i].type);
            if (index < 0) return -1;
            *out_index = index;
            return 0;
        }
    }
    return -1;
}

static int json_parse(const unsigned char *input, size_t input_len,
                      json_parser_t *parser, int *root) {
    memset(parser, 0, sizeof(*parser));
    if (!input || input_len == 0 || input_len > TPM_TRUST_FEED_MAX_BYTES)
        return -1;
    parser->input = input;
    parser->input_len = input_len;
    parser->node_capacity = JSON_NODE_LIMIT;
    parser->nodes = calloc(parser->node_capacity, sizeof(*parser->nodes));
    if (!parser->nodes) return -1;
    skip_space(parser);
    if (parse_value(parser, 0, root) != 0) return -1;
    skip_space(parser);
    if (parser->offset != parser->input_len) return -1;
    return 0;
}

static int object_member(const json_parser_t *parser, int object,
                         const char *key) {
    if (object < 0 || parser->nodes[object].type != JSON_OBJECT) return -1;
    size_t key_len = strlen(key);
    for (int child = parser->nodes[object].first_child;
         child >= 0; child = parser->nodes[child].next_sibling) {
        int value = parser->nodes[child].next_sibling;
        if (value < 0) return -1;
        json_node_t *key_node = &parser->nodes[child];
        if (key_node->type == JSON_STRING && key_node->text_len == key_len &&
            memcmp(key_node->text, key, key_len) == 0)
            return value;
        child = value;
    }
    return -1;
}

/* ---------------------------------------------------------------------------
 * Bounded JSON document API (shared with the dynamic config loader)
 * ------------------------------------------------------------------------- */

struct tpm_json_document {
    json_parser_t parser;
    int root;
};

static int node_valid(const tpm_json_document_t *document, int node) {
    return document && node >= 0 && (size_t)node < document->parser.node_count;
}

tpm_json_document_t *tpm_json_document_parse(const char *json, size_t json_len) {
    if (!json || json_len == 0) return NULL;

    tpm_json_document_t *document = calloc(1, sizeof(*document));
    if (!document) return NULL;
    if (json_parse((const unsigned char *)json, json_len, &document->parser,
                   &document->root) != 0) {
        json_free(&document->parser);
        free(document);
        return NULL;
    }
    return document;
}

void tpm_json_document_free(tpm_json_document_t *document) {
    if (!document) return;
    json_free(&document->parser);
    free(document);
}

int tpm_json_root(const tpm_json_document_t *document) {
    return document ? document->root : -1;
}

tpm_json_type_t tpm_json_node_type(const tpm_json_document_t *document, int node) {
    if (!node_valid(document, node)) return TPM_JSON_NULL;
    return (tpm_json_type_t)document->parser.nodes[node].type;
}

int tpm_json_object_member(const tpm_json_document_t *document, int object,
                           const char *key) {
    if (!document || !key) return -1;
    if (!node_valid(document, object) ||
        document->parser.nodes[object].type != JSON_OBJECT) return -1;
    return object_member(&document->parser, object, key);
}

int tpm_json_object_member_at(const tpm_json_document_t *document, int object,
                              size_t index, const char **key, size_t *key_len) {
    if (!document || !node_valid(document, object) ||
        document->parser.nodes[object].type != JSON_OBJECT) return -1;

    size_t current = 0;
    for (int child = document->parser.nodes[object].first_child;
         child >= 0; child = document->parser.nodes[child].next_sibling) {
        int value = document->parser.nodes[child].next_sibling;
        if (value < 0 || document->parser.nodes[child].type != JSON_STRING)
            return -1;
        if (current == index) {
            if (key) *key = document->parser.nodes[child].text;
            if (key_len) *key_len = document->parser.nodes[child].text_len;
            return value;
        }
        current++;
        child = value;
    }
    return -1;
}

int tpm_json_array_length(const tpm_json_document_t *document, int array) {
    if (!document || !node_valid(document, array) ||
        document->parser.nodes[array].type != JSON_ARRAY) return -1;
    int count = 0;
    for (int child = document->parser.nodes[array].first_child;
         child >= 0; child = document->parser.nodes[child].next_sibling) {
        if (++count == INT_MAX) return -1;
    }
    return count;
}

int tpm_json_array_at(const tpm_json_document_t *document, int array,
                      size_t index) {
    if (!document || !node_valid(document, array) ||
        document->parser.nodes[array].type != JSON_ARRAY) return -1;
    size_t current = 0;
    for (int child = document->parser.nodes[array].first_child;
         child >= 0; child = document->parser.nodes[child].next_sibling) {
        if (current++ == index) return child;
    }
    return -1;
}

int tpm_json_node_string(const tpm_json_document_t *document, int node,
                         const char **text, size_t *length) {
    if (!node_valid(document, node) ||
        document->parser.nodes[node].type != JSON_STRING) return -1;
    if (text) *text = document->parser.nodes[node].text;
    if (length) *length = document->parser.nodes[node].text_len;
    return 0;
}

int tpm_json_node_bool(const tpm_json_document_t *document, int node, int *value) {
    if (!node_valid(document, node) || !value) return -1;
    if (document->parser.nodes[node].type == JSON_TRUE) {
        *value = 1;
        return 0;
    }
    if (document->parser.nodes[node].type == JSON_FALSE) {
        *value = 0;
        return 0;
    }
    return -1;
}

int tpm_json_node_uint64(const tpm_json_document_t *document, int node,
                         uint64_t *value) {
    if (!node_valid(document, node) || !value ||
        document->parser.nodes[node].type != JSON_NUMBER ||
        document->parser.nodes[node].text_len == 0) return -1;

    uint64_t parsed = 0;
    const char *text = document->parser.nodes[node].text;
    for (size_t i = 0; i < document->parser.nodes[node].text_len; ++i) {
        unsigned char c = (unsigned char)text[i];
        if (c < '0' || c > '9') return -1;
        unsigned int digit = (unsigned int)(c - '0');
        if (parsed > (UINT64_MAX - digit) / 10) return -1;
        parsed = parsed * 10 + digit;
    }
    *value = parsed;
    return 0;
}

static int object_has_only_keys(const json_parser_t *parser, int object,
                                const char *const *allowed, size_t count) {
    if (object < 0 || parser->nodes[object].type != JSON_OBJECT) return 0;
    for (int key = parser->nodes[object].first_child;
         key >= 0; key = parser->nodes[key].next_sibling) {
        int value = parser->nodes[key].next_sibling;
        if (value < 0 || parser->nodes[key].type != JSON_STRING) return 0;
        int found = 0;
        for (size_t i = 0; i < count; ++i) {
            size_t len = strlen(allowed[i]);
            if (parser->nodes[key].text_len == len &&
                memcmp(parser->nodes[key].text, allowed[i], len) == 0) {
                found = 1;
                break;
            }
        }
        if (!found) return 0;
        key = value;
    }
    return 1;
}

static int copy_string(const json_parser_t *parser, int node,
                       char *output, size_t output_size) {
    if (node < 0 || parser->nodes[node].type != JSON_STRING ||
        parser->nodes[node].text_len == 0 ||
        parser->nodes[node].text_len >= output_size) return -1;
    memcpy(output, parser->nodes[node].text, parser->nodes[node].text_len + 1);
    return 0;
}

static int parse_uint(const json_parser_t *parser, int node, uint64_t *out) {
    if (node < 0 || parser->nodes[node].type != JSON_NUMBER ||
        parser->nodes[node].text_len == 0) return -1;
    uint64_t value = 0;
    const char *text = parser->nodes[node].text;
    for (size_t i = 0; i < parser->nodes[node].text_len; ++i) {
        unsigned char c = (unsigned char)text[i];
        if (c < '0' || c > '9') return -1;
        unsigned int digit = c - '0';
        if (value > (UINT64_MAX - digit) / 10) return -1;
        value = value * 10 + digit;
    }
    if (value == 0) return -1;
    *out = value;
    return 0;
}

static int valid_identifier(const char *value) {
    if (!value || !value[0] || strlen(value) >= 64) return 0;
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
        if (!( (*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
               (*p >= '0' && *p <= '9') || *p == '.' || *p == '_' ||
               *p == ':' || *p == '-')) return 0;
    }
    return 1;
}

static int valid_sha256(const char *value) {
    if (!value || strlen(value) != 64) return 0;
    int nonzero = 0;
    for (size_t i = 0; i < 64; ++i) {
        unsigned char c = (unsigned char)value[i];
        if (!isxdigit(c)) return 0;
        if (c != '0') nonzero = 1;
    }
    return nonzero;
}

static int fingerprint_public_key(EVP_PKEY *key, char output[65]) {
    int der_len = i2d_PUBKEY(key, NULL);
    unsigned char *der = der_len > 0 ? malloc((size_t)der_len) : NULL;
    if (!der) return -1;
    unsigned char *cursor = der;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    int ok = i2d_PUBKEY(key, &cursor) == der_len &&
        EVP_Digest(der, (size_t)der_len, digest, &digest_len,
                   EVP_sha256(), NULL) == 1 && digest_len == 32;
    free(der);
    if (!ok) return -1;
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; ++i) {
        output[i * 2] = hex[digest[i] >> 4];
        output[i * 2 + 1] = hex[digest[i] & 15];
    }
    output[64] = '\0';
    OPENSSL_cleanse(digest, sizeof(digest));
    return 0;
}

static int verify_signature(const unsigned char *message, size_t message_len,
                            const unsigned char *signature, size_t signature_len,
                            const tpm_trust_feed_policy_t *policy) {
    static const unsigned char domain[] = "SPPIO-TPM-TRUST-FEED-V1\n";
    if (message_len > TPM_TRUST_FEED_MAX_BYTES ||
        sizeof(domain) - 1 > SIZE_MAX - message_len) return -1;
    size_t signed_len = sizeof(domain) - 1 + message_len;
    unsigned char *signed_message = malloc(signed_len);
    if (!signed_message) return -1;
    memcpy(signed_message, domain, sizeof(domain) - 1);
    memcpy(signed_message + sizeof(domain) - 1, message, message_len);

    BIO *bio = BIO_new_mem_buf(policy->trust_anchor_public_key_pem, -1);
    EVP_PKEY *key = bio ? PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL) : NULL;
    BIO_free(bio);
    if (!key) {
        free(signed_message);
        return 0;
    }

    char fingerprint[65];
    if (fingerprint_public_key(key, fingerprint) != 0) {
        EVP_PKEY_free(key);
        free(signed_message);
        return -1;
    }
    if (strcasecmp(fingerprint, policy->trust_anchor_sha256) != 0) {
        EVP_PKEY_free(key);
        free(signed_message);
        return 0;
    }

    const char *algorithm = policy->signature_algorithm;
    int key_type = EVP_PKEY_base_id(key);
    const EVP_MD *digest = NULL;
    int rsa_padding = 0;
    int algorithm_valid = 0;
    if (strcmp(algorithm, "ed25519") == 0) {
        algorithm_valid = key_type == EVP_PKEY_ED25519 && signature_len == 64;
    } else if (strcmp(algorithm, "rsa-pss-sha256") == 0) {
        algorithm_valid = (key_type == EVP_PKEY_RSA ||
                           key_type == EVP_PKEY_RSA_PSS) &&
                          EVP_PKEY_get_bits(key) >= 3072;
        digest = EVP_sha256();
        rsa_padding = RSA_PKCS1_PSS_PADDING;
    } else if (strcmp(algorithm, "ecdsa-p256-sha256") == 0 ||
               strcmp(algorithm, "ecdsa-p384-sha384") == 0) {
        char group[80] = {0};
        size_t group_len = 0;
        int p384 = strcmp(algorithm, "ecdsa-p384-sha384") == 0;
        algorithm_valid = key_type == EVP_PKEY_EC &&
            EVP_PKEY_get_bits(key) == (p384 ? 384 : 256) &&
            EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME,
                group, sizeof(group), &group_len) == 1 &&
            strcmp(group, p384 ? "secp384r1" : "prime256v1") == 0;
        digest = p384 ? EVP_sha384() : EVP_sha256();
    }
    if (!algorithm_valid) {
        EVP_PKEY_free(key);
        free(signed_message);
        return 0;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *key_ctx = NULL;
    if (!ctx || EVP_DigestVerifyInit(ctx, &key_ctx, digest, NULL, key) != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(key);
        free(signed_message);
        return -1;
    }
    int configured = 1;
    if (rsa_padding) {
        configured = key_ctx &&
            EVP_PKEY_CTX_set_rsa_padding(key_ctx, rsa_padding) > 0 &&
            EVP_PKEY_CTX_set_rsa_mgf1_md(key_ctx, EVP_sha256()) > 0 &&
            EVP_PKEY_CTX_set_rsa_pss_saltlen(key_ctx, 32) > 0;
    }
    int result = configured
        ? EVP_DigestVerify(ctx, signature, signature_len,
                           signed_message, signed_len)
        : -1;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    free(signed_message);
    return result < 0 ? -1 : result == 1;
}

static int certificate_fingerprint(const char *pem, uint64_t now_epoch_seconds,
                                   char output[65]) {
    BIO *bio = BIO_new_mem_buf(pem, -1);
    X509 *certificate = bio ? PEM_read_bio_X509(bio, NULL, NULL, NULL) : NULL;
    BIO_free(bio);
    time_t verification_time = (time_t)now_epoch_seconds;
    if (!certificate || (uint64_t)verification_time != now_epoch_seconds ||
        X509_check_ca(certificate) <= 0) {
        X509_free(certificate);
        return -1;
    }
    int before = X509_cmp_time(X509_get0_notBefore(certificate),
                               &verification_time);
    int after = X509_cmp_time(X509_get0_notAfter(certificate),
                              &verification_time);
    if (before == 0 || after == 0 || before > 0 || after < 0) {
        X509_free(certificate);
        return -1;
    }
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    int ok = X509_digest(certificate, EVP_sha256(), digest, &digest_len) == 1 &&
             digest_len == 32;
    X509_free(certificate);
    if (!ok) return -1;
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; ++i) {
        output[i * 2] = hex[digest[i] >> 4];
        output[i * 2 + 1] = hex[digest[i] & 15];
    }
    output[64] = '\0';
    OPENSSL_cleanse(digest, sizeof(digest));
    return 0;
}

static int parse_array_strings(const json_parser_t *parser, int array,
                               int fingerprints, char *output,
                               size_t output_stride,
                               size_t *out_count) {
    if (array < 0 || parser->nodes[array].type != JSON_ARRAY) return -1;
    size_t count = 0;
    for (int child = parser->nodes[array].first_child;
         child >= 0; child = parser->nodes[child].next_sibling) {
        if (count >= TPM_TRUST_FEED_MAX_REVOKED) return -1;
        char value[65] = {0};
        if (copy_string(parser, child, value, sizeof(value)) != 0 ||
            (fingerprints ? !valid_sha256(value) : !valid_identifier(value)))
            return -1;
        for (size_t i = 0; i < count; ++i) {
            if (strcmp(output + i * output_stride, value) == 0) return -1;
        }
        memcpy(output + count * output_stride, value, strlen(value) + 1);
        count++;
    }
    *out_count = count;
    return 0;
}

static tpm_trust_feed_result_t parse_feed(const unsigned char *feed_json,
                                           size_t feed_json_len,
                                           uint64_t now_epoch_seconds,
                                           tpm_trust_feed_t *feed) {
    json_parser_t parser;
    int root = -1;
    if (json_parse(feed_json, feed_json_len, &parser, &root) != 0) {
        json_free(&parser);
        return TPM_TRUST_FEED_INVALID_JSON;
    }
    static const char *const top_keys[] = {
        "schema", "authority_id", "sequence", "issued_at", "expires_at",
        "ek_roots", "revoked_device_ids", "revoked_ek_fingerprints"
    };
    tpm_trust_feed_result_t result = TPM_TRUST_FEED_INVALID_SCHEMA;
    if (parser.nodes[root].type != JSON_OBJECT ||
        !object_has_only_keys(&parser, root, top_keys,
                              sizeof(top_keys) / sizeof(top_keys[0])))
        goto done;

    char schema[64] = {0};
    int node = object_member(&parser, root, "schema");
    if (copy_string(&parser, node, schema, sizeof(schema)) != 0 ||
        strcmp(schema, "sppio-tpm-trust-feed-v1") != 0 ||
        copy_string(&parser, object_member(&parser, root, "authority_id"),
                    feed->authority_id, sizeof(feed->authority_id)) != 0 ||
        !valid_identifier(feed->authority_id) ||
        parse_uint(&parser, object_member(&parser, root, "sequence"),
                   &feed->sequence) != 0 ||
        parse_uint(&parser, object_member(&parser, root, "issued_at"),
                   &feed->issued_at) != 0 ||
        parse_uint(&parser, object_member(&parser, root, "expires_at"),
                   &feed->expires_at) != 0 ||
        feed->expires_at <= feed->issued_at)
        goto done;

    int roots = object_member(&parser, root, "ek_roots");
    if (roots < 0 || parser.nodes[roots].type != JSON_ARRAY) goto done;
    static const char *const root_keys[] = {"id", "pem", "sha256"};
    for (int child = parser.nodes[roots].first_child;
         child >= 0; child = parser.nodes[child].next_sibling) {
        if (feed->ek_root_count >= TPM_TRUST_FEED_MAX_EK_ROOTS ||
            parser.nodes[child].type != JSON_OBJECT ||
            !object_has_only_keys(&parser, child, root_keys, 3))
            goto done;
        tpm_trust_feed_ek_root_t *root_entry =
            &feed->ek_roots[feed->ek_root_count];
        if (copy_string(&parser, object_member(&parser, child, "id"),
                        root_entry->id, sizeof(root_entry->id)) != 0 ||
            !valid_identifier(root_entry->id) ||
            copy_string(&parser, object_member(&parser, child, "pem"),
                        root_entry->certificate_pem,
                        sizeof(root_entry->certificate_pem)) != 0 ||
            copy_string(&parser, object_member(&parser, child, "sha256"),
                        root_entry->sha256, sizeof(root_entry->sha256)) != 0 ||
            !valid_sha256(root_entry->sha256))
            goto done;
        char actual_fingerprint[65];
        if (certificate_fingerprint(root_entry->certificate_pem,
                                    now_epoch_seconds,
                                    actual_fingerprint) != 0 ||
            strcasecmp(actual_fingerprint, root_entry->sha256) != 0)
            goto done;
        for (size_t i = 0; i < feed->ek_root_count; ++i) {
            if (strcmp(feed->ek_roots[i].id, root_entry->id) == 0 ||
                strcasecmp(feed->ek_roots[i].sha256, root_entry->sha256) == 0)
                goto done;
        }
        feed->ek_root_count++;
    }
    if (feed->ek_root_count == 0 ||
        parse_array_strings(&parser,
            object_member(&parser, root, "revoked_device_ids"), 0,
            &feed->revoked_device_ids[0][0],
            sizeof(feed->revoked_device_ids[0]),
            &feed->revoked_device_count) != 0 ||
        parse_array_strings(&parser,
            object_member(&parser, root, "revoked_ek_fingerprints"), 1,
            &feed->revoked_ek_fingerprints[0][0],
            sizeof(feed->revoked_ek_fingerprints[0]),
            &feed->revoked_ek_count) != 0)
        goto done;

    result = TPM_TRUST_FEED_VALID;
done:
    json_free(&parser);
    return result;
}

static int valid_provisioning(const tpm_trust_feed_policy_t *policy) {
    if (!policy || !valid_identifier(policy->authority_id) ||
        !policy->trust_anchor_public_key_pem ||
        !policy->trust_anchor_public_key_pem[0] ||
        strlen(policy->trust_anchor_public_key_pem) >= TRUST_KEY_PEM_MAX ||
        !valid_sha256(policy->trust_anchor_sha256) ||
        !policy->signature_algorithm || !policy->signature_algorithm[0] ||
        policy->max_evidence_age_seconds == 0 ||
        !policy->replay_state_available)
        return 0;
    return strcmp(policy->signature_algorithm, "ed25519") == 0 ||
           strcmp(policy->signature_algorithm, "rsa-pss-sha256") == 0 ||
           strcmp(policy->signature_algorithm, "ecdsa-p256-sha256") == 0 ||
           strcmp(policy->signature_algorithm, "ecdsa-p384-sha384") == 0;
}

tpm_trust_feed_result_t tpm_trust_feed_verify(
    const unsigned char *feed_json, size_t feed_json_len,
    const unsigned char *signature, size_t signature_len,
    const tpm_trust_feed_policy_t *policy, uint64_t now_epoch_seconds,
    tpm_trust_feed_t *out_feed) {
    if (out_feed) memset(out_feed, 0, sizeof(*out_feed));
    if (!valid_provisioning(policy) || now_epoch_seconds == 0)
        return TPM_TRUST_FEED_BLOCKED_CONFIGURATION;
    if (!out_feed) return TPM_TRUST_FEED_INTERNAL_ERROR;
    if (!feed_json || feed_json_len == 0 ||
        feed_json_len > TPM_TRUST_FEED_MAX_BYTES)
        return TPM_TRUST_FEED_INVALID_JSON;
    if (!signature || signature_len == 0 ||
        signature_len > TRUST_SIGNATURE_MAX)
        return TPM_TRUST_FEED_INVALID_SIGNATURE;

    int verified = verify_signature(feed_json, feed_json_len, signature,
                                    signature_len, policy);
    if (verified != 1)
        return verified < 0 ? TPM_TRUST_FEED_INTERNAL_ERROR
                            : TPM_TRUST_FEED_INVALID_SIGNATURE;

    tpm_trust_feed_result_t parsed =
        parse_feed(feed_json, feed_json_len, now_epoch_seconds, out_feed);
    if (parsed != TPM_TRUST_FEED_VALID) {
        OPENSSL_cleanse(out_feed, sizeof(*out_feed));
        return parsed;
    }
    if (strcmp(out_feed->authority_id, policy->authority_id) != 0) {
        OPENSSL_cleanse(out_feed, sizeof(*out_feed));
        return TPM_TRUST_FEED_UNKNOWN_AUTHORITY;
    }
    if (out_feed->sequence <= policy->highest_persisted_sequence) {
        OPENSSL_cleanse(out_feed, sizeof(*out_feed));
        return TPM_TRUST_FEED_REPLAYED;
    }
    if (out_feed->issued_at > now_epoch_seconds ||
        now_epoch_seconds - out_feed->issued_at >
            policy->max_evidence_age_seconds ||
        out_feed->expires_at <= now_epoch_seconds ||
        out_feed->expires_at - out_feed->issued_at >
            policy->max_evidence_age_seconds) {
        OPENSSL_cleanse(out_feed, sizeof(*out_feed));
        return TPM_TRUST_FEED_EXPIRED;
    }
    return TPM_TRUST_FEED_VALID;
}

const char *tpm_trust_feed_result_name(tpm_trust_feed_result_t result) {
    switch (result) {
        case TPM_TRUST_FEED_VALID: return "VALID";
        case TPM_TRUST_FEED_BLOCKED_CONFIGURATION: return "BLOCKED_CONFIGURATION";
        case TPM_TRUST_FEED_INVALID_JSON: return "INVALID_JSON";
        case TPM_TRUST_FEED_INVALID_SCHEMA: return "INVALID_SCHEMA";
        case TPM_TRUST_FEED_UNKNOWN_AUTHORITY: return "UNKNOWN_AUTHORITY";
        case TPM_TRUST_FEED_INVALID_SIGNATURE: return "INVALID_SIGNATURE";
        case TPM_TRUST_FEED_EXPIRED: return "EXPIRED";
        case TPM_TRUST_FEED_REPLAYED: return "REPLAYED";
        case TPM_TRUST_FEED_INTERNAL_ERROR: return "INTERNAL_ERROR";
    }
    return "UNKNOWN";
}
