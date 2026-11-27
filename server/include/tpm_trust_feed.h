#ifndef EXAMOS_TPM_TRUST_FEED_H
#define EXAMOS_TPM_TRUST_FEED_H

#include <stddef.h>
#include <stdint.h>

#define TPM_TRUST_FEED_MAX_BYTES (1024U * 1024U)
#define TPM_TRUST_FEED_MAX_EK_ROOTS 32U
#define TPM_TRUST_FEED_MAX_REVOKED 128U
#define TPM_TRUST_FEED_CERT_PEM_MAX 4096U

typedef enum {
    TPM_TRUST_FEED_VALID = 0,
    TPM_TRUST_FEED_BLOCKED_CONFIGURATION,
    TPM_TRUST_FEED_INVALID_JSON,
    TPM_TRUST_FEED_INVALID_SCHEMA,
    TPM_TRUST_FEED_UNKNOWN_AUTHORITY,
    TPM_TRUST_FEED_INVALID_SIGNATURE,
    TPM_TRUST_FEED_EXPIRED,
    TPM_TRUST_FEED_REPLAYED,
    TPM_TRUST_FEED_INTERNAL_ERROR
} tpm_trust_feed_result_t;

typedef struct {
    char id[64];
    char certificate_pem[TPM_TRUST_FEED_CERT_PEM_MAX];
    char sha256[65];
} tpm_trust_feed_ek_root_t;

typedef struct {
    char authority_id[64];
    uint64_t sequence;
    uint64_t issued_at;
    uint64_t expires_at;
    size_t ek_root_count;
    tpm_trust_feed_ek_root_t ek_roots[TPM_TRUST_FEED_MAX_EK_ROOTS];
    size_t revoked_device_count;
    char revoked_device_ids[TPM_TRUST_FEED_MAX_REVOKED][64];
    size_t revoked_ek_count;
    char revoked_ek_fingerprints[TPM_TRUST_FEED_MAX_REVOKED][65];
} tpm_trust_feed_t;

typedef struct {
    const char *authority_id;
    const char *trust_anchor_public_key_pem;
    const char *trust_anchor_sha256;
    const char *signature_algorithm;
    uint64_t max_evidence_age_seconds;
    uint64_t highest_persisted_sequence;
    int replay_state_available;
} tpm_trust_feed_policy_t;

/*
 * Verifies a detached signature over the SPPIO TPM trust-feed domain prefix
 * and exact feed bytes, then validates the strict v1 schema and policy.
 * Trust inputs and the persisted sequence must come from an independently
 * provisioned source.
 */
tpm_trust_feed_result_t tpm_trust_feed_verify(
    const unsigned char *feed_json, size_t feed_json_len,
    const unsigned char *signature, size_t signature_len,
    const tpm_trust_feed_policy_t *policy, uint64_t now_epoch_seconds,
    tpm_trust_feed_t *out_feed);

const char *tpm_trust_feed_result_name(tpm_trust_feed_result_t result);

/*
 * Bounded JSON document API.
 *
 * The trust-feed verifier and the dynamic config loader share one parser so
 * that every on-disk manifest is validated against the same depth, size and
 * duplicate-key limits. Documents are opaque; nodes are integer handles that
 * are only valid while their document is alive. All accessors return -1 on a
 * missing member, a type mismatch, or an invalid handle.
 */
typedef struct tpm_json_document tpm_json_document_t;

typedef enum {
    TPM_JSON_OBJECT = 0,
    TPM_JSON_ARRAY,
    TPM_JSON_STRING,
    TPM_JSON_NUMBER,
    TPM_JSON_TRUE,
    TPM_JSON_FALSE,
    TPM_JSON_NULL
} tpm_json_type_t;

/* Parses and fully validates one JSON document. Returns NULL on any error. */
tpm_json_document_t *tpm_json_document_parse(const char *json, size_t json_len);
void tpm_json_document_free(tpm_json_document_t *document);

int tpm_json_root(const tpm_json_document_t *document);
tpm_json_type_t tpm_json_node_type(const tpm_json_document_t *document, int node);

/* Object access. `key` must be NUL terminated. */
int tpm_json_object_member(const tpm_json_document_t *document, int object,
                           const char *key);
/* Iterates members in document order; returns the value node and its key. */
int tpm_json_object_member_at(const tpm_json_document_t *document, int object,
                              size_t index, const char **key, size_t *key_len);

/* Array access. */
int tpm_json_array_length(const tpm_json_document_t *document, int array);
int tpm_json_array_at(const tpm_json_document_t *document, int array,
                      size_t index);

/* Scalar access. */
int tpm_json_node_string(const tpm_json_document_t *document, int node,
                         const char **text, size_t *length);
int tpm_json_node_bool(const tpm_json_document_t *document, int node, int *value);
int tpm_json_node_uint64(const tpm_json_document_t *document, int node,
                         uint64_t *value);

#endif
