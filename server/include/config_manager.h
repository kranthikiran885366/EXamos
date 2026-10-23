#ifndef EXAMOS_CONFIG_MANAGER_H
#define EXAMOS_CONFIG_MANAGER_H
#include <stddef.h>

#define EXAM_CONF_PATH "/etc/examos/exam.conf"
#define ADMIN_CONF_PATH "/etc/examos/admin.conf"
#define EXAM_URL_MAX 512
#define EXAM_NAME_MAX 128
#define EXAM_ALLOWED_ORIGINS_MAX 1024
#define EXAM_ID_MAX 64

typedef struct {
    char exam_url[EXAM_URL_MAX];
    char exam_name[EXAM_NAME_MAX];
    char exam_id[EXAM_ID_MAX];  /* stable examination identifier (provisioned) */
    char allowed_origins[EXAM_ALLOWED_ORIGINS_MAX];
    int  exam_duration_minutes;
    int  configured;            /* 1 if a valid URL has been set */
} exam_config_t;

/* Returns 0 on success, -1 if file missing or malformed. Fills *cfg. */
int  config_load(exam_config_t *cfg);

/* Validates a provisioned examination identifier: non-empty, <= EXAM_ID_MAX-1,
 * and restricted to [A-Za-z0-9._-]. Returns 1 if valid, 0 otherwise. */
int  config_validate_exam_id(const char *exam_id);

/* Resolves the active examination identifier from the provisioned exam.conf.
 * Returns 0 and fills out_exam_id when a valid identifier is configured;
 * returns -1 when no examination identity has been provisioned, so callers
 * fail closed rather than fabricate a default. */
int  config_active_exam_id(char *out_exam_id, size_t out_size);

/* Writes exam_url, exam_name, and duration to EXAM_CONF_PATH atomically. Returns 0 on success. */
int  config_save(const exam_config_t *cfg);
int  config_validate_exam_url(const char *url);
int  config_validate_allowed_origins(const char *origins);

/* PBKDF2-SHA256 credential format: iterations:salt_hex:hash_hex. */
int config_create_password_hash(const char *plaintext_password,
                                char *out_credential, size_t credential_size);
int config_verify_password_hash(const char *plaintext_password,
                                const char *credential);
int config_verify_admin_credentials(const char *username,
                                    const char *plaintext_password);

#endif
