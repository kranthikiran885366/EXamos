#ifndef EXAMOS_CONFIG_MANAGER_H
#define EXAMOS_CONFIG_MANAGER_H
#include <stddef.h>

#define EXAM_CONF_PATH "/etc/examos/exam.conf"
#define ADMIN_CONF_PATH "/etc/examos/admin.conf"
#define EXAM_URL_MAX 512
#define EXAM_NAME_MAX 128
#define ADMIN_HASH_LEN 65   /* SHA-256 hex + null */

typedef struct {
    char exam_url[EXAM_URL_MAX];
    char exam_name[EXAM_NAME_MAX];
    int  exam_duration_minutes;
    int  configured;            /* 1 if a valid URL has been set */
} exam_config_t;

/* Returns 0 on success, -1 if file missing or malformed. Fills *cfg. */
int  config_load(exam_config_t *cfg);

/* Writes exam_url, exam_name, and duration to EXAM_CONF_PATH atomically. Returns 0 on success. */
int  config_save(const exam_config_t *cfg);

/* Reads the SHA-256 hex hash of the admin password from ADMIN_CONF_PATH.
   Writes into out_hash (must be at least ADMIN_HASH_LEN bytes). Returns 0 on success. */
int  config_load_admin_hash(char *out_hash, size_t max_len);

/* Validates that the given plain-text password matches the stored hash. Returns 1 if valid, 0 if not. */
int  config_verify_admin_password(const char *plaintext_password);

#endif
