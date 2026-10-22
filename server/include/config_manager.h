#ifndef EXAMOS_CONFIG_MANAGER_H
#define EXAMOS_CONFIG_MANAGER_H
#include <stddef.h>

#define EXAM_CONF_PATH "/etc/examos/exam.conf"
#define ADMIN_CONF_PATH "/etc/examos/admin.conf"
#define EXAM_URL_MAX 512
#define EXAM_NAME_MAX 128

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
int  config_validate_exam_url(const char *url);

/* PBKDF2-SHA256 credential format: iterations:salt_hex:hash_hex. */
int config_verify_password_hash(const char *plaintext_password,
                                const char *credential);
int config_verify_admin_credentials(const char *username,
                                    const char *plaintext_password);

#endif
