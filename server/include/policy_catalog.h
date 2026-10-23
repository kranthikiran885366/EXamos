#ifndef EXAMOS_POLICY_CATALOG_H
#define EXAMOS_POLICY_CATALOG_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define POLICY_CATALOG_MAX      64
#define POLICY_NAME_MAX         64
#define POLICY_DESCRIPTION_MAX  256
#define POLICY_JSON_MAX         8192

/*
 * The browser/kiosk policy catalog is provisioned deployment content, not a
 * compiled-in default. An exam must reference a policy that the deployment
 * actually ships, so that the enforced policy is always auditable and
 * versioned alongside the release.
 */
typedef struct {
    char name[POLICY_NAME_MAX];
    char description[POLICY_DESCRIPTION_MAX];
    char policy_json[POLICY_JSON_MAX];
} policy_catalog_entry_t;

/*
 * Loads the catalog from a JSON file.
 * Returns 0 on success, -1 when the file is unreadable or malformed.
 */
int  policy_catalog_load(const char *path);

/* Returns 1 when a catalog has been loaded, 0 otherwise. */
int  policy_catalog_is_loaded(void);

/* Copies the policy JSON for a named entry. Returns 0 on success. */
int  policy_catalog_get(const char *name, char *out_json, size_t max_len);

/* Writes a JSON array of the available policy names and descriptions. */
int  policy_catalog_names_json(char *out_json, size_t max_len);

#ifdef __cplusplus
}
#endif

#endif /* EXAMOS_POLICY_CATALOG_H */
