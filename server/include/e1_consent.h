#ifndef EXAMOS_E1_CONSENT_H
#define EXAMOS_E1_CONSENT_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int wifi;
    int ble;
    int rf;
    int second_camera;
} e1_consent_scopes_t;

/*
 * Parse a complete source-scope consent object and append it to the existing
 * per-session event chain. This records candidate preference only; it never
 * authorizes or starts sensor collection.
 */
int e1_consent_record_json(const char *session_id, const char *request_json,
                           e1_consent_scopes_t *out_scopes);

#ifdef __cplusplus
}
#endif

#endif
