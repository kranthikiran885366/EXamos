#ifndef EXAMOS_SECOND_CAMERA_H
#define EXAMOS_SECOND_CAMERA_H

#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_SECOND_CAMERA_SESSIONS 256
#define QR_TOKEN_LEN 64

typedef enum {
    SECOND_CAM_STATE_UNPAIRED = 0,
    SECOND_CAM_STATE_PAIRING_REQUESTED,
    SECOND_CAM_STATE_PAIRED,
    SECOND_CAM_STATE_CONNECTED,
    SECOND_CAM_STATE_DISCONNECTED,
    SECOND_CAM_STATE_EXPIRED
} second_cam_state_t;

typedef struct {
    char               session_id[64];
    char               qr_pairing_token[QR_TOKEN_LEN + 1];
    second_cam_state_t state;
    time_t             token_created_at;
    time_t             connected_at;
    time_t             expires_at;
    int                token_used;
} second_camera_session_t;

/* --- Lifecycle & Operations --- */
void second_camera_init(void);

/* Generate a short-lived one-time pairing QR token bound to a session */
int  second_camera_create_pairing_token(const char *session_id, char *out_token, size_t max_out);

/* Validate and claim a pairing token when mobile browser connects */
int  second_camera_validate_pairing(const char *session_id, const char *pairing_token);

/* Update status when second camera stream disconnects */
void second_camera_disconnect(const char *session_id);

/* Check current state of second camera for a session */
second_cam_state_t second_camera_get_status(const char *session_id);

/* Returns self-contained responsive mobile HTML page for second camera capture */
const char *second_camera_portal_html(const char *session_id, const char *token);

#ifdef __cplusplus
}
#endif

#endif /* EXAMOS_SECOND_CAMERA_H */
