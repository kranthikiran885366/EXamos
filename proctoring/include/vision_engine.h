#ifndef EXAMOS_VISION_ENGINE_H
#define EXAMOS_VISION_ENGINE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Return codes for the analysis entry points. */
#define VISION_ENGINE_OK            0
#define VISION_ENGINE_NO_DETECTOR (-2)   /* no approved detector is available */
#define VISION_ENGINE_NO_FRAME    (-3)   /* the supplied frame was unusable */

/*
 * A cascade detector reports presence and location, not a calibrated
 * probability. The confidence field therefore stays 0.0 for cascade-based
 * detection; a probabilistic scorer would be required to populate it, and
 * fabricating a value would misrepresent the evidence.
 */
typedef struct {
    float x;
    float y;
    float width;
    float height;
    float confidence;
} vision_bbox_t;

typedef struct {
    int           face_count;
    vision_bbox_t faces[8];
    float         yaw_deg;
    float         pitch_deg;
    float         roll_deg;
    float         head_pose_confidence;
    int           phone_detected;
    float         phone_confidence;
    vision_bbox_t phone_bbox;
    int           book_detected;
    float         book_confidence;
    vision_bbox_t book_bbox;
    uint64_t      frame_sequence;
    int64_t       timestamp_ms;
    int           analysis_status;   /* VISION_ENGINE_OK or the failure code */
    int           confidence_available; /* 1 when the scorer produced a score */
    char          scorer[64];        /* identifier of the detector that ran */
} vision_frame_result_t;

/* --- Vision Engine Lifecycle --- */

/*
 * Initialises the detectors.
 *
 * config_path points at the model manifest. Every artefact it names is
 * verified against the SHA-256 digest recorded in the manifest before it is
 * used, so a substituted or corrupted model cannot become examination
 * evidence. When no usable detector can be established the engine refuses
 * to analyse frames rather than producing invented detections.
 *
 * Returns VISION_ENGINE_OK when a face detector is available and
 * VISION_ENGINE_NO_DETECTOR otherwise.
 */
int  vision_engine_init(const char *config_path);
void vision_engine_destroy(void);

/* Identifier of the active face detector, or NULL when none is loaded. */
const char *vision_engine_scorer(void);

/*
 * Analyze raw image frame (RGB24 or Grayscale).
 * width: image width in pixels
 * height: image height in pixels
 * stride: bytes per row
 * channels: 1 (grayscale) or 3 (RGB)
 *
 * Returns VISION_ENGINE_OK, VISION_ENGINE_NO_DETECTOR or
 * VISION_ENGINE_NO_FRAME. out_result is always initialised, so a caller can
 * always report the reason analysis did not happen.
 */
int  vision_engine_analyze_frame(const uint8_t *pixel_data, int width, int height,
                                 int stride, int channels, uint64_t frame_seq,
                                 vision_frame_result_t *out_result);

/* Format frame analysis into normalized proctoring events JSON */
int  vision_engine_format_event_json(const vision_frame_result_t *res, const char *event_type,
                                     char *out_json, size_t max_out);

#ifdef __cplusplus
}
#endif

#endif /* EXAMOS_VISION_ENGINE_H */
