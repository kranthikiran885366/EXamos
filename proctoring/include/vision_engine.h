#ifndef EXAMOS_VISION_ENGINE_H
#define EXAMOS_VISION_ENGINE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

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
} vision_frame_result_t;

/* --- Vision Engine Lifecycle --- */
int  vision_engine_init(const char *config_path);
void vision_engine_destroy(void);

/*
 * Analyze raw image frame (RGB24 or Grayscale).
 * width: image width in pixels
 * height: image height in pixels
 * stride: bytes per row
 * channels: 1 (grayscale) or 3 (RGB)
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
