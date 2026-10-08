#ifndef EXAMOS_HARDWARE_GUARD_H
#define EXAMOS_HARDWARE_GUARD_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int display_count;
    int external_display_detected;
    int usb_storage_detected;
    int audio_input_available;
    int audio_output_available;
    int unauthorized_device_flag;
} hardware_state_t;

int hardware_guard_init(void);
int hardware_guard_scan(hardware_state_t *state);
int hardware_guard_format_json(const hardware_state_t *state, char *out_buf, size_t max_len);

#ifdef __cplusplus
}
#endif

#endif // EXAMOS_HARDWARE_GUARD_H
