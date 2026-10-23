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
    int process_violation_detected;
    int audio_input_available;
    int audio_output_available;
    int unauthorized_device_flag;
    int camera_available;   /* a V4L2 capture device was opened and queried */
    int camera_count;       /* number of usable capture devices found */
    int network_state;      /* see network_state_t */
} hardware_state_t;

/* Network reachability as measured on the device itself. */
typedef enum {
    DEVICE_NETWORK_UNKNOWN = 0,
    DEVICE_NETWORK_ONLINE,
    DEVICE_NETWORK_OFFLINE
} device_network_state_t;

int hardware_guard_init(void);
int hardware_guard_scan(hardware_state_t *state);
int hardware_guard_format_json(const hardware_state_t *state, char *out_buf, size_t max_len);

/*
 * Measures the device's own network reachability by inspecting the kernel's
 * link state for every non-loopback interface. This is a measurement, not a
 * configuration value.
 */
device_network_state_t hardware_guard_detect_network(void);
const char *hardware_guard_network_state_name(device_network_state_t state);

#ifdef __cplusplus
}
#endif

#endif // EXAMOS_HARDWARE_GUARD_H
