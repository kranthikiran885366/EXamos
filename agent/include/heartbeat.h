#ifndef EXAMOS_HEARTBEAT_H
#define EXAMOS_HEARTBEAT_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    long timestamp;
    long uptime_seconds;
    float cpu_load;
    unsigned long mem_total_kb;
    unsigned long mem_available_kb;
    int process_count;
    char device_id[65];
} heartbeat_payload_t;

int heartbeat_init(const char *server_url, const char *device_id);
int heartbeat_collect_metrics(heartbeat_payload_t *payload);
int heartbeat_format_json(const heartbeat_payload_t *payload, const char *hardware_json, const char *rf_json, char *out, size_t out_len);
int heartbeat_send_json(const char *post_data);
int heartbeat_send(const heartbeat_payload_t *payload, const char *hardware_json, const char *rf_json);

#ifdef __cplusplus
}
#endif

#endif // EXAMOS_HEARTBEAT_H
