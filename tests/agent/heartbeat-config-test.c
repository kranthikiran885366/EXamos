#define _POSIX_C_SOURCE 200809L
#include "../../agent/include/heartbeat.h"
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(expression) do { \
    if (!(expression)) { \
        fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #expression); \
        return EXIT_FAILURE; \
    } \
} while (0)

int main(void) {
    heartbeat_payload_t payload = {0};
    char oversized_url[4097];

    CHECK(unsetenv("EXAMOS_TPM_MODE") == 0);
    CHECK(curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK);
    CHECK(heartbeat_collect_metrics(&payload) == -1);
    CHECK(heartbeat_send(&payload, NULL, NULL) == -1);
    CHECK(heartbeat_init("https://exam.invalid/api/v1/heartbeat", "device-1") == -1);
    CHECK(setenv("EXAMOS_TPM_MODE", "invalid", 1) == 0);
    CHECK(heartbeat_init("https://exam.invalid/api/v1/heartbeat", "device-1") == -1);
    CHECK(setenv("EXAMOS_TPM_MODE", "development", 1) == 0);
    CHECK(heartbeat_init(NULL, "device-1") == -1);
    CHECK(heartbeat_init("", "device-1") == -1);
    CHECK(heartbeat_init("https://exam.invalid/api/v1/heartbeat", NULL) == -1);
    CHECK(heartbeat_init("ftp://exam.invalid/api/v1/heartbeat", "device-1") == -1);
    CHECK(heartbeat_init("https://user:password@exam.invalid/heartbeat", "device-1") == -1);
    CHECK(heartbeat_init("https://exam.invalid/heartbeat?token=value", "device-1") == -1);
    CHECK(heartbeat_init("https://exam.invalid/heartbeat#fragment", "device-1") == -1);
    CHECK(setenv("EXAMOS_TPM_MODE", "production", 1) == 0);
    CHECK(heartbeat_init("http://exam.invalid/heartbeat", "device-1") == -1);

    memset(oversized_url, 'a', sizeof(oversized_url));
    memcpy(oversized_url, "https://exam.invalid/", sizeof("https://exam.invalid/") - 1);
    oversized_url[sizeof(oversized_url) - 1] = '\0';
    CHECK(heartbeat_init(oversized_url, "device-1") == -1);

    char oversized_device_id[EXAMOS_HEARTBEAT_DEVICE_ID_MAX + 2];
    memset(oversized_device_id, 'd', sizeof(oversized_device_id) - 1);
    oversized_device_id[sizeof(oversized_device_id) - 1] = '\0';
    CHECK(heartbeat_init("https://exam.invalid/heartbeat", oversized_device_id) == -1);

    CHECK(setenv("EXAMOS_TPM_MODE", "development", 1) == 0);
    CHECK(heartbeat_init("http://exam.invalid/api/v1/heartbeat", "device-1") == 0);
    CHECK(heartbeat_collect_metrics(&payload) == 0);
    CHECK(strcmp(payload.device_id, "device-1") == 0);

    CHECK(setenv("EXAMOS_TPM_MODE", "production", 1) == 0);
    CHECK(heartbeat_init("http://exam.invalid/heartbeat", "device-1") == -1);

    CHECK(heartbeat_init("https://exam.invalid/api/v1/heartbeat", "device-1") == 0);
    CHECK(heartbeat_collect_metrics(&payload) == 0);
    CHECK(strcmp(payload.device_id, "device-1") == 0);

    curl_global_cleanup();
    puts("heartbeat configuration tests passed");
    return 0;
}
