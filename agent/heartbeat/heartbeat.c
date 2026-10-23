#define _GNU_SOURCE
#include "../include/heartbeat.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <dirent.h>
#include <curl/curl.h>

static char g_server_url[256];
static char g_device_id[65];

int heartbeat_init(const char *server_url, const char *device_id) {
    if (!server_url || !*server_url || strlen(server_url) >= sizeof(g_server_url) ||
        !device_id || !*device_id || strlen(device_id) >= sizeof(g_device_id)) return -1;
    if (strncmp(server_url, "https://", 8) != 0) return -1;
    snprintf(g_server_url, sizeof(g_server_url), "%s", server_url);
    snprintf(g_device_id, sizeof(g_device_id), "%s", device_id);
    return curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK ? 0 : -1;
}

static int count_running_processes(void) {
    int count = 0;
    DIR *dir = opendir("/proc");
    if (!dir) return 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] >= '0' && entry->d_name[0] <= '9') {
            count++;
        }
    }
    closedir(dir);
    return count;
}

int heartbeat_collect_metrics(heartbeat_payload_t *payload) {
    if (!payload) return -1;
    memset(payload, 0, sizeof(heartbeat_payload_t));

    payload->timestamp = (long)time(NULL);
    snprintf(payload->device_id, sizeof(payload->device_id), "%s", g_device_id);

    // Read Uptime
    FILE *f_up = fopen("/proc/uptime", "r");
    if (f_up) {
        double up = 0;
        if (fscanf(f_up, "%lf", &up) == 1) {
            payload->uptime_seconds = (long)up;
        }
        fclose(f_up);
    }

    // Read Memory
    FILE *f_mem = fopen("/proc/meminfo", "r");
    if (f_mem) {
        char line[256];
        while (fgets(line, sizeof(line), f_mem)) {
            if (strncmp(line, "MemTotal:", 9) == 0) {
                sscanf(line + 9, "%lu", &payload->mem_total_kb);
            } else if (strncmp(line, "MemAvailable:", 13) == 0) {
                sscanf(line + 13, "%lu", &payload->mem_available_kb);
            }
        }
        fclose(f_mem);
    }

    // Read CPU Load
    double loadavg[3];
    if (getloadavg(loadavg, 1) == 1) {
        payload->cpu_load = (float)loadavg[0];
    } else {
        payload->cpu_load = 0.0f;
    }

    payload->process_count = count_running_processes();

    return 0;
}

int heartbeat_send(const heartbeat_payload_t *payload, const char *hardware_json, const char *rf_json) {
    if (!payload) return -1;

    char post_data[4096];
    snprintf(post_data, sizeof(post_data),
             "{"
             "\"device_id\":\"%s\","
             "\"timestamp\":%ld,"
             "\"uptime\":%ld,"
             "\"cpu_load\":%.2f,"
             "\"mem_total_kb\":%lu,"
             "\"mem_avail_kb\":%lu,"
             "\"process_count\":%d,"
             "\"hardware\":%s,"
             "\"rf_environment\":%s"
             "}",
             payload->device_id,
             payload->timestamp,
             payload->uptime_seconds,
             payload->cpu_load,
             payload->mem_total_kb,
             payload->mem_available_kb,
             payload->process_count,
             hardware_json ? hardware_json : "{}",
             rf_json ? rf_json : "{}");

    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    const char *api_token = getenv("EXAMOS_AGENT_API_TOKEN");
    if (!api_token || strlen(api_token) < 32) {
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return -1;
    }
    char authorization[512];
    snprintf(authorization, sizeof(authorization), "Authorization: Bearer %s", api_token);
    headers = curl_slist_append(headers, authorization);
    if (!headers) {
        curl_easy_cleanup(curl);
        return -1;
    }

    CURLcode options_status = curl_easy_setopt(curl, CURLOPT_URL, g_server_url);
    if (options_status == CURLE_OK) options_status = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    if (options_status == CURLE_OK) options_status = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    if (options_status == CURLE_OK) options_status = curl_easy_setopt(curl, CURLOPT_TIMEOUT, 3L);
    if (options_status == CURLE_OK) options_status = curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 2L);
    if (options_status == CURLE_OK) options_status = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    if (options_status == CURLE_OK) options_status = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    if (options_status == CURLE_OK) options_status = curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    if (options_status == CURLE_OK) options_status = curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    CURLcode res = options_status == CURLE_OK ? curl_easy_perform(curl) : options_status;
    long response_status = 0;
    if (res == CURLE_OK) {
        res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_status);
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return (res == CURLE_OK && response_status >= 200 && response_status < 300) ? 0 : -1;
}
