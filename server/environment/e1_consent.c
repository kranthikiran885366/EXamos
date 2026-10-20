#include "../include/e1_consent.h"
#include "../include/event_chain.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

enum {
    E1_SCOPE_WIFI = 1U << 0,
    E1_SCOPE_BLE = 1U << 1,
    E1_SCOPE_RF = 1U << 2,
    E1_SCOPE_SECOND_CAMERA = 1U << 3,
    E1_SCOPE_SESSION = 1U << 4,
    E1_SCOPE_ALL = E1_SCOPE_WIFI | E1_SCOPE_BLE |
                   E1_SCOPE_RF | E1_SCOPE_SECOND_CAMERA | E1_SCOPE_SESSION
};

static void skip_whitespace(const char **cursor)
{
    while (**cursor && isspace((unsigned char)**cursor)) {
        (*cursor)++;
    }
}

static int parse_scope_key(const char **cursor, unsigned int *scope)
{
    static const struct {
        const char *name;
        unsigned int scope;
    } keys[] = {
        {"wifi", E1_SCOPE_WIFI},
        {"ble", E1_SCOPE_BLE},
        {"rf", E1_SCOPE_RF},
        {"second_camera", E1_SCOPE_SECOND_CAMERA},
        {"session_id", E1_SCOPE_SESSION}
    };
    const char *start;
    size_t length;

    if (**cursor != '"') {
        return -1;
    }
    start = ++(*cursor);
    while (**cursor && **cursor != '"' && **cursor != '\\') {
        (*cursor)++;
    }
    if (**cursor != '"') {
        return -1;
    }
    length = (size_t)(*cursor - start);
    (*cursor)++;

    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        if (strlen(keys[i].name) == length &&
            memcmp(start, keys[i].name, length) == 0) {
            *scope = keys[i].scope;
            return 0;
        }
    }
    return -1;
}

static int parse_boolean(const char **cursor, int *value)
{
    if (strncmp(*cursor, "true", 4) == 0 &&
        ((*cursor)[4] == ',' || (*cursor)[4] == '}' ||
         isspace((unsigned char)(*cursor)[4]))) {
        *value = 1;
        *cursor += 4;
        return 0;
    }
    if (strncmp(*cursor, "false", 5) == 0 &&
        ((*cursor)[5] == ',' || (*cursor)[5] == '}' ||
         isspace((unsigned char)(*cursor)[5]))) {
        *value = 0;
        *cursor += 5;
        return 0;
    }
    return -1;
}

static int parse_consent(const char *json, const char *expected_session_id,
                         e1_consent_scopes_t *scopes)
{
    const char *cursor = json;
    unsigned int seen = 0;

    if (!json || !scopes) {
        return -1;
    }
    memset(scopes, 0, sizeof(*scopes));
    skip_whitespace(&cursor);
    if (*cursor++ != '{') {
        return -1;
    }

    for (;;) {
        unsigned int scope = 0;
        int value = 0;

        skip_whitespace(&cursor);
        if (parse_scope_key(&cursor, &scope) != 0 || (seen & scope)) {
            return -1;
        }
        seen |= scope;
        skip_whitespace(&cursor);
        if (*cursor++ != ':') {
            return -1;
        }
        skip_whitespace(&cursor);
        if (scope == E1_SCOPE_SESSION) {
            const char *start;
            size_t session_length;
            if (*cursor++ != '"') {
                return -1;
            }
            start = cursor;
            while (*cursor && *cursor != '"' && *cursor != '\\') {
                cursor++;
            }
            if (*cursor != '"') {
                return -1;
            }
            session_length = (size_t)(cursor - start);
            if (session_length != strlen(expected_session_id) ||
                memcmp(start, expected_session_id, session_length) != 0) {
                return -1;
            }
            cursor++;
            skip_whitespace(&cursor);
            if (*cursor == '}') {
                cursor++;
                break;
            }
            if (*cursor++ != ',') {
                return -1;
            }
            continue;
        }
        if (parse_boolean(&cursor, &value) != 0) {
            return -1;
        }
        switch (scope) {
            case E1_SCOPE_WIFI:
                scopes->wifi = value;
                break;
            case E1_SCOPE_BLE:
                scopes->ble = value;
                break;
            case E1_SCOPE_RF:
                scopes->rf = value;
                break;
            case E1_SCOPE_SECOND_CAMERA:
                scopes->second_camera = value;
                break;
            default:
                return -1;
        }

        skip_whitespace(&cursor);
        if (*cursor == '}') {
            cursor++;
            break;
        }
        if (*cursor++ != ',') {
            return -1;
        }
    }

    skip_whitespace(&cursor);
    return *cursor == '\0' && seen == E1_SCOPE_ALL ? 0 : -1;
}

int e1_consent_record_json(const char *session_id, const char *request_json,
                           e1_consent_scopes_t *out_scopes)
{
    e1_consent_scopes_t scopes;
    char payload[MAX_PAYLOAD_LEN];
    int written;

    if (!session_id || !session_id[0] ||
        strlen(session_id) >= EVENT_SESSION_ID_LEN ||
        !out_scopes || parse_consent(request_json, session_id, &scopes) != 0) {
        return -1;
    }

    written = snprintf(payload, sizeof(payload),
                       "{\"schema_version\":1,\"disclosure\":\"E1_SOURCE_SCOPE_V1\","
                       "\"wifi\":%s,\"ble\":%s,\"rf\":%s,\"second_camera\":%s,"
                       "\"collection_status\":\"DISABLED_BY_POLICY\"}",
                       scopes.wifi ? "true" : "false",
                       scopes.ble ? "true" : "false",
                       scopes.rf ? "true" : "false",
                       scopes.second_camera ? "true" : "false");
    if (written < 0 || (size_t)written >= sizeof(payload)) {
        return -1;
    }

    if (event_chain_append(session_id, "CANDIDATE", "E1_CONSENT_RECORDED",
                           payload, "examos-e1-consent",
                           "1", NULL) != 0) {
        return -2;
    }

    *out_scopes = scopes;
    return 0;
}
