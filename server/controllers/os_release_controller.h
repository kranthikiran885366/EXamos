#ifndef EXAMOS_OS_RELEASE_CONTROLLER_H
#define EXAMOS_OS_RELEASE_CONTROLLER_H

#include <stddef.h>

void os_release_handle(int client_fd, const char *method, const char *path,
                       const char *body, const char *auth_header,
                       const char *origin, char *extra_headers, size_t extra_len);

#endif /* EXAMOS_OS_RELEASE_CONTROLLER_H */
