#ifndef SECURITY_ASSURANCE_CONTROLLER_H
#define SECURITY_ASSURANCE_CONTROLLER_H

#include <stddef.h>

void security_assurance_handle(int client_fd, const char *method, const char *path,
                               const char *body, const char *auth_header,
                               const char *origin, char *extra_headers,
                               size_t extra_len);

#endif /* SECURITY_ASSURANCE_CONTROLLER_H */
