#ifndef EXAMOS_STUDENT_CONTROLLER_H
#define EXAMOS_STUDENT_CONTROLLER_H

#include <stddef.h>

void student_handle(int client_fd, const char *method, const char *path,
                    const char *body, const char *auth_header,
                    const char *origin, char *extra_headers, size_t extra_len);

#endif /* EXAMOS_STUDENT_CONTROLLER_H */
