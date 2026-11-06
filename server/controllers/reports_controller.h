#ifndef EXAMOS_REPORTS_CONTROLLER_H
#define EXAMOS_REPORTS_CONTROLLER_H

#include <stddef.h>

/*
 * Dedicated, server-enforced reporting API.
 *
 * Routes (all require an authenticated admin bearer/cookie session):
 *   GET  /api/v1/reports/catalog
 *   GET  /api/v1/reports/hub
 *   GET  /api/v1/reports/exams
 *   GET  /api/v1/reports/devices
 *   GET  /api/v1/reports/security
 *   GET  /api/v1/reports/business
 *   GET  /api/v1/reports/history
 *   POST /api/v1/reports/export
 *
 * Tenant scope is resolved from the authenticated session. A platform owner
 * may request a specific tenant or a global aggregate; every other role is
 * pinned to its own institution regardless of query/body input.
 */
void reports_handle(int client_fd, const char *method, const char *path,
                    const char *body, const char *auth_header,
                    const char *origin, char *extra_headers, size_t extra_len);

#endif /* EXAMOS_REPORTS_CONTROLLER_H */
