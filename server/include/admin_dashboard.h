#ifndef EXAMOS_ADMIN_DASHBOARD_H
#define EXAMOS_ADMIN_DASHBOARD_H

#include <stddef.h>
#include <stdint.h>

/* Returns static HTML string for the admin dashboard login page. */
const char *admin_login_html(void);

/* Returns dynamic HTML string for the admin dashboard main page. */
const char *admin_dashboard_html(const char *current_url, const char *current_name, int duration_minutes);

/* Returns 1 for a valid PostgreSQL-backed Bearer session; local Basic auth is development-only. */
int admin_check_auth(const char *auth_header);
int admin_check_permission(const char *auth_header, uint32_t permission);

#endif
