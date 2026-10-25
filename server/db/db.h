#ifndef EXAMOS_DB_H
#define EXAMOS_DB_H

#include <libpq-fe.h>
#include <stddef.h>
#include <time.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * Database connection pool
 * ========================================================================= */
#define EXAMOS_DB_MAX_CONNECTIONS 32

typedef struct {
    PGconn *conn;
    int in_use;
    time_t checked_out_at;
} db_connection_t;

typedef struct {
    db_connection_t conns[EXAMOS_DB_MAX_CONNECTIONS];
    int count;
    pthread_mutex_t lock;
} db_pool_t;

extern db_pool_t g_db_pool;

/* Initialize the connection pool from EXAMOS_DATABASE_URL.
 * Returns 0 on success, -1 on failure. */
int db_init(const char *conninfo);

/* Shut down the pool, closing all connections. */
void db_shutdown(void);

/* Acquire a connection from the pool. Blocks until one is available. */
PGconn *db_acquire(void);

/* Release a connection back to the pool. If broken != 0, the connection
 * is closed and a new one will be created on next acquire. */
void db_release(PGconn *conn, int broken);

/* Execute a query and return the result (caller must PQclear). */
PGresult *db_exec(PGconn *conn, const char *sql, int n_params, const char **params,
                  const int *param_lengths, const int *param_formats, int result_format);

/* One-shot helper: execute a SELECT-style query and return PGresult. */
PGresult *db_query(const char *sql, int n_params, const char **params);

/* Simplified PQexecParams wrapper (paramTypes = NULL, formats = 0). */
PGresult *db_simple(PGconn *conn, const char *sql,
                    int n_params, const char **params, const int *lens);

/* =========================================================================
 * Schema initialization
 * ========================================================================= */

/* Create all tables if they don't exist. Returns 0 on success. */
int db_create_schema(void);

/* Run a migration file by path. Returns 0 on success. */
int db_run_migration_file(const char *path);

/* =========================================================================
 * Health check
 * ========================================================================= */
/* Returns 0 if the database is healthy. */
int db_health(void);

#ifdef __cplusplus
}
#endif

#endif /* EXAMOS_DB_H */
