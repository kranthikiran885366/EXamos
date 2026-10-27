#include <stdio.h>
#include <string.h>
#include <errno.h>

int ledger_init(const char *ledger_file_path, const char *hmac_key);

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "./_logs/server_run/ledger.log";
    const char *key = "abcdef0123456789abcdef0123456789abcdef01";
    printf("Testing ledger_init with path=%s\n", path);
    int rc = ledger_init(path, key);
    printf("Result of ledger_init: %d (errno=%d: %s)\n", rc, errno, strerror(errno));
    return rc;
}
