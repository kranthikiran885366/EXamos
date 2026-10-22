#define _GNU_SOURCE
#include "../../server/include/ledger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
    char path[] = "/tmp/examos-ledger-recovery-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) return 1;
    close(fd);

    if (ledger_init(path) != 0 || ledger_get_block_count() != 0 ||
        ledger_append_event("START", "device-a", "first", NULL) != 0 ||
        ledger_append_event("EVENT", "device-a", "second", NULL) != 0 ||
        ledger_init(path) != 0 || ledger_get_block_count() != 2 ||
        ledger_verify_integrity() != 1 ||
        ledger_append_event("EVENT", "device-a", "after-restart", NULL) != 0 ||
        ledger_get_block_count() != 3 || ledger_verify_integrity() != 1) {
        unlink(path);
        fputs("FAIL: ledger did not recover its verified sequence after restart\n", stderr);
        return 1;
    }

    FILE *file = fopen(path, "r+");
    if (!file) {
        unlink(path);
        fputs("FAIL: could not open ledger for corruption check\n", stderr);
        return 1;
    }
    int tamper_failed = fseek(file, 0, SEEK_SET) != 0 || fputc('X', file) == EOF;
    if (fclose(file) != 0) tamper_failed = 1;
    if (tamper_failed || ledger_init(path) == 0) {
        unlink(path);
        fputs("FAIL: corrupted ledger was accepted\n", stderr);
        return 1;
    }

    unlink(path);
    puts("PASS: ledger restart restores sequence/hash and rejects tampering");
    return 0;
}
