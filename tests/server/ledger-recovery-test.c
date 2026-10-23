#define _GNU_SOURCE
#include "../../server/include/ledger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <openssl/sha.h>

/*
 * Regression coverage for the authenticated (HMAC-SHA256) evidence ledger.
 *
 * The properties under test:
 *   1. The ledger refuses to open without an authentication key.
 *   2. A correct key restores the verified sequence across a restart.
 *   3. A forged chain (an attacker recomputing the legacy plain SHA-256
 *      block digest) is rejected. This is the property the old bare-hash
 *      chain could not provide.
 *   4. A truncated ledger is rejected even though every surviving block is
 *      individually authentic.
 *   5. A different key cannot open an existing ledger.
 *
 * Each tamper scenario runs against its own copy of a known-good ledger so
 * that one scenario cannot mask another.
 */

#define TEST_KEY  "ledger-test-key-0123456789abcdefghijklmnop"
#define OTHER_KEY "ledger-other-key-0123456789abcdefghijklmn"

static int fail(const char *message, const char *path)
{
    fprintf(stderr, "FAIL: %s\n", message);
    if (path) unlink(path);
    return 1;
}

/* Recompute the legacy plain SHA-256 block digest for a rewritten block. */
static void legacy_sha256_digest(const char *payload, char out[65])
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)payload, strlen(payload), hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(out + (i * 2), "%02x", hash[i]);
    out[64] = '\0';
}

/* Copy a file byte-for-byte. */
static int copy_file(const char *from, const char *to)
{
    FILE *in = fopen(from, "rb");
    if (!in) return -1;
    FILE *out = fopen(to, "wb");
    if (!out) { fclose(in); return -1; }
    char buf[4096];
    size_t n;
    int rc = 0;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) { rc = -1; break; }
    }
    if (ferror(in)) rc = -1;
    if (fclose(in) != 0) rc = -1;
    if (fclose(out) != 0) rc = -1;
    return rc;
}

/* Copy a ledger together with its truncation anchor. */
static int copy_ledger(const char *from, const char *to)
{
    char anchor_from[600], anchor_to[600];
    if (copy_file(from, to) != 0) return -1;
    snprintf(anchor_from, sizeof(anchor_from), "%s.anchor", from);
    snprintf(anchor_to, sizeof(anchor_to), "%s.anchor", to);
    return copy_file(anchor_from, anchor_to);
}

/* Rewrite block 2 with different details, re-hashed the legacy way. */
static int forge_second_block(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char header[256];
    if (!fgets(header, sizeof(header), f)) { fclose(f); return -1; }

    char block1[1024], block2[1024];
    if (!fgets(block1, sizeof(block1), f) || !fgets(block2, sizeof(block2), f)) {
        fclose(f);
        return -1;
    }
    fclose(f);

    long idx = 0, ts = 0;
    char type[32] = {0}, dev[64] = {0}, details[256] = {0};
    char prev[65] = {0}, mac[65] = {0};
    if (sscanf(block2, "%ld|%ld|%31[^|]|%63[^|]|%255[^|]|%64[^|]|%64s",
               &idx, &ts, type, dev, details, prev, mac) != 7) {
        return -1;
    }

    char forged_details[256];
    snprintf(forged_details, sizeof(forged_details), "forged-%s", details);
    char payload[1024];
    snprintf(payload, sizeof(payload), "%ld:%ld:%s:%s:%s:%s",
             idx, ts, type, dev, forged_details, prev);
    char digest[65];
    legacy_sha256_digest(payload, digest);

    FILE *out = fopen(path, "w");
    if (!out) return -1;
    fputs(header, out);
    fputs(block1, out);
    fprintf(out, "%ld|%ld|%s|%s|%s|%s|%s\n", idx, ts, type, dev,
            forged_details, prev, digest);
    if (fclose(out) != 0) return -1;
    return 0;
}

/* Keep only the header and the first block. */
static int truncate_to_one_block(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char header[256], block1[1024];
    if (!fgets(header, sizeof(header), f) || !fgets(block1, sizeof(block1), f)) {
        fclose(f);
        return -1;
    }
    fclose(f);
    FILE *out = fopen(path, "w");
    if (!out) return -1;
    fputs(header, out);
    fputs(block1, out);
    if (fclose(out) != 0) return -1;
    return 0;
}

static void cleanup(const char *dir, const char *const *paths, size_t count)
{
    char anchor[600];
    for (size_t i = 0; i < count; i++) {
        unlink(paths[i]);
        snprintf(anchor, sizeof(anchor), "%s.anchor", paths[i]);
        unlink(anchor);
    }
    rmdir(dir);
}

int main(void)
{
    char dir[] = "/tmp/examos-ledger-test-XXXXXX";
    if (!mkdtemp(dir)) return 1;

    char good[512], forged[512], truncated[512], wrongkey[512];
    snprintf(good, sizeof(good), "%s/events.log", dir);
    snprintf(forged, sizeof(forged), "%s/forged.log", dir);
    snprintf(truncated, sizeof(truncated), "%s/truncated.log", dir);
    snprintf(wrongkey, sizeof(wrongkey), "%s/wrongkey.log", dir);

    const char *all_paths[] = { good, forged, truncated, wrongkey };

    /* 1. No authentication key -> the ledger must refuse to open. */
    if (ledger_init(good, NULL) == 0)
        return fail("ledger opened without an authentication key", good);
    if (ledger_init(good, "too-short") == 0)
        return fail("ledger opened with an undersized authentication key", good);

    /* 2. Correct key -> append, restart, and the sequence is restored. */
    if (ledger_init(good, TEST_KEY) != 0)
        return fail("ledger did not open with a valid authentication key", good);
    if (ledger_get_block_count() != 0 || !ledger_is_authenticated())
        return fail("fresh ledger was not empty or not marked authenticated", good);
    if (ledger_append_event("START", "device-a", "first", NULL) != 0 ||
        ledger_append_event("EVENT", "device-a", "second", NULL) != 0 ||
        ledger_append_event("EVENT", "device-b", "third", NULL) != 0)
        return fail("ledger append failed", good);
    if (ledger_verify_integrity() != 1)
        return fail("freshly written ledger did not verify", good);
    if (ledger_init(good, TEST_KEY) != 0)
        return fail("ledger did not reopen after restart", good);
    if (ledger_get_block_count() != 3)
        return fail("ledger did not recover its block count after restart", good);
    if (ledger_verify_integrity() != 1)
        return fail("recovered ledger did not verify", good);
    if (ledger_append_event("EVENT", "device-a", "after-restart", NULL) != 0 ||
        ledger_get_block_count() != 4 || ledger_verify_integrity() != 1)
        return fail("ledger did not accept a post-restart append", good);

    /* Build the scenario copies from the known-good ledger. */
    if (copy_ledger(good, forged) != 0 ||
        copy_ledger(good, truncated) != 0 ||
        copy_ledger(good, wrongkey) != 0)
        return fail("could not stage the tamper scenarios", good);

    /* 3. A different key must not open an existing ledger. */
    if (ledger_init(wrongkey, OTHER_KEY) == 0)
        return fail("ledger opened with the wrong authentication key", wrongkey);

    /* 4. A forged chain (legacy plain-SHA256 re-hash) must be rejected. */
    if (forge_second_block(forged) != 0)
        return fail("could not construct the forged chain fixture", forged);
    if (ledger_init(forged, TEST_KEY) == 0)
        return fail("forged chain was accepted", forged);

    /* 5. Truncation must be detected by the committed anchor. */
    if (truncate_to_one_block(truncated) != 0)
        return fail("could not construct the truncated ledger fixture", truncated);
    if (ledger_init(truncated, TEST_KEY) == 0)
        return fail("truncated ledger was accepted", truncated);

    cleanup(dir, all_paths, sizeof(all_paths) / sizeof(all_paths[0]));

    puts("PASS: ledger authenticates blocks, recovers after restart, and rejects forged and truncated chains");
    return 0;
}
