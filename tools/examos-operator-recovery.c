/*
 * Operator recovery: authenticated kiosk pause/resume.
 * Does not generate predictable keys, print secrets, or open a candidate shell.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>

#define OPERATOR_KEY_PATH "/etc/examos/operator_recovery.key"
#define BREAKOUT_TICKET_PATH "/run/examos/operator-breakout.ticket"
#define MIN_KEY_BYTES 32
#define TICKET_BYTES 32
#define TICKET_TTL_SEC 30

static int ct_equal(const unsigned char *a, const unsigned char *b, size_t n)
{
    unsigned char acc = 0;
    for (size_t i = 0; i < n; i++)
        acc |= (unsigned char)(a[i] ^ b[i]);
    return acc == 0;
}

static pid_t find_kiosk_launcher_pid(void)
{
    DIR *proc = opendir("/proc");
    if (!proc)
        return -1;
    struct dirent *entry;
    pid_t found_pid = -1;
    while ((entry = readdir(proc)) != NULL) {
        char *endptr = NULL;
        long pid = strtol(entry->d_name, &endptr, 10);
        if (endptr == entry->d_name || *endptr != '\0' || pid <= 1)
            continue;
        char cmdline_path[64];
        snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%ld/cmdline", pid);
        FILE *f = fopen(cmdline_path, "r");
        if (!f)
            continue;
        char cmd[256];
        size_t n = fread(cmd, 1, sizeof(cmd) - 1, f);
        fclose(f);
        cmd[n] = '\0';
        if (memmem(cmd, n + 1, "examos-kiosk-launcher", 21)) {
            found_pid = (pid_t)pid;
            break;
        }
    }
    closedir(proc);
    return found_pid;
}

static int read_key_file(unsigned char *out, size_t *out_len)
{
    FILE *f = fopen(OPERATOR_KEY_PATH, "r");
    if (!f)
        return -1;
    char line[256];
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return -1;
    }
    fclose(f);
    size_t n = strlen(line);
    while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
        line[--n] = '\0';
    if (n < MIN_KEY_BYTES)
        return -1;
    memcpy(out, line, n);
    *out_len = n;
    return 0;
}

static int write_ticket(void)
{
    if (mkdir("/run/examos", 0700) != 0 && errno != EEXIST)
        return -1;
    unsigned char ticket[TICKET_BYTES];
    int rfd = open("/dev/urandom", O_RDONLY);
    if (rfd < 0)
        return -1;
    ssize_t got = read(rfd, ticket, sizeof(ticket));
    close(rfd);
    if (got != (ssize_t)sizeof(ticket))
        return -1;
    int fd = open(BREAKOUT_TICKET_PATH, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0)
        return -1;
    ssize_t w = write(fd, ticket, sizeof(ticket));
    close(fd);
    explicit_bzero(ticket, sizeof(ticket));
    return w == (ssize_t)sizeof(ticket) ? 0 : -1;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "ExamOS operator recovery (no candidate shell)\n"
            "  %s provision-key     read 32+ byte secret from stdin; do not print it\n"
            "  %s trigger-breakout  read the same secret from stdin; pause kiosk\n"
            "  %s resume-kiosk      restart the kiosk after maintenance\n"
            "  %s check-status\n",
            argv0, argv0, argv0, argv0);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "generate-key") == 0) {
        fprintf(stderr, "Refused: generate-key is removed. Use provision-key with a custody secret on stdin.\n");
        return 2;
    }

    if (strcmp(argv[1], "provision-key") == 0) {
        char key[256];
        if (!fgets(key, sizeof(key), stdin)) {
            fprintf(stderr, "FAIL: could not read recovery secret from stdin.\n");
            return 1;
        }
        size_t n = strlen(key);
        while (n > 0 && (key[n - 1] == '\n' || key[n - 1] == '\r'))
            key[--n] = '\0';
        if (n < MIN_KEY_BYTES) {
            fprintf(stderr, "FAIL: recovery secret must be at least %d bytes.\n", MIN_KEY_BYTES);
            explicit_bzero(key, sizeof(key));
            return 1;
        }
        if (mkdir("/etc/examos", 0700) != 0 && errno != EEXIST) {
            perror("mkdir /etc/examos");
            return 1;
        }
        int fd = open(OPERATOR_KEY_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0) {
            perror("open operator key");
            return 1;
        }
        ssize_t w = write(fd, key, n);
        if (w != (ssize_t)n || write(fd, "\n", 1) != 1) {
            perror("write operator key");
            close(fd);
            return 1;
        }
        close(fd);
        explicit_bzero(key, sizeof(key));
        printf("Operator recovery secret stored at %s (value not printed).\n", OPERATOR_KEY_PATH);
        return 0;
    }

    if (strcmp(argv[1], "trigger-breakout") == 0) {
        char presented[256];
        if (!fgets(presented, sizeof(presented), stdin)) {
            fprintf(stderr, "FAIL: recovery secret must be supplied on stdin.\n");
            return 1;
        }
        size_t pn = strlen(presented);
        while (pn > 0 && (presented[pn - 1] == '\n' || presented[pn - 1] == '\r'))
            presented[--pn] = '\0';
        unsigned char stored[256];
        size_t sn = 0;
        if (read_key_file(stored, &sn) != 0) {
            fprintf(stderr, "FAIL: operator recovery secret is not provisioned.\n");
            explicit_bzero(presented, sizeof(presented));
            return 1;
        }
        size_t max = pn > sn ? pn : sn;
        unsigned char a[256] = {0};
        unsigned char b[256] = {0};
        memcpy(a, presented, pn);
        memcpy(b, stored, sn);
        int match = (pn == sn) && ct_equal(a, b, max == 0 ? 1 : max);
        explicit_bzero(presented, sizeof(presented));
        explicit_bzero(stored, sizeof(stored));
        explicit_bzero(a, sizeof(a));
        explicit_bzero(b, sizeof(b));
        if (!match) {
            fprintf(stderr, "AUTHENTICATION FAILURE\n");
            return 2;
        }
        unlink(BREAKOUT_TICKET_PATH);
        if (write_ticket() != 0) {
            fprintf(stderr, "FAIL: could not write one-shot breakout ticket.\n");
            return 1;
        }
        pid_t launcher_pid = find_kiosk_launcher_pid();
        if (launcher_pid <= 0) {
            fprintf(stderr, "Operator verified; kiosk supervisor is not running.\n");
            return 0;
        }
        if (kill(launcher_pid, SIGUSR1) != 0) {
            perror("signal kiosk supervisor");
            return 1;
        }
        printf("Breakout ticket issued; kiosk supervisor signaled (pid %d). Resume with resume-kiosk.\n",
               (int)launcher_pid);
        return 0;
    }

    if (strcmp(argv[1], "resume-kiosk") == 0) {
        unlink(BREAKOUT_TICKET_PATH);
        if (system("systemctl start examos-kiosk.service examos-kiosk-readiness.service") != 0) {
            fprintf(stderr, "FAIL: could not restart kiosk services.\n");
            return 1;
        }
        printf("Kiosk restart requested.\n");
        return 0;
    }

    if (strcmp(argv[1], "check-status") == 0) {
        pid_t launcher_pid = find_kiosk_launcher_pid();
        struct stat st;
        int ticket = (stat(BREAKOUT_TICKET_PATH, &st) == 0);
        printf("kiosk_supervisor=%s ticket=%s\n",
               launcher_pid > 0 ? "ACTIVE" : "INACTIVE",
               ticket ? "PRESENT" : "ABSENT");
        return launcher_pid > 0 ? 0 : 1;
    }

    usage(argv[0]);
    return 1;
}
