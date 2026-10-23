#define _GNU_SOURCE
#include "../include/admin_auth_store.h"
#include "../include/config_manager.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

static void to_hex(const unsigned char *bytes, size_t length, char *hex) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < length; ++i) {
        hex[i * 2] = digits[bytes[i] >> 4];
        hex[i * 2 + 1] = digits[bytes[i] & 0x0f];
    }
    hex[length * 2] = '\0';
}

static int read_password(const char *prompt, char output[257]) {
    struct termios original, hidden;
    if (!isatty(STDIN_FILENO) || tcgetattr(STDIN_FILENO, &original) != 0)
        return -1;
    hidden = original;
    hidden.c_lflag &= (tcflag_t)~ECHO;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) != 0) return -1;
    fputs(prompt, stderr);
    fflush(stderr);
    char *read_result = fgets(output, 257, stdin);
    int restore_result = tcsetattr(STDIN_FILENO, TCSAFLUSH, &original);
    fputc('\n', stderr);
    if (!read_result || restore_result != 0) return -1;
    size_t length = strcspn(output, "\r\n");
    if (length == 256) {
        int next = fgetc(stdin);
        if (next != EOF && next != '\n') return -1;
    }
    output[length] = '\0';
    return length >= 12 && length <= 256 ? 0 : -1;
}

/*
 * Reads the initial password from a file for unattended provisioning.
 *
 * The file must be a regular file owned by the invoking user with no
 * group or world permissions, exactly like the database URL file used by
 * the rest of the platform. The file holds a single line, which is the
 * password itself.
 */
static int read_password_file(const char *path, char output[257]) {
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & 0077) != 0 || st.st_size <= 0 || st.st_size >= 257) {
        fprintf(stderr, "Password file is missing, not a regular file, not owned by this user, or too permissive.\n");
        return -1;
    }
    FILE *file = fopen(path, "r");
    if (!file) return -1;
    if (!fgets(output, 257, file)) { fclose(file); return -1; }
    if (fclose(file) != 0) return -1;
    size_t length = strcspn(output, "\r\n");
    output[length] = '\0';
    return length >= 12 && length <= 256 ? 0 : -1;
}

int main(int argc, char **argv) {
    user_account_t user = {0};
    if (argc < 2 || argc > 4 ||
        strnlen(argv[1], sizeof(user.username)) >= sizeof(user.username)) {
        fprintf(stderr, "Usage: admin-provision USERNAME [FULL_NAME] [EMAIL]\n");
        return 2;
    }
    char first_password[257] = {0};
    char second_password[257] = {0};
    unsigned char id_bytes[16] = {0};
    char id_hex[33] = {0};
    snprintf(user.username, sizeof(user.username), "%s", argv[1]);
    if (argc > 2) snprintf(user.full_name, sizeof(user.full_name), "%s", argv[2]);
    if (argc > 3) snprintf(user.email, sizeof(user.email), "%s", argv[3]);
    user.role = ROLE_PLATFORM_OWNER;
    user.active = 1;

    const char *password_file = getenv("EXAMOS_ADMIN_PROVISION_PASSWORD_FILE");
    if (password_file && password_file[0]) {
        /* Unattended provisioning: the password is supplied by a protected
           file rather than an interactive terminal. */
        if (read_password_file(password_file, first_password) != 0) {
            fprintf(stderr, "Password file input failed.\n");
            goto failure;
        }
        memcpy(second_password, first_password, strlen(first_password) + 1);
    } else if (read_password("New password: ", first_password) != 0 ||
               read_password("Confirm password: ", second_password) != 0 ||
               strlen(first_password) != strlen(second_password) ||
               CRYPTO_memcmp(first_password, second_password, strlen(first_password)) != 0) {
        fprintf(stderr, "Password input or confirmation failed.\n");
        goto failure;
    }
    if (RAND_bytes(id_bytes, sizeof(id_bytes)) != 1) {
        fprintf(stderr, "Cryptographic user identifier generation failed.\n");
        goto failure;
    }
    to_hex(id_bytes, sizeof(id_bytes), id_hex);
    snprintf(user.user_id, sizeof(user.user_id), "owner-%s", id_hex);
    if (config_create_password_hash(first_password, user.password_hash,
                                    sizeof(user.password_hash)) != 0) {
        fprintf(stderr, "Password hash generation failed.\n");
        goto failure;
    }
    if (admin_auth_store_init() != 0) {
        fprintf(stderr, "Verified PostgreSQL authentication storage is unavailable.\n");
        goto failure;
    }
    if (admin_auth_store_create_initial_owner(&user) != 0) {
        fprintf(stderr, "Initial owner creation failed; the database may already contain an administrator.\n");
        admin_auth_store_shutdown();
        goto failure;
    }
    admin_auth_store_shutdown();
    fprintf(stderr, "Initial platform owner created. Configure and enroll required MFA before operational use.\n");
    OPENSSL_cleanse(&user, sizeof(user));
    OPENSSL_cleanse(first_password, sizeof(first_password));
    OPENSSL_cleanse(second_password, sizeof(second_password));
    OPENSSL_cleanse(id_bytes, sizeof(id_bytes));
    OPENSSL_cleanse(id_hex, sizeof(id_hex));
    return 0;

failure:
    admin_auth_store_shutdown();
    OPENSSL_cleanse(&user, sizeof(user));
    OPENSSL_cleanse(first_password, sizeof(first_password));
    OPENSSL_cleanse(second_password, sizeof(second_password));
    OPENSSL_cleanse(id_bytes, sizeof(id_bytes));
    OPENSSL_cleanse(id_hex, sizeof(id_hex));
    return 1;
}
