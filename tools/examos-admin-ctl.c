#define _GNU_SOURCE
#include "../server/include/admin_auth_store.h"
#include "../server/include/config_manager.h"
#include "../server/include/enterprise_platform.h"
#include "../server/include/totp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

static int hash_password(const char *password, char *out_hash, size_t out_max) {
    if (!password || strlen(password) < 12) return -1;

    unsigned char salt[16];
    unsigned char hash[32];
    if (RAND_bytes(salt, sizeof(salt)) != 1 ||
        PKCS5_PBKDF2_HMAC(password, (int)strlen(password), salt, sizeof(salt),
                          600000, EVP_sha256(), sizeof(hash), hash) != 1) {
        return -1;
    }

    char salt_hex[33], hash_hex[65];
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < 16; ++i) {
        salt_hex[i * 2]     = digits[salt[i] >> 4];
        salt_hex[i * 2 + 1] = digits[salt[i] & 0x0f];
    }
    salt_hex[32] = '\0';
    for (size_t i = 0; i < 32; ++i) {
        hash_hex[i * 2]     = digits[hash[i] >> 4];
        hash_hex[i * 2 + 1] = digits[hash[i] & 0x0f];
    }
    hash_hex[64] = '\0';

    snprintf(out_hash, out_max, "600000:%s:%s", salt_hex, hash_hex);
    OPENSSL_cleanse(salt, sizeof(salt));
    OPENSSL_cleanse(hash, sizeof(hash));
    return 0;
}

static void print_usage(const char *prog) {
    printf("ExamOS Enterprise Administrator Management CLI\n\n"
           "Usage:\n"
           "  %s create-owner <username> <password> <full_name> <email>\n"
           "  %s create-user <actor_id> <username> <password> <role_1_to_9> <full_name> <email> [institution_id]\n"
           "  %s enroll-mfa <username>\n"
           "  %s confirm-mfa <username> <totp_code>\n"
           "  %s reset-password <username> <new_password>\n"
           "  %s list-users\n\n"
           "Roles:\n"
           "  1 = PLATFORM_OWNER\n"
           "  2 = INSTITUTION_ADMIN\n"
           "  3 = EXAM_MANAGER\n"
           "  4 = SECURITY_ADMIN\n"
           "  5 = INVIGILATOR\n"
           "  6 = TECH_OPERATOR\n"
           "  7 = INCIDENT_INVESTIGATOR\n"
           "  8 = READONLY_AUDITOR\n"
           "  9 = SUPPORT_ENGINEER\n",
           prog, prog, prog, prog, prog, prog);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (admin_auth_store_init() != 0) {
        fprintf(stderr, "Error: Failed to connect to ExamOS database. Ensure EXAMOS_DATABASE_URL_FILE is set or /etc/examos/secrets/db_url exists.\n");
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "create-owner") == 0) {
        if (argc < 6) {
            fprintf(stderr, "Usage: %s create-owner <username> <password> <full_name> <email>\n", argv[0]);
            admin_auth_store_shutdown();
            return 1;
        }
        user_account_t user;
        memset(&user, 0, sizeof(user));
        snprintf(user.user_id, sizeof(user.user_id), "USR-OWNER-001");
        snprintf(user.username, sizeof(user.username), "%s", argv[2]);
        snprintf(user.full_name, sizeof(user.full_name), "%s", argv[4]);
        snprintf(user.email, sizeof(user.email), "%s", argv[5]);
        user.role = ROLE_PLATFORM_OWNER;
        user.active = 1;

        if (hash_password(argv[3], user.password_hash, sizeof(user.password_hash)) != 0) {
            fprintf(stderr, "Error: Password must be at least 12 characters.\n");
            admin_auth_store_shutdown();
            return 1;
        }

        if (admin_auth_store_create_initial_owner(&user) == 0) {
            printf("SUCCESS: Initial Platform Owner created: %s (ID: %s)\n", user.username, user.user_id);
        } else {
            fprintf(stderr, "Error: Failed to create platform owner. Ensure database is clean or owner does not already exist.\n");
            admin_auth_store_shutdown();
            return 1;
        }
    }
    else if (strcmp(cmd, "create-user") == 0) {
        if (argc < 8) {
            fprintf(stderr, "Usage: %s create-user <actor_id> <username> <password> <role> <full_name> <email> [institution_id]\n", argv[0]);
            admin_auth_store_shutdown();
            return 1;
        }
        user_account_t user;
        memset(&user, 0, sizeof(user));
        snprintf(user.user_id, sizeof(user.user_id), "USR-%u", (unsigned int)time(NULL));
        snprintf(user.username, sizeof(user.username), "%s", argv[3]);
        user.role = (user_role_t)atoi(argv[5]);
        snprintf(user.full_name, sizeof(user.full_name), "%s", argv[6]);
        snprintf(user.email, sizeof(user.email), "%s", argv[7]);
        if (argc >= 9) snprintf(user.institution_id, sizeof(user.institution_id), "%s", argv[8]);
        user.active = 1;

        if (hash_password(argv[4], user.password_hash, sizeof(user.password_hash)) != 0) {
            fprintf(stderr, "Error: Password must be at least 12 characters.\n");
            admin_auth_store_shutdown();
            return 1;
        }

        if (admin_auth_store_create_user(&user, argv[2]) == 0) {
            printf("SUCCESS: Administrator account created: %s (Role: %s, ID: %s)\n",
                   user.username, admin_role_to_string(user.role), user.user_id);
        } else {
            fprintf(stderr, "Error: Failed to create user. Verify actor permissions (must be Owner or Institution Admin) and username uniqueness.\n");
            admin_auth_store_shutdown();
            return 1;
        }
    }
    else if (strcmp(cmd, "enroll-mfa") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s enroll-mfa <username>\n", argv[0]);
            admin_auth_store_shutdown();
            return 1;
        }
        char secret[TOTP_BASE32_LEN + 1] = {0};
        char uri[512] = {0};
        char codes[TOTP_NUM_RECOVERY_CODES][TOTP_RECOVERY_CODE_LEN + 1];

        if (admin_auth_store_mfa_enroll(argv[2], secret, uri, sizeof(uri), codes) == 0) {
            printf("\n=== TOTP MFA ENROLLMENT FOR: %s ===\n", argv[2]);
            printf("Secret Key (Base32): %s\n", secret);
            printf("Provisioning URI:   %s\n\n", uri);
            printf("EMERGENCY SINGLE-USE RECOVERY CODES:\n");
            for (int i = 0; i < TOTP_NUM_RECOVERY_CODES; ++i) {
                printf("  [%d] %s\n", i + 1, codes[i]);
            }
            printf("\nTo complete activation, confirm with: %s confirm-mfa %s <6-digit-code>\n", argv[0], argv[2]);
        } else {
            fprintf(stderr, "Error: Failed to enroll MFA. Verify user exists.\n");
            admin_auth_store_shutdown();
            return 1;
        }
    }
    else if (strcmp(cmd, "confirm-mfa") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: %s confirm-mfa <username> <code>\n", argv[0]);
            admin_auth_store_shutdown();
            return 1;
        }
        if (admin_auth_store_mfa_confirm(argv[2], argv[3]) == 0) {
            printf("SUCCESS: TOTP MFA successfully activated for %s.\n", argv[2]);
        } else {
            fprintf(stderr, "Error: Invalid confirmation code. MFA activation failed.\n");
            admin_auth_store_shutdown();
            return 1;
        }
    }
    else if (strcmp(cmd, "reset-password") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: %s reset-password <username> <new_password>\n", argv[0]);
            admin_auth_store_shutdown();
            return 1;
        }
        char token[65];
        if (admin_auth_store_password_reset_request(argv[2], token) != 0) {
            fprintf(stderr, "Error: Failed to initiate password reset. User not found.\n");
            admin_auth_store_shutdown();
            return 1;
        }
        if (admin_auth_store_password_reset_complete(argv[2], token, argv[3]) == 0) {
            printf("SUCCESS: Password reset successfully for %s. All existing sessions invalidated.\n", argv[2]);
        } else {
            fprintf(stderr, "Error: Password reset failed. Ensure password is >= 12 characters.\n");
            admin_auth_store_shutdown();
            return 1;
        }
    }
    else if (strcmp(cmd, "list-users") == 0) {
        char json[16384];
        if (admin_auth_store_list_users_json(json, sizeof(json)) == 0) {
            printf("%s\n", json);
        } else {
            fprintf(stderr, "Error: Failed to list users.\n");
            admin_auth_store_shutdown();
            return 1;
        }
    }
    else {
        print_usage(argv[0]);
        admin_auth_store_shutdown();
        return 1;
    }

    admin_auth_store_shutdown();
    return 0;
}
