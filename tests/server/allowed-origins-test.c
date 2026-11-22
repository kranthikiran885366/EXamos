#include "../../server/include/enterprise_platform.h"
#include <assert.h>
#include <string.h>

static void expect_valid(const char *origins) {
    char error[256] = {0};
    assert(platform_validate_allowed_origins(origins, error, sizeof(error)) == 0);
}

static void expect_invalid(const char *origins) {
    char error[256] = {0};
    assert(platform_validate_allowed_origins(origins, error, sizeof(error)) != 0);
    assert(error[0] != '\0');
}

int main(void) {
    expect_valid("https://exam.example.edu");
    expect_valid("https://exam.example.edu/");
    expect_valid("https://exam.example.edu:8443, https://portal.example.edu");
    expect_valid("https://[2001:db8::1]:443");

    expect_invalid("http://exam.example.edu");
    expect_invalid("https://user:pass@example.edu");
    expect_invalid("https://exam.example.edu/path");
    expect_invalid("https://exam.example.edu?next=/");
    expect_invalid("https://exam.example.edu/#fragment");
    expect_invalid("https://*.example.edu");
    expect_invalid("https://");
    expect_invalid("https://exam.example.edu:65536");
    expect_invalid("https://bad_.example.edu");
    expect_invalid("https://999.999.999.999");
    expect_invalid("https://exam.example.edu,");
    expect_invalid("https://exam.example.edu,,https://portal.example.edu");
    return 0;
}
