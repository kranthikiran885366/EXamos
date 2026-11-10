#include "../../server/include/config_manager.h"
#include "../../server/include/enterprise_platform.h"
#include <stdio.h>

typedef struct {
    const char *url;
    int expected;
} url_case_t;

int main(void) {
    static const url_case_t cases[] = {
        {"https://exam.alpha.edu/exam/start", 1},
        {"https://portal.beta.edu:8443/session", 1},
        {"https://sppio-os.vercel.app/candidate-login", 1},
        {"https://127.0.0.1/exam", 1},
        {"http://127.0.0.1:8000/exam", 1},
        {"http://localhost:8000/exam", 1},
        {"http://127.0.0.1/exam", 0},
        {"http://localhost/exam", 0},
        {"http://localhost:8001/exam", 0},
        {"http://127.0.0.1:8001/exam", 0},
        {"http://localhost.evil.test/exam", 0},
        {"http://127.0.0.10/exam", 0},
        {"http://exam.alpha.edu/exam", 0},
        {"https://user:secret@exam.alpha.edu/exam", 0},
        {"https://exam.alpha.edu:99999/exam", 0},
        {"https:///missing-host", 0},
        {"https://*.exam.alpha.edu/exam", 0},
        {"https://evil.sppio-os.vercel.app/candidate-login", 0},
        {"https://exam..alpha.edu/exam", 0},
        {"https://example.com/exam", 0},
        {"https://DEPLOYMENT_REQUIRED/exam", 0},
        {"NOT_CONFIGURED", 0},
        {"ftp://exam.alpha.edu/exam", 0},
        {NULL, 0}
    };

    for (size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        int actual = config_validate_exam_url(cases[index].url);
        if (actual != cases[index].expected) {
            fprintf(stderr, "FAIL: URL case %zu returned %d, expected %d\n",
                    index + 1, actual, cases[index].expected);
            return 1;
        }

        char error[160];
        int platform_actual = platform_validate_exam_url(cases[index].url,
                                                         error, sizeof(error)) == 0;
        if (platform_actual != cases[index].expected) {
            fprintf(stderr, "FAIL: platform URL case %zu returned %d, expected %d (%s)\n",
                    index + 1, platform_actual, cases[index].expected, error);
            return 1;
        }
    }

    if (!config_validate_exam_url("https://sppio-os.vercel.app/candidate-login")) {
        fprintf(stderr, "FAIL: configured candidate portal URL must be approved\n");
        return 1;
    }

    printf("PASS: %zu cases across both exam URL validators\n",
           sizeof(cases) / sizeof(cases[0]));
    return 0;
}