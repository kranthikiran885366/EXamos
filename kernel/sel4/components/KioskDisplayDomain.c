#include <camkes.h>
#include <stdint.h>
#include <string.h>

int run(void) {
    volatile uint32_t *telemetry = (volatile uint32_t *)telemetry_out;
    while (1) {
        /* Monitor shared framebuffer boundary for unauthorized overlay flags */
        const volatile uint32_t *fb = (const volatile uint32_t *)framebuffer_port;
        if (fb[0] == 0xBAD0BEEFu) {
            telemetry[0] = 0xDEAD0001u;
        }
        seL4_Yield();
    }
    return 0;
}
