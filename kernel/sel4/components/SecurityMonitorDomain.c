#include <camkes.h>
#include <stdint.h>

int run(void) {
    const volatile uint32_t *telemetry = (const volatile uint32_t *)telemetry_in;
    while (1) {
        if (telemetry[0] == 0xDEAD0001u) {
            tamper_irq_emit();
        }
        seL4_Yield();
    }
    return 0;
}
