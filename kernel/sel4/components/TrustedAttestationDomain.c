#include <camkes.h>
#include <stdint.h>
#include <string.h>

static volatile uint8_t g_ephemeral_keys[96];

static void zeroize_volatile(volatile uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) buf[i] = 0;
}

int run(void) {
    memset((void *)g_ephemeral_keys, 0xA5, sizeof(g_ephemeral_keys));
    memset((void *)attestation_out, 0, 4096);
    while (1) {
        tamper_irq_wait();
        zeroize_volatile(g_ephemeral_keys, sizeof(g_ephemeral_keys));
        memset((void *)attestation_out, 0, 4096);
    }
    return 0;
}
