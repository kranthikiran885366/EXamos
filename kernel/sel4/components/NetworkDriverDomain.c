#include <camkes.h>
#include <string.h>

int run(void) {
    while (1) {
        /* Only forward attested frames from TrustedAttestationDomain */
        seL4_Yield();
    }
    return 0;
}
