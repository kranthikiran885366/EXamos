#include <camkes.h>
#include <string.h>

int run(void) {
    memset((void *)framebuffer_port, 0, 65536);
    memset((void *)net_port, 0, 4096);
    while (1) {
        seL4_Yield();
    }
    return 0;
}
