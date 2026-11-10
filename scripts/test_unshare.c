#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <errno.h>

int main() {
    if (unshare(CLONE_NEWUSER) == -1) {
        perror("unshare(CLONE_NEWUSER)");
        return 1;
    }
    printf("unshare SUCCESS\n");
    return 0;
}
