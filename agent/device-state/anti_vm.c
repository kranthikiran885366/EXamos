#define _GNU_SOURCE
#include "../include/anti_vm.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#endif

static void read_sysfs_line(const char *path, char *out, size_t out_size) {
    if (!out || out_size == 0) return;
    out[0] = '\0';
    FILE *f = fopen(path, "r");
    if (!f) return;
    if (fgets(out, (int)out_size, f)) {
        size_t len = strlen(out);
        while (len > 0 && (out[len - 1] == '\n' || out[len - 1] == '\r' ||
                           isspace((unsigned char)out[len - 1]))) {
            out[--len] = '\0';
        }
    }
    fclose(f);
}

static int contains_ci(const char *haystack, const char *needle) {
    if (!haystack || !needle || !needle[0]) return 0;
    size_t hlen = strlen(haystack);
    size_t nlen = strlen(needle);
    if (nlen > hlen) return 0;
    for (size_t i = 0; i <= hlen - nlen; i++) {
        size_t j = 0;
        while (j < nlen &&
               tolower((unsigned char)haystack[i + j]) ==
               tolower((unsigned char)needle[j])) {
            j++;
        }
        if (j == nlen) return 1;
    }
    return 0;
}

static int check_dmi_acpi(char *out_vendor, size_t out_size) {
    static const char *const paths[] = {
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/bios_vendor",
        "/sys/class/dmi/id/board_vendor",
        "/sys/hypervisor/type"
    };
    static const char *const vm_markers[] = {
        "vmware", "virtualbox", "vbox", "qemu", "kvm", "xen",
        "bochs", "bhyve", "parallels", "innotek", "microsoft corporation virtual",
        "hyper-v", "amazon ec2", "google compute engine", "openstack", NULL
    };

    for (size_t p = 0; p < sizeof(paths) / sizeof(paths[0]); p++) {
        char buf[128] = {0};
        read_sysfs_line(paths[p], buf, sizeof(buf));
        if (!buf[0]) continue;
        if (p == 0 && out_vendor && out_size > 0) {
            snprintf(out_vendor, out_size, "%s", buf);
        }
        for (size_t m = 0; vm_markers[m] != NULL; m++) {
            if (contains_ci(buf, vm_markers[m])) {
                if (out_vendor && out_size > 0 && !out_vendor[0]) {
                    snprintf(out_vendor, out_size, "%s", buf);
                }
                return 1;
            }
        }
    }
    return 0;
}

#if defined(__x86_64__) || defined(__i386__)
static inline uint64_t rdtsc_serialized(void) {
    unsigned int lo = 0, hi = 0;
    __asm__ __volatile__(
        "lfence\n\t"
        "rdtsc\n\t"
        : "=a"(lo), "=d"(hi)
        :
        : "memory");
    return ((uint64_t)hi << 32) | lo;
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t va = *(const uint64_t *)a;
    uint64_t vb = *(const uint64_t *)b;
    return (va > vb) - (va < vb);
}

static void check_cpuid_and_rdtsc(examos_anti_vm_report_t *out) {
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        if (ecx & (1U << 31)) {
            out->cpuid_hypervisor_bit = 1;
        }
    }

    if (out->cpuid_hypervisor_bit) {
        __cpuid(0x40000000U, eax, ebx, ecx, edx);
        memcpy(out->hypervisor_vendor + 0, &ebx, 4);
        memcpy(out->hypervisor_vendor + 4, &ecx, 4);
        memcpy(out->hypervisor_vendor + 8, &edx, 4);
        out->hypervisor_vendor[12] = '\0';
    }

    /* Measure RDTSC delta across CPUID (forced VM-exit under hypervisors).
     * Bare-metal CPUID takes ~80-250 cycles; VM-exit typically > 1000 cycles. */
    enum { SAMPLES = 32 };
    uint64_t deltas[SAMPLES];
    for (int i = 0; i < SAMPLES; i++) {
        uint64_t t0 = rdtsc_serialized();
        __cpuid(0, eax, ebx, ecx, edx);
        uint64_t t1 = rdtsc_serialized();
        deltas[i] = (t1 > t0) ? (t1 - t0) : 0;
    }
    qsort(deltas, SAMPLES, sizeof(uint64_t), cmp_u64);
    uint64_t median = deltas[SAMPLES / 2];
    out->rdtsc_median_cycles = (unsigned long long)median;
    if (median > 1500ULL) {
        out->rdtsc_anomaly = 1;
    }
}
#else
static void check_cpuid_and_rdtsc(examos_anti_vm_report_t *out) {
    (void)out;
}
#endif

int examos_anti_vm_check(examos_anti_vm_report_t *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));

    check_cpuid_and_rdtsc(out);
    out->acpi_dmi_match = check_dmi_acpi(out->dmi_vendor, sizeof(out->dmi_vendor));

    out->vm_detected = (out->cpuid_hypervisor_bit || out->acpi_dmi_match ||
                        out->rdtsc_anomaly)
                           ? 1
                           : 0;
    return out->vm_detected;
}
