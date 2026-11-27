#ifndef EXAMOS_ANTI_VM_H
#define EXAMOS_ANTI_VM_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int vm_detected;
    int cpuid_hypervisor_bit;
    int acpi_dmi_match;
    int rdtsc_anomaly;
    char hypervisor_vendor[32];
    char dmi_vendor[128];
    unsigned long long rdtsc_median_cycles;
} examos_anti_vm_report_t;

/*
 * Performs multi-signal hypervisor / VM detection:
 *   1. CPUID leaf 0x1 ECX bit 31 + leaf 0x40000000 vendor signature
 *   2. DMI / ACPI sysfs vendor strings (/sys/class/dmi/id/*)
 *   3. Serialized RDTSC instruction timing variance across CPUID exits
 *
 * Returns 0 on bare-metal physical hardware, 1 if a hypervisor/VM is detected,
 * or -1 on invalid arguments.
 */
int examos_anti_vm_check(examos_anti_vm_report_t *out);

#ifdef __cplusplus
}
#endif

#endif /* EXAMOS_ANTI_VM_H */
