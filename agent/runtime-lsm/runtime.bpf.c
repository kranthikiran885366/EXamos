/* Narrow, deterministic kernel policy supplementing the existing AppArmor,
 * nftables and USBGuard rules. Global to a dedicated examination appliance;
 * never install this policy on a general-purpose workstation. */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct task_struct;
struct vm_area_struct;

SEC("lsm/ptrace_access_check")
int BPF_PROG(examos_deny_ptrace, struct task_struct *child,
             unsigned int mode, int ret) {
    (void)ctx; (void)child; (void)mode;
    return ret ? ret : -1; /* EPERM. Never override an earlier LSM's denial. */
}

SEC("lsm/file_mprotect")
int BPF_PROG(examos_deny_wx, struct vm_area_struct *vma,
             unsigned long reqprot, unsigned long prot, int ret) {
    (void)ctx; (void)vma; (void)reqprot;
    if (ret) return ret;
    return (prot & 6UL) == 6UL ? -1 : 0; /* PROT_WRITE | PROT_EXEC */
}

char LICENSE[] SEC("license") = "GPL";
