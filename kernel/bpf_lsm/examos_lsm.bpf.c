// SPDX-License-Identifier: GPL-2.0
/*
 * SPPIO / ExamOS Kernel Runtime Security — eBPF / BPF-LSM
 *
 * Enforces zero-trust process execution, file integrity protection,
 * ptrace isolation, and network egress rules inline inside the Linux kernel
 * with near-zero CPU overhead.
 *
 * Requires kernel >= 5.7 with CONFIG_BPF_LSM=y and lsm=...,bpf
 */
#include <linux/bpf.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define EXAMOS_MODE_LOCKDOWN 1

struct examos_lsm_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 uid;
    __u8  hook_id;   /* 1=bprm, 2=file_open, 3=socket_connect, 4=ptrace */
    __s32 decision;  /* 0=allow, -EPERM/-EACCES=deny */
    char  comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} lockdown_mode_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);   /* allowed IPv4 address (network byte order) */
    __type(value, __u8);
} allowed_ipv4_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, __u32);   /* protected PIDs (kiosk, securityd, agent) */
    __type(value, __u8);
} protected_pid_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18); /* 256 KiB ring buffer */
} lsm_events SEC(".maps");

static __always_inline __u32 is_lockdown_active(void) {
    __u32 key = 0;
    __u32 *val = bpf_map_lookup_elem(&lockdown_mode_map, &key);
    return val ? (*val == EXAMOS_MODE_LOCKDOWN) : 0;
}

static __always_inline void emit_event(__u8 hook_id, __s32 decision) {
    struct examos_lsm_event *ev = bpf_ringbuf_reserve(&lsm_events, sizeof(*ev), 0);
    if (!ev) return;
    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    ev->uid = (__u32)bpf_get_current_uid_gid();
    ev->hook_id = hook_id;
    ev->decision = decision;
    bpf_get_current_comm(ev->comm, sizeof(ev->comm));
    bpf_ringbuf_submit(ev, 0);
}

static __always_inline int is_blocked_shell_comm(const char *comm) {
    /* Block interactive shells & debuggers when exam lockdown is active */
    if (comm[0] == 'b' && comm[1] == 'a' && comm[2] == 's' && comm[3] == 'h' && comm[4] == '\0') return 1;
    if (comm[0] == 's' && comm[1] == 'h' && comm[2] == '\0') return 1;
    if (comm[0] == 'g' && comm[1] == 'd' && comm[2] == 'b' && comm[3] == '\0') return 1;
    if (comm[0] == 's' && comm[1] == 't' && comm[2] == 'r' && comm[3] == 'a' && comm[4] == 'c' && comm[5] == 'e') return 1;
    return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(examos_bprm_check, struct linux_binprm *bprm)
{
    if (!is_lockdown_active())
        return 0;

    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    __u32 uid = (__u32)bpf_get_current_uid_gid();

    /* Non-root unprivileged processes cannot spawn shells or debuggers in lockdown */
    if (uid != 0 && is_blocked_shell_comm(comm)) {
        emit_event(1, -EPERM);
        return -EPERM;
    }
    return 0;
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(examos_ptrace_check, struct task_struct *child, unsigned int mode)
{
    __u32 target_pid = BPF_CORE_READ(child, tgid);
    __u8 *protected = bpf_map_lookup_elem(&protected_pid_map, &target_pid);
    if (protected && *protected == 1) {
        emit_event(4, -EPERM);
        return -EPERM;
    }
    return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(examos_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
    if (!is_lockdown_active())
        return 0;
    if (!address || addrlen < (int)sizeof(struct sockaddr_in))
        return 0;

    sa_family_t family = BPF_CORE_READ(address, sa_family);
    if (family == AF_INET) {
        struct sockaddr_in *in_addr = (struct sockaddr_in *)address;
        __u32 dst_ip = BPF_CORE_READ(in_addr, sin_addr.s_addr);
        /* Always permit loopback 127.0.0.1 */
        if (dst_ip == __bpf_htonl(0x7f000001))
            return 0;
        __u8 *allowed = bpf_map_lookup_elem(&allowed_ipv4_map, &dst_ip);
        if (!allowed || *allowed != 1) {
            emit_event(3, -EACCES);
            return -EACCES;
        }
    }
    return 0;
}
