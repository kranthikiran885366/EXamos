// SPDX-License-Identifier: GPL-2.0
/*
 * SPPIO / ExamOS — Driver-Level eBPF XDP Packet & DNS-Tunneling Filter
 *
 * Enforces at the NIC driver layer (before sk_buff allocation / user space):
 *   1. Drops all plaintext DNS (UDP/TCP port 53) to prevent DNS tunneling.
 *   2. Enforces strict IPv4/IPv6 allowlists when policy mode is active.
 *   3. Permits only encrypted DNS-over-TLS (853) and HTTPS/DoH (443)
 *      to allowlisted exam & attestation endpoints.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define STAT_ALLOWED 0
#define STAT_DROPPED_DNS53 1
#define STAT_DROPPED_POLICY 2

struct ipv6_key {
    __u32 addr[4];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} xdp_policy_mode_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} xdp_allowed_ipv4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct ipv6_key);
    __type(value, __u8);
} xdp_allowed_ipv6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} xdp_stats_map SEC(".maps");

static __always_inline void bump_stat(__u32 idx) {
    __u64 *cnt = bpf_map_lookup_elem(&xdp_stats_map, &idx);
    if (cnt) __sync_fetch_and_add(cnt, 1);
}

static __always_inline int is_strict_mode(void) {
    __u32 k = 0;
    __u32 *v = bpf_map_lookup_elem(&xdp_policy_mode_map, &k);
    return (v && *v == 1);
}

static __always_inline int extract_ports(void *l4, void *data_end, __u8 proto,
                                         __u16 *sport, __u16 *dport) {
    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcph = l4;
        if ((void *)(tcph + 1) > data_end) return -1;
        *sport = bpf_ntohs(tcph->source);
        *dport = bpf_ntohs(tcph->dest);
        return 0;
    }
    if (proto == IPPROTO_UDP) {
        struct udphdr *udph = l4;
        if ((void *)(udph + 1) > data_end) return -1;
        *sport = bpf_ntohs(udph->source);
        *dport = bpf_ntohs(udph->dest);
        return 0;
    }
    return -1;
}

SEC("xdp")
int examos_xdp_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    __u16 h_proto = bpf_ntohs(eth->h_proto);
    __u16 sport = 0, dport = 0;

    if (h_proto == ETH_P_IP) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end) return XDP_PASS;
        if (iph->ihl < 5) return XDP_DROP;

        void *l4 = (void *)iph + (iph->ihl * 4);
        if (extract_ports(l4, data_end, iph->protocol, &sport, &dport) == 0) {
            /* Always block plaintext DNS (port 53) at driver layer */
            if (sport == 53 || dport == 53) {
                bump_stat(STAT_DROPPED_DNS53);
                return XDP_DROP;
            }
            if (is_strict_mode()) {
                __u32 saddr = iph->saddr;
                __u32 daddr = iph->daddr;
                __u8 *ok_s = bpf_map_lookup_elem(&xdp_allowed_ipv4, &saddr);
                __u8 *ok_d = bpf_map_lookup_elem(&xdp_allowed_ipv4, &daddr);
                int encrypted_port = (sport == 443 || dport == 443 || sport == 853 || dport == 853);
                if ((!ok_s && !ok_d) || !encrypted_port) {
                    bump_stat(STAT_DROPPED_POLICY);
                    return XDP_DROP;
                }
            }
        }
    } else if (h_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end) return XDP_PASS;

        void *l4 = (void *)(ip6 + 1);
        if (extract_ports(l4, data_end, ip6->nexthdr, &sport, &dport) == 0) {
            if (sport == 53 || dport == 53) {
                bump_stat(STAT_DROPPED_DNS53);
                return XDP_DROP;
            }
            if (is_strict_mode()) {
                struct ipv6_key sk = {0}, dk = {0};
                __builtin_memcpy(sk.addr, ip6->saddr.in6_u.u6_addr32, 16);
                __builtin_memcpy(dk.addr, ip6->daddr.in6_u.u6_addr32, 16);
                __u8 *ok_s = bpf_map_lookup_elem(&xdp_allowed_ipv6, &sk);
                __u8 *ok_d = bpf_map_lookup_elem(&xdp_allowed_ipv6, &dk);
                int encrypted_port = (sport == 443 || dport == 443 || sport == 853 || dport == 853);
                if ((!ok_s && !ok_d) || !encrypted_port) {
                    bump_stat(STAT_DROPPED_POLICY);
                    return XDP_DROP;
                }
            }
        }
    }

    bump_stat(STAT_ALLOWED);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
