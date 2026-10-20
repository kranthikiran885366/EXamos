# ExamOS P2 — Default-Deny Network Firewall

## 1. Backend

nftables (package: `nftables`, config: `/etc/nftables.conf`).

## 2. Policy Design

All three hooks (input, forward, output) default to DROP.

Allowed outbound:
| Traffic | Justification |
|---|---|
| DNS UDP/TCP to configured resolver IPs | Name resolution for exam server |
| DHCP (port 67/68) | Network configuration |
| NTP UDP to configured NTP IPs | Time synchronisation |
| TCP 443 to exam server IPs | Exam traffic |
| TCP 80 to CRL/OCSP responder IPs | Certificate validation |

Allowed inbound:
| Traffic | Justification |
|---|---|
| Loopback | Admin dashboard on 127.0.0.1:8000, IPC |
| Established/related | Return traffic for sessions we initiated |
| ICMP echo-reply, dest-unreachable, time-exceeded | Path MTU discovery |

No 0.0.0.0/0 accept rule exists anywhere in the ruleset.

## 3. Boot Ordering (fail-closed)

`nftables.service.d/p2-ordering.conf` places nftables **before** `network-pre.target` and `NetworkManager.service`. NetworkManager cannot start until nftables rules are loaded.

`ExecStartPre=/usr/sbin/nft --check --file /etc/nftables.conf` — if the ruleset fails syntax check, nftables does not start and NetworkManager never starts (no network access).

`ExecStopPost` installs an emergency drop-all table if nftables stops for any reason.

## 4. IPv6

IPv6 is disabled at the sysctl level (`net.ipv6.conf.all.disable_ipv6=1`). The nftables ruleset also includes an `ip6 filter` table that drops all IPv6 traffic as belt-and-suspenders.

## 5. Deployment Configuration

Replace the placeholder IPs in `/etc/nftables.conf` at deployment:
- Exam server IPs (TCP 443)
- Controlled DNS resolver IPs (UDP/TCP 53)
- NTP server IPs (UDP 123)
- CRL/OCSP responder IPs (TCP 80)

The startup validator blocks exam start if `CONTROLLED_DNS_ADDRESS=DEPLOYMENT_CONFIGURED`.

## 6. Tests

| Test | Script | Mandatory |
|---|---|---|
| P2-01: non-exam URL blocked | p2-network-tests.sh | Yes |
| P2-02: IP literal/redirect blocked | p2-network-tests.sh | Yes |
| P2-03: non-exam destination blocked | p2-network-tests.sh | Yes |
| P2-09: external port scan | p2-network-tests.sh | Yes |
| P2-13: firewall before network | p2-network-tests.sh | Yes |
