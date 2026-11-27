# Security Policy

## Supported Versions

Only the latest release on `main` and active institutional LTS releases receive security updates.

## Reporting a Vulnerability

We take security vulnerabilities in **SPPIO / ExamOS** seriously. If you discover a security issue in the OS image, kernel eBPF/LSM policies, `sppio-core` server, endpoint agent, or web console (`sppio-os.vercel.app`), please report it privately.

- **Contact**: Report via GitHub Private Vulnerability Reporting (`Security` -> `Advisories` -> `Report a vulnerability` on `https://github.com/kranthikiran885366/EXamos/security/advisories/new`).
- **Response SLA**: We acknowledge receipt within **48 hours** and provide an initial triage assessment within **5 business days**.
- **Coordinated Disclosure**: Please allow us reasonable time to investigate, patch, and notify affected institutional deployments before public disclosure.

## Scope

In-scope targets include:
- `sppio-core` (`server/`)
- Endpoint agent & hardware guard (`agent/`)
- Proctoring worker (`proctoring/`)
- Rust security daemons (`rust-services/`)
- Kernel eBPF LSM / XDP & image lockdown scripts (`kernel/`, `image/`)
- Web console (`frontend/`)
