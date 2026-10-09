# Enterprise upgrade status

ExamOS preserves its native C/C++ architecture. Production claims are permitted only when the dynamic gates pass on the target appliance.

## Implemented foundations

- Real V4L2 MMAP capture with YUYV-to-RGB conversion; synthetic frames are never emitted as evidence.
- PBKDF2-SHA256 candidate credential verification with a deployment-provisioned credential store.
- Separate candidate, administrator, agent, and proctor authentication boundaries.
- Deployment-provisioned event-signing and service secrets; no compiled-in evidence signing key.
- Durable event writes using `fsync`, with failures propagated to API callers.
- Enforcing Chromium AppArmor profile and expanded systemd sandboxing.
- Truly concurrent load generation and gates that derive their status from executed tests.
- Detection evaluation requires a real labelled dataset and native evaluator; synthetic metrics cannot pass.

## Required deployment provisioning

1. Replace every `NOT_PROVISIONED` value in `/etc/examos/proctor.env` with an independent random secret of at least 32 characters.
2. Replace the development admin password hash.
3. Provision candidates with `scripts/provision-candidate.sh` or an approved identity synchronization process.
4. Provide a licensed, versioned vision model and labelled evaluation dataset.
5. Enroll production Secure Boot keys, TPM endorsement/attestation keys, and measured-boot PCR policy generated from the release image.
6. Terminate TLS with client authentication at a hardened native proxy or add OpenSSL TLS directly to the service before exposing it beyond loopback.

## Release blockers

- The current vision algorithm is not a validated face/object model.
- TPM verification still contains development PCRs and a test quote-signature construction.
- WebRTC signaling/SFU transport is not implemented.
- Server state is not replicated and is unsuitable for multi-node high availability.
- The project has no supplied real-media dataset or `exam-vision-eval` binary yet, so the P4 gate intentionally fails.
