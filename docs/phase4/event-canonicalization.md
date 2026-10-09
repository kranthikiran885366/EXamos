# ExamOS Phase 4 — Event Canonicalization Specification

## 1. Purpose
To ensure tamper-evident hash chaining is reproducible across platforms and independent verifiers, all events must be serialized into a strict canonical byte representation before computing the SHA-256 digest.

## 2. Canonical JSON Format
The canonical JSON representation defines strict alphabetical key ordering, no whitespace between key-value pairs or delimiters, and ISO 8601 UTC millisecond timestamps:

```json
{"event_type":"<TYPE>","model_name":"<NAME>","model_version":"<VER>","payload":<PAYLOAD_JSON>,"previous_hash":"<64_HEX>","sequence":<UINT64>,"server_timestamp":"<ISO8601>","session_id":"<ID>","source_timestamp":"<ISO8601>","source_type":"<SRC>"}
```

## 3. Hash Chaining Formula
For any event $E_i$ at sequence $i$:
$$H_0 = 0000000000000000000000000000000000000000000000000000000000000000$$
$$H_i = \text{SHA256}(H_{i-1} \parallel \text{CanonicalJSON}(E_i))$$

## 4. Verification Invariants
1. Sequence number $i$ must equal expected counter ($1, 2, 3, \dots, N$).
2. Stored `previous_hash` must match calculated $H_{i-1}$.
3. Stored `event_hash` must match calculated $H_i$.
