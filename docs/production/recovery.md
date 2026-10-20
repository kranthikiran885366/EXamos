# Operator recovery

Authorized maintenance must not present a candidate shell and must not use
predictable or printed recovery secrets.

## Provision (once, from custody)

```bash
# 32+ byte secret from an HSM or password manager; value is not echoed back.
examos-operator-recovery provision-key < recovery.secret
```

## Pause kiosk

```bash
examos-operator-recovery trigger-breakout < recovery.secret
```

This writes a 30-second one-shot ticket under `/run/examos/` and signals the
kiosk supervisor. The supervisor exits only if that ticket is valid.

## Resume exam mode

```bash
examos-operator-recovery resume-kiosk
```

## Absolute limits

- No `generate-key` from clock/pid.
- No recovery key in git or the OS image.
- No firmware, TPM clear, or Windows boot changes from this tool.
- If the kiosk cannot resume, boot Windows from the firmware menu (see
  `docs/production/hardware-qualification.md`).
