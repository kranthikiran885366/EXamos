import { need, fail } from '../../core/services/common';

export async function attest(a, deviceId) {
  need(a, 'tpm.run');
  if (!deviceId) fail('A device ID is required.');
  fail('Hardware-backed TPM verification is unavailable. No attestation was recorded and device trust was not changed.');
}
