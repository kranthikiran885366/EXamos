import { all, get, put } from '../../core/db/db';
import { sha256, canon, sign, verify, randomId } from '../../core/security/crypto';
import { id, need, fail, log, PCRS } from '../../core/services/common';
import { raise } from '../incidents/service';

export async function pcrValues(digest, tampered = false) {
  const o = {};
  for (const i of PCRS) o[i] = await sha256(`PCR${i}:${digest}${tampered && i === 7 ? ':unsigned-bootloader' : ''}`);
  return o;
}
// 1) server issues a fresh single-use nonce
export async function issueChallenge(d) {
  const ch = { id: id('att'), tenantId: d.tenantId, deviceId: d.id, hostname: d.hostname, nonce: randomId(16), issuedAt: Date.now(), status: 'issued' };
  await put('attestations', ch); return ch;
}
// 2) device agent builds + signs a quote with its non-extractable key (simulated agent)
export async function agentQuote(d, nonce) {
  const k = await get('keys', d.id); if (!k) fail('Device key is missing.');
  const rel = await get('releases', d.releaseId);
  const pcr = await pcrValues(rel?.digest || 'none', d.tampered);
  const body = { deviceId: d.id, nonce, pcr, pcrDigest: await sha256(canon(pcr)), releaseId: d.releaseId, ts: Date.now() };
  return { body, sig: await sign(k.priv, canon(body)) };
}
// 3) server verifies: nonce state, signature, PCR digest, golden PCRs, enrolment, release revocation
export async function verifyQuote(ch, quote) {
  const d = await get('devices', ch.deviceId); const cur = await get('attestations', ch.id);
  if (!cur || cur.nonce !== quote.body.nonce) return 'nonce unknown';
  if (cur.status !== 'issued') return 'nonce already used (replay)';
  await put('attestations', { ...cur, status: 'used' });
  if (Date.now() - cur.issuedAt > 60000) return 'nonce expired';
  if (!d || d.status !== 'enrolled') return 'device not enrolled';
  const k = await get('keys', d.id);
  if (!k || !(await verify(k.pub, canon(quote.body), quote.sig))) return 'quote signature invalid';
  if ((await sha256(canon(quote.body.pcr))) !== quote.body.pcrDigest) return 'PCR digest mismatch';
  const rel = await get('releases', quote.body.releaseId);
  if (!rel) return 'unknown release';
  if (rel.status === 'revoked') return 'release revoked';
  const golden = await pcrValues(rel.digest, false);
  const bad = PCRS.filter((i) => golden[i] !== quote.body.pcr[i]);
  if (bad.length) return `PCR ${bad.join(',')} differs from golden policy`;
  return null;
}
export async function attest(a, deviceId) {
  need(a, 'tpm.run');
  const d = await get('devices', deviceId); if (!d) fail('Device not found.');
  const ch = await issueChallenge(d); const quote = await agentQuote(d, ch.nonce);
  const reason = await verifyQuote(ch, quote);
  const cur = await get('attestations', ch.id);
  await put('attestations', { ...cur, status: 'used', result: reason ? 'failed' : 'attested', reason: reason || 'quote verified', verifiedAt: Date.now(), quote });
  await put('devices', { ...(await get('devices', deviceId)), trust: reason ? 'failed' : 'attested', lastAttested: Date.now() });
  if (reason) { await raise({ tenantId: d.tenantId, key: `att:${d.id}`, title: `Attestation failed · ${d.hostname}: ${reason}`, severity: 'high', source: 'tpm-verifier', deviceId: d.id }); await log(a, 'ATTEST_FAILED', `${d.hostname}: ${reason}`); }
  return reason ? `Attestation failed: ${reason}.` : `${d.hostname} attested.`;
}
export async function replayTest(a, deviceId) {
  need(a, 'tpm.run');
  const last = (await all('attestations')).filter((x) => x.deviceId === deviceId && x.quote).sort((x, y) => y.issuedAt - x.issuedAt)[0];
  if (!last) fail('Run an attestation first; there is no quote to replay.');
  const reason = await verifyQuote(last, last.quote);
  await log(a, 'ATTEST_REPLAY_TEST', `${deviceId}: ${reason || 'ACCEPTED (bug)'}`);
  return reason ? `Replay rejected: ${reason}.` : 'Replay was accepted. That is a defect.';
}
export async function setTamper(a, d) {
  need(a, 'tpm.run');
  await put('devices', { ...d, tampered: !d.tampered }); await log(a, 'SIM_FIRMWARE_CHANGE', `${d.hostname} tampered=${!d.tampered}`);
  return d.tampered ? 'Simulated tampering cleared. Re-attest to restore trust.' : 'Simulated bootloader change applied. Re-attest to see it detected.';
}
