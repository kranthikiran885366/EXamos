import { useState } from 'react';
import Crud, { useRun, Flash } from '../../core/ui/Crud';
import Badge from '../../core/ui/Badge';
import { useAuth } from '../../core/auth/AuthContext';
import { useCol } from '../../core/db/tenant';
import { can } from '../../core/security/rbac';
import { fmt } from '../../core/ui/format';
import { attest, replayTest, setTamper } from './service';

export default function TpmPage() {
  const { user } = useAuth(); const atts = useCol('attestations'), devices = useCol('devices');
  const [did, setDid] = useState(''); const [msg, run, setMsg] = useRun();
  const d = devices.find((x) => x.id === did); const ok = can(user.role, 'tpm.run');
  const top = (
    <div className="card pad2"><b>Attestation workbench</b>
      <p className="muted sm">Server nonce → device-signed quote (non-extractable ECDSA key) → signature, PCR digest, golden PCR and revocation checks. The device agent is simulated; the verification is real.</p>
      <div className="row wrap"><select value={did} onChange={(e) => setDid(e.target.value)}><option value="">Select device…</option>{devices.map((x) => <option key={x.id} value={x.id}>{x.hostname}</option>)}</select>
        <button className="btn primary" disabled={!d || !ok} onClick={() => run(() => attest(user, d.id))}>Run attestation</button>
        <button className="btn" disabled={!d || !ok} onClick={() => run(() => replayTest(user, d.id))}>Replay last quote</button>
        <button className="btn danger" disabled={!d || !ok} onClick={() => run(() => setTamper(user, d))}>{d?.tampered ? 'Clear simulated tampering' : 'Simulate bootloader change'}</button>
        {d && <span className="muted sm">Trust: <Badge>{d.trust === 'attested' ? 'Attested' : d.trust === 'failed' ? 'Failed' : 'Pending'}</Badge></span>}</div>
      <Flash msg={msg} onClose={() => setMsg(null)} />
    </div>);
  return (
    <Crud title="TPM Trust" desc="Attestation results. Nonces are single-use and expire in 60 seconds." rows={atts.filter((a) => a.result).sort((x, y) => y.issuedAt - x.issuedAt)} search={(a) => `${a.hostname} ${a.result} ${a.reason}`} top={top}
      columns={[{ label: 'Time', render: (a) => fmt(a.issuedAt) }, { label: 'Device', render: (a) => <span className="mono">{a.hostname}</span> }, { label: 'Nonce', render: (a) => <span className="mono muted">{a.nonce.slice(0, 10)}…</span> }, { label: 'Reason', key: 'reason' }, { label: 'Result', render: (a) => <Badge>{a.result === 'attested' ? 'Attested' : 'Failed'}</Badge> }]} />
  );
}
