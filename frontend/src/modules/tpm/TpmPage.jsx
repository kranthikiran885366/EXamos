import { useState } from 'react';
import Crud from '../../core/ui/Crud';
import Badge from '../../core/ui/Badge';
import { useCol } from '../../core/db/tenant';
import { fmt } from '../../core/ui/format';

export default function TpmPage() {
  const atts = useCol('attestations'), devices = useCol('devices');
  const [did, setDid] = useState('');
  const d = devices.find((x) => x.id === did);
  const top = (
    <div className="card pad2"><b>Attestation workbench</b>
      <p className="muted sm">Server-side TPM quote verification and replay testing are unavailable. Client-side simulations are disabled and cannot establish device trust.</p>
      <div className="row wrap"><select value={did} onChange={(e) => setDid(e.target.value)}><option value="">Select device…</option>{devices.map((x) => <option key={x.id} value={x.id}>{x.hostname}</option>)}</select>
        {d && <span className="muted sm">Server trust: <Badge>Unverified</Badge></span>}</div>
    </div>);
  return (
    <Crud title="TPM Trust" desc="Legacy console records are unverified and are not evidence of trusted hardware." rows={atts.filter((a) => a.result).sort((x, y) => y.issuedAt - x.issuedAt)} search={(a) => `${a.hostname} ${a.result} ${a.reason}`} top={top}
      columns={[{ label: 'Time', render: (a) => fmt(a.issuedAt) }, { label: 'Device', render: (a) => <span className="mono">{a.hostname}</span> }, { label: 'Nonce', render: (a) => <span className="mono muted">{a.nonce.slice(0, 10)}…</span> }, { label: 'Reason', key: 'reason' }, { label: 'Result', render: () => <Badge>Unverified legacy record</Badge> }]} />
  );
}
