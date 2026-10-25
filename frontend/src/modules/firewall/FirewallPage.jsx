import { useState } from 'react';
import Crud from '../../core/ui/Crud';
import { useAuth } from '../../core/auth/AuthContext';
import { useTenant, useCol } from '../../core/db/tenant';
import { createRule, toggleRule, deleteRule, testUrl, toNft } from './service';

export default function FirewallPage() {
  const { user } = useAuth(); const { tenantId } = useTenant(); const rules = useCol('rules');
  const [url, setUrl] = useState('https://exam.examos.in/start'); const res = testUrl(rules, url);
  const top = (
    <div className="two">
      <div className="card pad2"><b>Policy tester</b><p className="muted sm">Evaluates a URL against the enabled rules (first match by priority; default deny).</p>
        <input value={url} onChange={(e) => setUrl(e.target.value)} maxLength={300} aria-label="URL to test" />
        <p>{res.error ? <span className="err">{res.error}</span> : <>Decision for <code>{res.host}:{res.port}</code>: <span className={'badge ' + (res.action === 'allow' ? 'g' : 'r')}><i />{res.action}</span> <span className="muted sm">{res.rule ? `rule “${res.rule.name}”` : 'default deny'}</span></>}</p></div>
      <div className="card pad2"><b>Generated nftables ruleset</b><pre className="code">{toNft(rules)}</pre></div>
    </div>);
  return (
    <Crud title="Firewall" desc="OS-level egress rules. Changes that would break a published policy are refused." rows={[...rules].sort((a, b) => a.priority - b.priority)} search={(r) => `${r.name} ${r.host}`} top={top}
      columns={[{ label: 'Priority', key: 'priority' }, { label: 'Name', key: 'name' }, { label: 'Host', key: 'host' }, { label: 'Port', key: 'port' }, { label: 'Action', key: 'action', badge: true }, { label: 'Enabled', render: (r) => (r.enabled ? 'yes' : 'no') }]}
      create={{ label: 'Add rule', perm: 'firewall.manage', fields: [{ name: 'name', label: 'Name' }, { name: 'host', label: 'Host', placeholder: 'exam.examos.in or *.examos.in' }, { name: 'port', label: 'Port', default: '443' }, { name: 'action', label: 'Action', type: 'select', options: ['allow', 'deny'], default: 'allow' }, { name: 'priority', label: 'Priority (lower runs first)', type: 'number', default: 100 }], submit: (v) => createRule(user, { tenantId, ...v }) }}
      actions={[{ label: 'Toggle', perm: 'firewall.manage', run: (r) => toggleRule(user, r) }, { label: 'Delete', perm: 'firewall.manage', danger: true, reason: true, run: (r, why) => deleteRule(user, r, why) }]} />
  );
}
