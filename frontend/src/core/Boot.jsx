import { useEffect, useState } from 'react';
import { seed } from './seed';
import { initChain } from './security/auditChain';
import { all, del, wipe } from './db/db';
import { registerRoles } from './security/rbac';

export default function Boot({ children }) {
  const [state, setState] = useState('boot'); const [err, setErr] = useState(''); const [step, setStep] = useState('Preparing secure workspace');
  useEffect(() => {
    (async () => {
      try {
        setStep('Provisioning institution');
        await seed();
        setStep('Synchronizing production platform accounts');
        // Purge all legacy demo/mock seed users from IndexedDB, preserving only platform administrators (root, admin)
        const currentUsers = await all('users');
        const allowedAdmins = new Set(['root', 'admin']);
        for (const u of currentUsers) {
          if (!allowedAdmins.has(u.id) && !allowedAdmins.has(u.username)) {
            await del('users', u.id);
          }
        }
        // Purge mock staff and mock invitations
        const currentStaff = await all('staff');
        for (const s of currentStaff) {
          if (!allowedAdmins.has(s.userId)) {
            await del('staff', s.id);
          }
        }
        const currentInvites = await all('invitations');
        for (const inv of currentInvites) {
          await del('invitations', inv.id);
        }

        setStep('Loading roles');
        registerRoles(await all('roles'));
        setStep('Verifying audit chain');
        await initChain();
        setState('ready');
      } catch (e) { console.error(e); setErr(e?.message || String(e)); setState('error'); }
    })();
  }, []);
  if (state === 'ready') return children;
  return <div className="loginwrap"><div className="card login bootcard"><div className="brand dark"><span className="logo">▣</span> ExamOS <em>ENT</em></div>
    {state === 'boot' ? <><h2>Preparing secure workspace</h2><p className="muted">First run provisions signing keys, hashed credentials, seeded institutions and a hash-chained audit log. This takes a few seconds.</p><div className="bootstep"><span className="spinner" /> {step}</div></> : <><h2>Could not start</h2><div className="err">{err}</div><p className="muted sm">If the local store is corrupt you can reset it. This deletes all demo data on this browser only.</p><button className="btn" onClick={async () => { await wipe(); location.reload(); }}>Reset local data and retry</button></>}
  </div></div>;
}
