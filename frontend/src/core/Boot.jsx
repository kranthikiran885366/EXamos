import { useEffect, useState } from 'react';
import { seed } from './seed';
import { initChain } from './security/auditChain';
import { all, del, wipe } from './db/db';
import { registerRoles } from './security/rbac';
import { SppioSymbol } from './ui/SppioLogo';

export default function Boot({ children }) {
  const [ready, setReady] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        // Attempt non-blocking local cache seed; never block the application
        try {
          await seed();
        } catch (seedErr) {
          console.warn('[SPPIO-Boot] Local seed warning (non-fatal):', seedErr?.message || seedErr);
        }

        try {
          const currentUsers = await all('users');
          const allowedAdmins = new Set(['root', 'admin']);
          for (const u of currentUsers) {
            if (!allowedAdmins.has(u.id) && !allowedAdmins.has(u.username)) {
              await del('users', u.id);
            }
          }
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
        } catch (_) {}

        try {
          const roles = await all('roles');
          if (roles && roles.length) registerRoles(roles);
        } catch (_) {}

        try {
          await initChain();
        } catch (_) {}
      } catch (err) {
        console.warn('[SPPIO-Boot] Cache init warning:', err);
      } finally {
        setReady(true);
      }
    })();
  }, []);

  if (!ready) {
    return (
      <div className="loginwrap">
        <div className="card login bootcard">
          <div className="brand dark">
            <span className="logo" style={{ background: 'transparent', boxShadow: 'none' }}>
              <SppioSymbol size={26} accent="#B54F34" />
            </span>
            SPPIO <em>ENT</em>
          </div>
          <h2>Connecting to Secure Platform</h2>
          <div className="bootstep">
            <span className="spinner" /> Initializing secure workspace...
          </div>
        </div>
      </div>
    );
  }

  return children;
}
