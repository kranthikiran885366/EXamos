import { useEffect, useState } from 'react';
import { initChain } from './security/auditChain';
import { all, del, wipe } from './db/db';
import { registerRoles } from './security/rbac';
import { SppioSymbol } from './ui/SppioLogo';

export default function Boot({ children }) {
  const [ready, setReady] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        try {
          /*
           * Purge only locally-created credential rows (rows with a password_hash
           * field) — these are legacy artifacts from the removed IndexedDB login
           * realm. Server-fetched user records (no password_hash) are kept as
           * offline cache for the institution admin list and other UI.
           */
          const currentUsers = await all('users');
          for (const u of currentUsers) {
            if (u.password_hash || u.passwordHash || u.salt) {
              await del('users', u.id);
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
