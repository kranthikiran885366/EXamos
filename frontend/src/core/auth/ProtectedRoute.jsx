import { useEffect } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from './AuthContext';
import { can } from '../security/rbac';
import { record } from '../security/auditChain';

// Map backend (C server) roles to frontend roles for ProtectedRoute permission checks.
// Backend roles (enterprise_platform.h user_role_t):
//   ROLE_PLATFORM_OWNER, ROLE_INSTITUTION_ADMIN, ROLE_EXAM_MANAGER,
//   ROLE_SECURITY_ADMIN, ROLE_INVIGILATOR, ROLE_TECH_OPERATOR,
//   ROLE_INCIDENT_INVESTIGATOR, ROLE_READONLY_AUDITOR, ROLE_SUPPORT_ENGINEER
const BACKEND_ROLE_TO_FRONTEND = {
  PLATFORM_OWNER: 'superadmin',
  INSTITUTION_ADMIN: 'inst_admin',
  EXAM_MANAGER: 'exam_controller',
  SECURITY_ADMIN: 'security_engineer',
  INVIGILATOR: 'invigilator',
  TECH_OPERATOR: 'ops_admin',
  INCIDENT_INVESTIGATOR: 'auditor',
  READONLY_AUDITOR: 'auditor',
  SUPPORT_ENGINEER: 'support',
};

export function frontendRoleForBackend(backendRole) {
  if (!backendRole) return null;
  const mapped = BACKEND_ROLE_TO_FRONTEND[backendRole];
  return mapped || backendRole.toLowerCase();
}

export default function ProtectedRoute({ children, perm }) {
  const { user, backendMode, authReady } = useAuth();
  const loc = useLocation();
  const perms = perm ? (Array.isArray(perm) ? perm : [perm]) : [];

  // Determine effective frontend role (from local user or backend-mapped).
  let effectiveRole = user?.role;
  if (backendMode === 'admin' && user) {
    const mapped = frontendRoleForBackend(user.role);
    if (mapped) effectiveRole = mapped;
  }

  const allowed = !effectiveRole ? false : perms.length === 0 || perms.some((p) => can(effectiveRole, p));
  useEffect(() => { if (effectiveRole && !allowed) record(effectiveRole, 'ACCESS_DENIED', loc.pathname); }, [effectiveRole, allowed, loc.pathname]);
  if (!authReady) return <div className="pad"><div className="loading" role="status"><span className="spinner" /> Restoring your session…</div></div>;
  if (!effectiveRole) return <Navigate to="/login" replace state={{ from: loc.pathname + loc.search }} />;
  if (!allowed) return <div className="pad"><div className="card denied"><h2>Access denied</h2><p className="muted">Your role does not include this module. The attempt was recorded in the audit trail.</p><p className="muted sm">If you believe you need access, ask an administrator to review your effective permissions.</p><a className="btn" href="/">Return to your overview</a></div></div>;
  return children;
}
