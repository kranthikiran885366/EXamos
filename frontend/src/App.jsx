import { Component, Suspense, lazy } from 'react';
import { Routes, Route, Navigate, useLocation } from 'react-router-dom';
import Shell from './core/ui/Shell';
import ProtectedRoute from './core/auth/ProtectedRoute';
import LoginPage from './modules/auth/LoginPage';
import LandingPage from './core/ui/LandingPage';
import ArchitecturePage from './core/ui/ArchitecturePage';
import SolutionsPage from './core/ui/SolutionsPage';
import { ROUTES, LEGACY, GROUPS } from './core/nav';
import { useAuth } from './core/auth/AuthContext';
import { can } from './core/security/rbac';

const MfaPage = lazy(() => import('./modules/auth/pages').then((m) => ({ default: m.MfaPage })));
const RecoveryPage = lazy(() => import('./modules/auth/pages').then((m) => ({ default: m.RecoveryPage })));
const ResetPasswordPage = lazy(() => import('./modules/auth/pages').then((m) => ({ default: m.ResetPasswordPage })));
const InvitePage = lazy(() => import('./modules/auth/pages').then((m) => ({ default: m.InvitePage })));
const UnauthorizedPage = lazy(() => import('./modules/auth/pages').then((m) => ({ default: m.UnauthorizedPage })));
const ExpiredPage = lazy(() => import('./modules/auth/pages').then((m) => ({ default: m.ExpiredPage })));
const PublicInstitutionRegisterPage = lazy(() => import('./modules/institutions/PublicInstitutionRegisterPage'));

// Role to dedicated primary workspace dashboard mapping
const ROLE_HOME = {
  superadmin: '/platform/institutions',
  ops_admin: '/platform/institutions',
  inst_admin: '/institution/dashboard',
  exam_controller: '/college/exams',
  invigilator: '/operator/overview',
  it_admin: '/devices',
  security_engineer: '/security/overview',
  auditor: '/admin/audit',
  finance: '/admin/billing',
  student: '/student/home',
};

// Each route definition exposes an async loader. Wrap them once so React treats
// them as lazy components rather than rendering the returned promise as a child.
const ROUTE_COMPONENTS = new Map(ROUTES.map((r) => [r.path, lazy(r.load)]));

class ErrorBoundary extends Component {
  constructor(p) { super(p); this.state = { error: null, stack: '' }; }
  static getDerivedStateFromError(error) { return { error }; }
  componentDidCatch(error, info) { console.error('ExamOS render error', error, info); this.setState({ stack: info?.componentStack || '' }); }
  render() {
    if (this.state.error) {
      const isChunkError = /Failed to fetch dynamically imported module|Importing a module script failed/i.test(this.state.error?.message || '');
      return (
        <div className="pad">
          <div className="card denied">
            <h2>Something went wrong on this page</h2>
            <p className="muted">
              {isChunkError ? 'A new update was deployed to ExamOS. Please reload the console to load the latest version.' : 'The rest of the console is unaffected. No security state was changed.'}
            </p>
            <pre className="code">{String(this.state.error?.message || this.state.error)}{this.state.stack ? '\n' + this.state.stack : ''}</pre>
            <button
              className="btn primary"
              onClick={() => {
                if (isChunkError) {
                  window.location.reload();
                } else {
                  this.setState({ error: null, stack: '' });
                }
              }}
            >
              {isChunkError ? 'Reload Console' : 'Try again'}
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

function Home() {
  const { user } = useAuth();
  if (user?.role && ROLE_HOME[user.role]) {
    return <Navigate to={ROLE_HOME[user.role]} replace />;
  }
  const first = GROUPS.flatMap((g) => g.items).find((r) => can(user.role, r.perm));
  return <Navigate to={first ? first.path : '/dashboard'} replace />;
}

const Fallback = () => <div className="pad"><div className="loading"><span className="spinner" /> Loading module…</div></div>;

function Denied() { return <div className="pad"><div className="card denied"><h2>Access denied</h2><p className="muted">Your role does not include this module. The attempt was recorded in the audit trail.</p></div></div>; }

function PublicOnly({ children }) {
  const { user } = useAuth();
  if (!user) return children;
  if (user.role && ROLE_HOME[user.role]) {
    return <Navigate to={ROLE_HOME[user.role]} replace />;
  }
  return <Navigate to="/dashboard" replace />;
}

export default function App() {
  const loc = useLocation();
  return (
    <ErrorBoundary key={loc.pathname}>
      <Suspense fallback={<Fallback />}>
        <Routes>
          <Route path="/" element={<LandingPage />} />
          <Route path="/landing" element={<LandingPage />} />
          <Route path="/architecture" element={<ArchitecturePage />} />
          <Route path="/solutions" element={<SolutionsPage />} />

          {/* Public accreditation & onboarding registration */}
          <Route path="/register-institution" element={<PublicInstitutionRegisterPage />} />
          <Route path="/apply" element={<Navigate to="/register-institution" replace />} />
          <Route path="/institution/register" element={<Navigate to="/register-institution" replace />} />

          {/* Public auth routes */}
          <Route path="/login" element={<PublicOnly><LoginPage /></PublicOnly>} />
          <Route path="/candidate-login" element={<Navigate to="/login?realm=candidate" replace />} />
          <Route path="/mfa" element={<PublicOnly><MfaPage /></PublicOnly>} />
          <Route path="/recovery" element={<PublicOnly><RecoveryPage /></PublicOnly>} />
          <Route path="/reset-password" element={<PublicOnly><ResetPasswordPage /></PublicOnly>} />
          <Route path="/invite/:token" element={<PublicOnly><InvitePage /></PublicOnly>} />
          <Route path="/unauthorized" element={<UnauthorizedPage />} />
          <Route path="/expired" element={<ExpiredPage />} />

          {/* Protected app shell */}
          <Route element={<ProtectedRoute><Shell /></ProtectedRoute>}>
            <Route path="app" element={<Home />} />
            {ROUTES.map((r) => {
              const LazyPage = ROUTE_COMPONENTS.get(r.path);
              return <Route key={r.path} path={r.path} element={
                <ProtectedRoute perm={r.perm}>
                  <ErrorBoundary><LazyPage /></ErrorBoundary>
                </ProtectedRoute>
              } />;
            })}
            {Object.entries(LEGACY).map(([from, to]) => <Route key={from} path={from} element={<Navigate to={to} replace />} />)}
            <Route path="/admin/overview" element={<Navigate to="/dashboard" replace />} />
            <Route path="/college" element={<Navigate to="/college/overview" replace />} />
            <Route path="/student" element={<Navigate to="/student/home" replace />} />
            <Route path="/operator" element={<Navigate to="/operator/overview" replace />} />
            <Route path="/security" element={<Navigate to="/security/overview" replace />} />
            <Route path="/support/requests/new" element={<Navigate to="/support/requests" replace />} />
            <Route path="/reports/legacy" element={<Navigate to="/reports" replace />} />
            <Route path="/denied" element={<Denied />} />
            <Route path="*" element={<Denied />} />
          </Route>
        </Routes>
      </Suspense>
    </ErrorBoundary>
  );
}
