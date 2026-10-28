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

// Each route definition exposes an async loader. Wrap them once so React treats
// them as lazy components rather than rendering the returned promise as a child.
const ROUTE_COMPONENTS = new Map(ROUTES.map((r) => [r.path, lazy(r.load)]));

class ErrorBoundary extends Component {
  constructor(p) { super(p); this.state = { error: null, stack: '' }; }
  static getDerivedStateFromError(error) { return { error }; }
  componentDidCatch(error, info) { console.error('ExamOS render error', error, info); this.setState({ stack: info?.componentStack || '' }); }
  render() {
    if (this.state.error) return <div className="pad"><div className="card denied"><h2>Something went wrong on this page</h2><p className="muted">The rest of the console is unaffected. No security state was changed.</p><pre className="code">{String(this.state.error?.message || this.state.error)}{this.state.stack ? '\n' + this.state.stack : ''}</pre><button className="btn primary" onClick={() => this.setState({ error: null, stack: '' })}>Try again</button></div></div>;
    return this.props.children;
  }
}

function Home() {
  const { user } = useAuth();
  const first = GROUPS.flatMap((g) => g.items).find((r) => can(user.role, r.perm));
  if (user.role === 'student') return <Navigate to="/student/home" replace />;
  return <Navigate to={first ? first.path : '/dashboard'} replace />;
}

const Fallback = () => <div className="pad"><div className="loading"><span className="spinner" /> Loading module…</div></div>;

function Denied() { return <div className="pad"><div className="card denied"><h2>Access denied</h2><p className="muted">Your role does not include this module. The attempt was recorded in the audit trail.</p></div></div>; }

function PublicOnly({ children }) {
  const { user } = useAuth();
  return user ? <Navigate to={user.role === 'student' ? '/student/home' : '/dashboard'} replace /> : children;
}

export default function App() {
  const loc = useLocation();
  return (
    <ErrorBoundary key={loc.pathname}>
      <Suspense fallback={<Fallback />}>
        <Routes>
          {/* Direct redirect to login on root visit */}
          <Route path="/" element={<Navigate to="/login" replace />} />
          <Route path="/landing" element={<LandingPage />} />
          <Route path="/architecture" element={<ArchitecturePage />} />
          <Route path="/solutions" element={<SolutionsPage />} />

          {/* Public auth routes */}
          <Route path="/login" element={<PublicOnly><LoginPage /></PublicOnly>} />
          <Route path="/mfa" element={<PublicOnly><MfaPage /></PublicOnly>} />
          <Route path="/recovery" element={<PublicOnly><RecoveryPage /></PublicOnly>} />
          <Route path="/reset-password" element={<PublicOnly><ResetPasswordPage /></PublicOnly>} />
          <Route path="/invite/:token" element={<PublicOnly><InvitePage /></PublicOnly>} />
          <Route path="/unauthorized" element={<UnauthorizedPage />} />
          <Route path="/expired" element={<ExpiredPage />} />

          {/* Protected app shell */}
          <Route element={<ProtectedRoute><Shell /></ProtectedRoute>}>
            <Route index element={<Home />} />
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
