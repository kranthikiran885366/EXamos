import { Link, Navigate, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext';
import { LandNav, Hero, FeatureGrid, ModulesGrid, WhySection, CtaSection, LandFoot } from './kit';

export default function LandingPage() {
  const { user } = useAuth();
  const nav = useNavigate();
  const loc = useLocation();
  if (user) return <Navigate to={user.role === 'student' ? '/student/home' : '/dashboard'} replace />;

  return (
    <div className="land">
      <LandNav />
      <Hero />
      <FeatureGrid />
      <ModulesGrid />
      <WhySection />
      <CtaSection />
      <LandFoot />
    </div>
  );
}
