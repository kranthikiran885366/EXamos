import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import App from './App';
import { AuthProvider } from './core/auth/AuthContext';
import './styles/app.css';

// Anti-clickjacking (defence in depth; the real control is the frame-ancestors response header).
if (window.top !== window.self) { document.documentElement.innerHTML = ''; throw new Error('Framing blocked'); }

// Auto-reload on stale chunk imports caused by new deployments
window.addEventListener('vite:preloadError', (event) => {
  event.preventDefault();
  window.location.reload();
});

createRoot(document.getElementById('root')).render(
  <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
    <AuthProvider>
      <App />
    </AuthProvider>
  </BrowserRouter>
);
