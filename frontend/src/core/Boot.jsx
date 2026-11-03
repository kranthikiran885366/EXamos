import { useEffect, useState } from 'react';
import { removeLegacyApplicationCache } from './db/db';

export default function Boot({ children }) {
  const [state, setState] = useState({ ready: false, error: null });
  useEffect(() => {
    removeLegacyApplicationCache()
      .then(() => setState({ ready: true, error: null }))
      .catch((error) => setState({ ready: false, error }));
  }, []);
  if (state.error) {
    return <div className="pad"><div className="card denied"><h2>Could not clear the legacy local cache</h2><p>{state.error.message}</p><button className="btn" onClick={() => window.location.reload()}>Retry</button></div></div>;
  }
  if (!state.ready) return <div className="pad"><div className="loading"><span className="spinner" /> Preparing server-backed workspace…</div></div>;
  return children;
}
