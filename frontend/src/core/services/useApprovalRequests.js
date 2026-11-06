import { useCallback, useEffect, useState } from 'react';
import { listApprovalRequests } from '../api/services';

export function useApprovalRequests() {
  const [state, setState] = useState({ requests: [], loading: true, error: null });
  const refresh = useCallback(async () => {
    setState((current) => ({ ...current, loading: true, error: null }));
    try {
      const requests = await listApprovalRequests();
      setState({ requests, loading: false, error: null });
    } catch (error) {
      setState({ requests: [], loading: false, error });
    }
  }, []);

  useEffect(() => {
    refresh();
    const timer = setInterval(refresh, 30000);
    return () => clearInterval(timer);
  }, [refresh]);

  return { ...state, refresh };
}
