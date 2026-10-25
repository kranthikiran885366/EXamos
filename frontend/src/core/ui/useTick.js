import { useEffect, useState } from 'react';
export const useTick = (ms) => { const [, s] = useState(0); useEffect(() => { const i = setInterval(() => s((x) => x + 1), ms); return () => clearInterval(i); }, [ms]); };
