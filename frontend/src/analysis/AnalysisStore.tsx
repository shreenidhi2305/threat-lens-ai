import { createContext, useCallback, useContext, useMemo, useState } from 'react';
import type { ReactNode } from 'react';

import { recordAnalysis } from '../lib/history';
import type { AnalysisResult } from '../lib/types';

const SESSION_KEY = 'threatlens.lastResult';

function loadLast(): AnalysisResult | null {
  try {
    const raw = sessionStorage.getItem(SESSION_KEY);
    return raw ? (JSON.parse(raw) as AnalysisResult) : null;
  } catch {
    return null;
  }
}

interface Store {
  result: AnalysisResult | null;
  commit: (result: AnalysisResult) => void;
}

const AnalysisContext = createContext<Store | undefined>(undefined);

export function AnalysisProvider({ children }: { children: ReactNode }) {
  const [result, setResult] = useState<AnalysisResult | null>(loadLast);

  const commit = useCallback((next: AnalysisResult) => {
    setResult(next);
    recordAnalysis(next);
    try {
      sessionStorage.setItem(SESSION_KEY, JSON.stringify(next));
    } catch {
      /* ignore */
    }
  }, []);

  const value = useMemo(() => ({ result, commit }), [result, commit]);
  return <AnalysisContext.Provider value={value}>{children}</AnalysisContext.Provider>;
}

export function useAnalysis(): Store {
  const ctx = useContext(AnalysisContext);
  if (!ctx) throw new Error('useAnalysis must be used within an AnalysisProvider');
  return ctx;
}
