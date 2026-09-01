import { createContext, useContext, useMemo, useState } from 'react';
import type { ReactNode } from 'react';

import type { AnalysisResult } from '../lib/types';

interface AnalysisStore {
  result: AnalysisResult | null;
  setResult: (result: AnalysisResult | null) => void;
}

const AnalysisContext = createContext<AnalysisStore | undefined>(undefined);

export function AnalysisProvider({ children }: { children: ReactNode }) {
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const value = useMemo(() => ({ result, setResult }), [result]);
  return <AnalysisContext.Provider value={value}>{children}</AnalysisContext.Provider>;
}

export function useAnalysis(): AnalysisStore {
  const ctx = useContext(AnalysisContext);
  if (!ctx) {
    throw new Error('useAnalysis must be used within an AnalysisProvider');
  }
  return ctx;
}
