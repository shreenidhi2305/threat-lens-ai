import type { AnalysisResult } from './types';

const KEY = 'threatlens.history';
const LIMIT = 40;

export interface HistoryEntry {
  id: string;
  at: number;
  filename: string;
  sha256: string;
  size_bytes: number;
  score: number;
  level: AnalysisResult['risk']['level'];
  classification: string;
}

function read(): HistoryEntry[] {
  try {
    const raw = localStorage.getItem(KEY);
    return raw ? (JSON.parse(raw) as HistoryEntry[]) : [];
  } catch {
    return [];
  }
}

export function getHistory(): HistoryEntry[] {
  return read();
}

export function recordAnalysis(result: AnalysisResult): HistoryEntry {
  const entry: HistoryEntry = {
    id: `${result.hashes.sha256.slice(0, 12)}-${Date.now()}`,
    at: Date.now(),
    filename: result.object_path.split('/').pop() || result.object_path,
    sha256: result.hashes.sha256,
    size_bytes: result.metadata.size_bytes,
    score: result.risk.score,
    level: result.risk.level,
    classification: result.risk.classification,
  };
  try {
    localStorage.setItem(KEY, JSON.stringify([entry, ...read()].slice(0, LIMIT)));
  } catch {
    /* storage unavailable — history is a convenience, not critical */
  }
  return entry;
}

export function clearHistory(): void {
  try {
    localStorage.removeItem(KEY);
  } catch {
    /* ignore */
  }
}
