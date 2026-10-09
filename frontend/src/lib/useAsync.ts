import { useCallback, useEffect, useRef, useState } from 'react';

interface AsyncState<T> {
  data: T | null;
  /** True only while there is no data yet (first load). Use this for full-page spinners. */
  loading: boolean;
  /** True while re-fetching with data already on screen (auto-refresh, filter change). */
  refreshing: boolean;
  error: string | null;
  reload: () => void;
}

/**
 * Run an async loader and track its state.
 *
 * - Stale-while-revalidate: once data has loaded it stays on screen during
 *   reloads, so auto-refresh no longer flashes the page back to a spinner.
 * - The loader receives an AbortSignal that is aborted when the component
 *   unmounts, the deps change, or a newer request starts, so slow responses
 *   never overwrite newer ones and abandoned requests are actually cancelled.
 */
export function useAsync<T>(
  fn: (signal: AbortSignal) => Promise<T>,
  deps: unknown[] = [],
): AsyncState<T> {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  const hasData = useRef(false);

  const reload = useCallback(() => setTick((t) => t + 1), []);

  useEffect(() => {
    const controller = new AbortController();
    if (hasData.current) setRefreshing(true);
    else setLoading(true);

    fn(controller.signal)
      .then((result) => {
        if (controller.signal.aborted) return;
        hasData.current = true;
        setData(result);
        setError(null);
      })
      .catch((e: unknown) => {
        if (controller.signal.aborted) return;
        setError(e instanceof Error ? e.message : 'Request failed');
      })
      .finally(() => {
        if (controller.signal.aborted) return;
        setLoading(false);
        setRefreshing(false);
      });

    return () => controller.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tick, ...deps]);

  return { data, loading, refreshing, error, reload };
}