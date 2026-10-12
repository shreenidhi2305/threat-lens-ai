import { useEffect, useRef } from 'react';

/**
 * Call `callback` every `intervalMs` while the tab is visible.
 *
 * Polling pauses when the tab is hidden and fires once immediately when the tab
 * becomes visible again, so background tabs stop hitting the API and the user
 * sees fresh data the moment they return.
 */
export function usePolling(callback: () => void, intervalMs: number, enabled = true): void {
  const latest = useRef(callback);
  useEffect(() => {
    latest.current = callback;
  });

  useEffect(() => {
    if (!enabled) return;
    let timer: number | undefined;

    const start = () => {
      if (timer === undefined) timer = window.setInterval(() => latest.current(), intervalMs);
    };
    const stop = () => {
      if (timer !== undefined) {
        window.clearInterval(timer);
        timer = undefined;
      }
    };
    const onVisibility = () => {
      if (document.hidden) {
        stop();
      } else {
        latest.current();
        start();
      }
    };

    if (!document.hidden) start();
    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      stop();
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [intervalMs, enabled]);
}