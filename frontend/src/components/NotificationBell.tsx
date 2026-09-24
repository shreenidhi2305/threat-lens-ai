import { useEffect, useRef, useState } from 'react';

import {
  fetchNotifications,
  fetchUnreadCount,
  markAllNotificationsRead,
  markNotificationRead,
} from '../lib/api';
import type { AppNotification } from '../lib/types';
import { BellIcon } from '../ui/icons';
import { Spinner } from '../ui/primitives';

const POLL_MS = 20_000;

const SEVERITY_DOT: Record<string, string> = {
  critical: 'bg-risk-high',
  high: 'bg-risk-high',
  medium: 'bg-risk-medium',
  low: 'bg-risk-low',
  info: 'bg-muted',
};

function ago(iso: string): string {
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function NotificationBell() {
  const [open, setOpen] = useState(false);
  const [unread, setUnread] = useState(0);
  const [items, setItems] = useState<AppNotification[] | null>(null);
  const [loading, setLoading] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  const refreshCount = () => {
    fetchUnreadCount()
      .then((c) => setUnread(c.unread))
      .catch(() => undefined);
  };

  useEffect(() => {
    refreshCount();
    const id = window.setInterval(refreshCount, POLL_MS);
    return () => window.clearInterval(id);
  }, []);

  useEffect(() => {
    if (!open) return;
    const onClick = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onClick);
    return () => document.removeEventListener('mousedown', onClick);
  }, [open]);

  const toggle = () => {
    const next = !open;
    setOpen(next);
    if (next) {
      setLoading(true);
      fetchNotifications(false, 30)
        .then(setItems)
        .finally(() => setLoading(false));
    }
  };

  const readOne = async (id: string) => {
    setItems((prev) => prev?.map((n) => (n.id === id ? { ...n, read: true } : n)) ?? prev);
    setUnread((u) => Math.max(0, u - 1));
    try {
      await markNotificationRead(id);
    } catch {
      refreshCount();
    }
  };

  const readAll = async () => {
    setItems((prev) => prev?.map((n) => ({ ...n, read: true })) ?? prev);
    setUnread(0);
    try {
      await markAllNotificationsRead();
    } catch {
      refreshCount();
    }
  };

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={toggle}
        aria-label="Notifications"
        className="relative flex size-8 items-center justify-center rounded-md text-secondary transition-colors duration-150 ease-out hover:bg-surface-raised hover:text-text"
      >
        <BellIcon className="text-base" />
        {unread > 0 && (
          <span className="absolute right-1 top-1 grid min-w-3.5 place-items-center rounded-full bg-risk-high px-1 text-[0.6rem] font-semibold leading-none text-white">
            {unread > 9 ? '9+' : unread}
          </span>
        )}
      </button>

      {open && (
        <div className="tl-rise absolute right-0 z-20 mt-2 w-80 overflow-hidden rounded-lg border border-line bg-surface shadow-xl shadow-black/40">
          <div className="flex items-center justify-between border-b border-line-soft px-3 py-2.5">
            <span className="text-xs font-semibold uppercase tracking-[0.06em] text-muted">
              Notifications
            </span>
            {unread > 0 && (
              <button
                onClick={readAll}
                className="text-2xs font-medium text-accent hover:underline"
              >
                Mark all read
              </button>
            )}
          </div>
          <div className="max-h-96 overflow-y-auto">
            {loading ? (
              <div className="flex justify-center py-8">
                <Spinner />
              </div>
            ) : !items || items.length === 0 ? (
              <p className="px-3 py-6 text-center text-xs text-muted">No notifications yet.</p>
            ) : (
              items.map((n) => (
                <button
                  key={n.id}
                  onClick={() => !n.read && readOne(n.id)}
                  className={`flex w-full items-start gap-2.5 border-b border-line-soft px-3 py-2.5 text-left transition-colors duration-150 ease-out last:border-0 hover:bg-surface-raised ${
                    n.read ? 'opacity-60' : ''
                  }`}
                >
                  <span
                    className={`mt-1.5 size-1.5 shrink-0 rounded-full ${SEVERITY_DOT[n.severity] ?? 'bg-muted'}`}
                  />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-xs font-medium text-text">{n.title}</span>
                    <span className="mt-0.5 block truncate text-2xs text-secondary">{n.message}</span>
                    <span className="mt-0.5 block text-2xs text-muted">{ago(n.created_at)}</span>
                  </span>
                </button>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
