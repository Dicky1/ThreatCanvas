import { create } from 'zustand';
import { api } from '../api/client';

export type NotificationType = 'success' | 'error' | 'info';

export interface AppNotification {
  id: string;
  title: string;
  message: string;
  type: NotificationType;
  timestamp: number; // Date.now(), dipakai untuk hitung "X menit lalu"
  read: boolean;
}

interface NotificationState {
  notifications: AppNotification[];
  addNotification: (n: Omit<AppNotification, 'id' | 'timestamp' | 'read'>) => void;
  markAsRead: (id: string) => void;
  markAllAsRead: () => void;
  clearAll: () => void;
  hydrate: () => Promise<void>;
}

const MAX_NOTIFICATIONS = 20; // batasi supaya list tidak membengkak

export const useNotificationStore = create<NotificationState>((set) => ({
  notifications: [],

  addNotification: (n) => {
    const local = { ...n, id: crypto.randomUUID(), timestamp: Date.now(), read: false };
    set((state) => ({
      notifications: [
        local,
        ...state.notifications,
      ].slice(0, MAX_NOTIFICATIONS),
    }));
    void api.createNotification(n).catch(() => undefined);
  },

  markAsRead: (id) => {
    set((state) => ({
      notifications: state.notifications.map((n) =>
        n.id === id ? { ...n, read: true } : n
      ),
    }));
    void api.markNotificationRead(id).catch(() => undefined);
  },

  markAllAsRead: () =>
    set((state) => ({
      notifications: state.notifications.map((n) => ({ ...n, read: true })),
    })),

  clearAll: () => { set({ notifications: [] }); void api.clearNotifications().catch(() => undefined); },
  hydrate: async () => {
    try {
      const notifications = await api.notifications();
      set({ notifications: notifications.slice(0, MAX_NOTIFICATIONS) });
    } catch {
      // Backend history is optional; retain local notifications when offline.
    }
  },
}));

/**
 * Format timestamp jadi teks relatif ("5 menit lalu", "Kemarin", dst).
 * Dipakai di Header saat render, supaya waktunya selalu up-to-date.
 */
export function formatRelativeTime(timestamp: number): string {
  const diffMs = Date.now() - timestamp;
  const diffSec = Math.floor(diffMs / 1000);
  const diffMin = Math.floor(diffSec / 60);
  const diffHour = Math.floor(diffMin / 60);
  const diffDay = Math.floor(diffHour / 24);

  if (diffSec < 60) return 'Baru saja';
  if (diffMin < 60) return `${diffMin} menit lalu`;
  if (diffHour < 24) return `${diffHour} jam lalu`;
  if (diffDay === 1) return 'Kemarin';
  if (diffDay < 7) return `${diffDay} hari lalu`;

  return new Date(timestamp).toLocaleDateString('id-ID', {
    day: 'numeric',
    month: 'short',
  });
}
