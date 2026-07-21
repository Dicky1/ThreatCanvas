import { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { User, Bell, LogOut, CheckCircle2, XCircle, Info } from 'lucide-react';
import { useAuthStore } from '../../store/useAuthStore';
import { useNotificationStore, formatRelativeTime } from '../../store/useNotificationStore';

const TYPE_ICON = {
  success: CheckCircle2,
  error: XCircle,
  info: Info,
} as const;

const TYPE_COLOR = {
  success: 'text-success',
  error: 'text-danger',
  info: 'text-primary',
} as const;

/**
 * Komponen Header (Topbar) yang menampilkan status pengguna dan notifikasi.
 */
export default function Header() {
  const [isNotifOpen, setIsNotifOpen] = useState(false);
  const [isProfileOpen, setIsProfileOpen] = useState(false);

  const { user, logout } = useAuthStore();
  const { notifications, markAsRead, markAllAsRead } = useNotificationStore();
  const navigate = useNavigate();

  const notifRef = useRef<HTMLDivElement>(null);
  const profileRef = useRef<HTMLDivElement>(null);

  const unreadCount = notifications.filter((n) => !n.read).length;

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (notifRef.current && !notifRef.current.contains(event.target as Node)) {
        setIsNotifOpen(false);
      }
      if (profileRef.current && !profileRef.current.contains(event.target as Node)) {
        setIsProfileOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  function handleLogout() {
    logout();
    navigate('/login', { replace: true });
  }

  const displayName = user?.full_name || user?.username || 'Pengguna';
  const displayRole = user?.role || 'Lead Architect';

  return (
    <header className="h-16 bg-surface/80 backdrop-blur-md border-b border-gray-800 flex items-center justify-between px-8 sticky top-0 z-10">
      <div className="flex items-center">
        <h1 className="text-lg font-semibold text-gray-200">Cyber Engineering Workspace</h1>
      </div>

      <div className="flex items-center space-x-6">
        {/* Notifikasi -- diisi otomatis dari aktivitas nyata di aplikasi */}
        <div className="relative" ref={notifRef}>
          <button
            onClick={() => setIsNotifOpen((v) => !v)}
            className="text-gray-400 hover:text-white transition-colors relative"
          >
            <Bell className="w-5 h-5" />
            {unreadCount > 0 && (
              <span className="absolute -top-1 -right-1 w-2 h-2 bg-danger rounded-full"></span>
            )}
          </button>

          {isNotifOpen && (
            <div className="absolute right-0 mt-3 w-96 bg-surface border border-gray-800 rounded-lg shadow-xl overflow-hidden">
              <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800">
                <span className="text-sm font-semibold text-gray-200">Notifikasi</span>
                {unreadCount > 0 && (
                  <button
                    onClick={markAllAsRead}
                    className="text-xs text-primary hover:underline"
                  >
                    Tandai semua dibaca
                  </button>
                )}
              </div>

              <div className="max-h-96 overflow-y-auto">
                {notifications.length === 0 ? (
                  <p className="text-sm text-gray-500 px-4 py-8 text-center">
                    Belum ada aktivitas. Notifikasi akan muncul di sini saat kamu
                    memproses skenario, membuat artefak, atau menjalankan analisis coverage.
                  </p>
                ) : (
                  notifications.map((n) => {
                    const Icon = TYPE_ICON[n.type];
                    return (
                      <button
                        key={n.id}
                        onClick={() => markAsRead(n.id)}
                        className={`w-full text-left px-4 py-3 border-b border-gray-800 last:border-0 hover:bg-gray-800/50 transition-colors ${
                          !n.read ? 'bg-primary/5' : ''
                        }`}
                      >
                        <div className="flex items-start gap-2.5">
                          <Icon className={`w-4 h-4 mt-0.5 flex-shrink-0 ${TYPE_COLOR[n.type]}`} />
                          <div className="min-w-0">
                            <div className="flex items-center gap-1.5">
                              {!n.read && (
                                <span className="w-1.5 h-1.5 rounded-full bg-primary flex-shrink-0"></span>
                              )}
                              <p className="text-sm font-medium text-gray-200 truncate">
                                {n.title}
                              </p>
                            </div>
                            <p className="text-xs text-gray-400 mt-0.5">{n.message}</p>
                            <p className="text-xs text-gray-600 mt-1">
                              {formatRelativeTime(n.timestamp)}
                            </p>
                          </div>
                        </div>
                      </button>
                    );
                  })
                )}
              </div>
            </div>
          )}
        </div>

        {/* Profil */}
        <div className="relative pl-6 border-l border-gray-700" ref={profileRef}>
          <button
            onClick={() => setIsProfileOpen((v) => !v)}
            className="flex items-center space-x-3"
          >
            <div className="w-8 h-8 rounded-full bg-primary/20 flex items-center justify-center border border-primary/50">
              <User className="w-4 h-4 text-primary" />
            </div>
            <span className="text-sm font-medium text-gray-300">{displayName}</span>
          </button>

          {isProfileOpen && (
            <div className="absolute right-0 mt-3 w-64 bg-surface border border-gray-800 rounded-lg shadow-xl p-4 space-y-3">
              <div>
                <p className="text-sm font-medium text-gray-200">{displayName}</p>
                <p className="text-xs text-gray-500">{displayRole}</p>
                {user?.email && (
                  <p className="text-xs text-gray-600 mt-1">{user.email}</p>
                )}
              </div>

              <button
                onClick={handleLogout}
                className="w-full flex items-center justify-center gap-2 text-sm text-danger hover:bg-danger/10 rounded px-3 py-2 transition-colors border border-danger/30"
              >
                <LogOut className="w-4 h-4" />
                Keluar
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}