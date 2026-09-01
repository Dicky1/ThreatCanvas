import { create } from 'zustand';
import { api, TOKEN_KEY, USER_KEY } from '../api/client';

/**
 * Struktur data user yang dikembalikan backend (tanpa password)
 */
export interface AuthUser {
  id: string;
  username: string;
  email: string;
  full_name: string;
  role: string;
  is_active: boolean;
  created_at: string;
}

interface AuthState {
  token: string | null;
  user: AuthUser | null;
  isAuthenticating: boolean;
  error: string | null;

  login: (username: string, password: string) => Promise<boolean>;
  register: (payload: {
    username: string;
    email: string;
    full_name: string;
    password: string;
  }) => Promise<boolean>;
  logout: () => void;
  clearError: () => void;
}

// Hydrate dari localStorage saat store pertama kali dibuat,
// supaya user tetap login walau browser di-refresh.
function loadPersistedAuth(): { token: string | null; user: AuthUser | null } {
  try {
    const token = localStorage.getItem(TOKEN_KEY);
    const rawUser = localStorage.getItem(USER_KEY);
    return {
      token: token || null,
      user: rawUser ? JSON.parse(rawUser) : null,
    };
  } catch {
    return { token: null, user: null };
  }
}

export const useAuthStore = create<AuthState>((set) => ({
  ...loadPersistedAuth(),
  isAuthenticating: false,
  error: null,

  login: async (username: string, password: string) => {
    set({ isAuthenticating: true, error: null });

    try {
      const data = await api.login(username, password);

      localStorage.setItem(TOKEN_KEY, data.access_token);
      localStorage.setItem(USER_KEY, JSON.stringify(data.user));

      set({
        token: data.access_token,
        user: data.user as AuthUser,
        isAuthenticating: false,
      });

      return true;
    } catch (err: any) {
      set({
        error: err.message || 'Terjadi kesalahan saat login.',
        isAuthenticating: false,
      });
      return false;
    }
  },

  register: async (payload) => {
    set({ isAuthenticating: true, error: null });

    try {
      await api.register(payload);

      set({ isAuthenticating: false });
      return true;
    } catch (err: any) {
      set({
        error: err.message || 'Terjadi kesalahan saat registrasi.',
        isAuthenticating: false,
      });
      return false;
    }
  },

  logout: () => {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    set({ token: null, user: null });
  },

  clearError: () => set({ error: null }),
}));

// The API client dispatches this when a request comes back 401 (missing,
// expired, or otherwise invalid token). React by clearing auth state so
// ProtectedRoute redirects to /login instead of leaving the user stuck
// staring at failed requests.
window.addEventListener('tc:unauthorized', () => {
  useAuthStore.getState().logout();
});