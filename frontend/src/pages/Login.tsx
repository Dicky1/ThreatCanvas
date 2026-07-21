import { useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldCheck, Loader2 } from 'lucide-react';
import { useAuthStore } from '../store/useAuthStore';

/**
 * Halaman login untuk ThreatCanvas.
 */
export default function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  const { login, isAuthenticating, error, clearError } = useAuthStore();
  const navigate = useNavigate();

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    clearError();

    const success = await login(username, password);
    if (success) {
      navigate('/', { replace: true });
    }
  }

  return (
    <div className="min-h-screen bg-background flex items-center justify-center px-4">
      <div className="w-full max-w-sm">
        <div className="flex flex-col items-center mb-8">
          <div className="w-12 h-12 rounded-lg bg-primary/20 border border-primary/50 flex items-center justify-center mb-4">
            <ShieldCheck className="w-6 h-6 text-primary" />
          </div>
          <h1 className="text-xl font-semibold text-gray-100">ThreatCanvas</h1>
          <p className="text-sm text-gray-500 mt-1">Cyber Engineering Workspace</p>
        </div>

        <form
          onSubmit={handleSubmit}
          className="bg-surface border border-gray-800 rounded-lg p-6 space-y-4"
        >
          <div>
            <label htmlFor="username" className="text-xs text-gray-500 block mb-1.5">
              Username
            </label>
            <input
              id="username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              autoFocus
              className="w-full bg-gray-800/60 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-primary transition-colors"
              placeholder="dicky"
            />
          </div>

          <div>
            <label htmlFor="password" className="text-xs text-gray-500 block mb-1.5">
              Password
            </label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="w-full bg-gray-800/60 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-primary transition-colors"
              placeholder="••••••••"
            />
          </div>

          {error && (
            <p className="text-xs text-danger bg-danger/10 border border-danger/30 rounded px-3 py-2">
              {error}
            </p>
          )}

          <button
            type="submit"
            disabled={isAuthenticating}
            className="w-full bg-primary hover:bg-primary/90 disabled:opacity-60 disabled:cursor-not-allowed text-white text-sm font-medium rounded px-3 py-2.5 transition-colors flex items-center justify-center gap-2"
          >
            {isAuthenticating ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Memproses...
              </>
            ) : (
              'Masuk'
            )}
          </button>
        </form>

        <p className="text-xs text-gray-600 text-center mt-6">
          ThreatCanvas AI &middot; Internal Security Workspace
        </p>
      </div>
    </div>
  );
}