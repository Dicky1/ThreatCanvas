import { Navigate, Outlet } from 'react-router-dom';
import { useAuthStore } from '../store/useAuthStore';

/**
 * Wrapper route yang mengecek status login. Kalau belum login,
 * redirect ke /login. Kalau sudah, render halaman child-nya.
 */
export default function ProtectedRoute() {
  const token = useAuthStore((state) => state.token);

  if (!token) {
    return <Navigate to="/login" replace />;
  }

  return <Outlet />;
}