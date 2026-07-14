import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import MainLayout from './components/layout/MainLayout';
import Dashboard from './pages/Dashboard';
import History from './pages/History';
import PromptLibrary from './pages/PromptLibrary';
import Settings from './pages/Settings'; // 1. Tambahkan import ini

/**
 * Entry point routing aplikasi React.
 */
export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<MainLayout />}>
          <Route index element={<Dashboard />} />
          <Route path="history" element={<History />} /> 
          <Route path="library" element={<PromptLibrary />} /> 
          <Route path="settings" element={<Settings />} /> 
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}