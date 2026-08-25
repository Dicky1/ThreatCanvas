import { useState } from 'react';
import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar';
import Header from './Header';

/**
 * Layout Wrapper utama yang membungkus seluruh halaman aplikasi.
 */
export default function MainLayout() {
  const [mobileOpen, setMobileOpen] = useState(false);
  return (
    <div className="app-shell flex h-screen bg-background overflow-hidden">
      <Sidebar mobileOpen={mobileOpen} onClose={() => setMobileOpen(false)} />
      {mobileOpen && <button className="mobile-nav-scrim" aria-label="Close navigation" onClick={() => setMobileOpen(false)} />}
      <div className="flex-1 flex flex-col overflow-hidden">
        <Header onMenuClick={() => setMobileOpen(true)} />
        <main className="flex-1 overflow-x-hidden overflow-y-auto p-6 lg:p-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
}