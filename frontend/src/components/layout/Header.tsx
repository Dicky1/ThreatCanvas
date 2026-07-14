import { User, Bell } from 'lucide-react';

/**
 * Komponen Header (Topbar) yang menampilkan status pengguna dan notifikasi.
 */
export default function Header() {
  return (
    <header className="h-16 bg-surface/80 backdrop-blur-md border-b border-gray-800 flex items-center justify-between px-8 sticky top-0 z-10">
      <div className="flex items-center">
        <h1 className="text-lg font-semibold text-gray-200">Cyber Engineering Workspace</h1>
      </div>
      
      <div className="flex items-center space-x-6">
        <button className="text-gray-400 hover:text-white transition-colors relative">
          <Bell className="w-5 h-5" />
          <span className="absolute -top-1 -right-1 w-2 h-2 bg-danger rounded-full"></span>
        </button>
        <div className="flex items-center space-x-3 pl-6 border-l border-gray-700">
          <div className="w-8 h-8 rounded-full bg-primary/20 flex items-center justify-center border border-primary/50">
            <User className="w-4 h-4 text-primary" />
          </div>
          <span className="text-sm font-medium text-gray-300">Lead Architect</span>
        </div>
      </div>
    </header>
  );
}