import { Shield, Activity, FileText, Settings, History } from 'lucide-react';
import { NavLink } from 'react-router-dom';

/**
 * Komponen Sidebar navigasi utama aplikasi.
 * Menggunakan NavLink untuk status aktif.
 */
export default function Sidebar() {
  const navItems = [
    { icon: Activity, label: 'Dashboard', path: '/' },
    { icon: History, label: 'History', path: '/history' },
    { icon: FileText, label: 'Prompt Library', path: '/library' },
    { icon: Settings, label: 'Settings', path: '/settings' },
  ];

  return (
    <aside className="w-64 bg-surface border-r border-gray-800 h-screen flex flex-col">
      <div className="h-16 flex items-center px-6 border-b border-gray-800">
        <Shield className="w-8 h-8 text-primary mr-3" />
        <span className="text-xl font-bold tracking-wider text-white">ThreatCanvas</span>
      </div>
      
      <nav className="flex-1 py-6 px-4 space-y-2">
        {navItems.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            className={({ isActive }) =>
              `flex items-center px-4 py-3 rounded-lg transition-colors ${
                isActive 
                  ? 'bg-primary/10 text-primary border border-primary/20' 
                  : 'text-gray-400 hover:text-gray-100 hover:bg-gray-800'
              }`
            }
          >
            <item.icon className="w-5 h-5 mr-3" />
            <span className="font-medium">{item.label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="p-4 border-t border-gray-800">
        <div className="bg-gray-800/50 p-4 rounded-lg">
          <p className="text-xs text-gray-400 mb-1">System Status</p>
          <div className="flex items-center">
            <div className="w-2 h-2 bg-accent rounded-full mr-2 shadow-[0_0_8px_rgba(16,185,129,0.8)]"></div>
            <span className="text-sm text-gray-200">Engine Online</span>
          </div>
        </div>
      </div>
    </aside>
  );
}