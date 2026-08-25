import { useState } from 'react';
import { Shield, Activity, Settings, History, Radar, Workflow, FlaskConical, Users, ChevronLeft, ChevronRight, Info, BookOpen, Network } from 'lucide-react';
import { NavLink } from 'react-router-dom';

/**
 * Komponen Sidebar navigasi utama aplikasi.
 * Menggunakan NavLink untuk status aktif.
 */
export default function Sidebar({ mobileOpen = false, onClose }: { mobileOpen?: boolean; onClose?: () => void }) {
  const [collapsed, setCollapsed] = useState(false);
  const navItems = [
    { icon: Activity, label: 'Dashboard', path: '/' },
    { icon: Workflow, label: 'Threat Modeling', path: '/threat-modeling' },
    { icon: Network, label: 'Knowledge Graph', path: '/knowledge-graph' },
    { icon: Radar, label: 'Threat Intelligence', path: '/intelligence' },
    { icon: Users, label: 'Collective Defense', path: '/collective-defense' },
    { icon: FlaskConical, label: 'Research Metrics', path: '/research' },
    { icon: FlaskConical, label: 'Benchmark', path: '/benchmark' },
  ];
  const secondaryItems = [
    { icon: History, label: 'Scenarios', path: '/history' },
    { icon: BookOpen, label: 'Prompt Library', path: '/library' },
    { icon: Settings, label: 'Settings', path: '/settings' },
    { icon: Info, label: 'About / Research', path: '/about' },
  ];

  return (
    <aside className={`${collapsed ? 'md:w-[76px]' : 'md:w-64'} ${mobileOpen ? 'flex' : 'hidden'} md:flex fixed md:static inset-y-0 left-0 z-30 w-72 bg-surface border-r border-gray-800 h-screen flex-col transition-[width] duration-200`}>
      <div className="h-16 flex items-center justify-between px-5 border-b border-gray-800">
        <div className="flex items-center min-w-0">
        <Shield className="w-8 h-8 text-primary mr-3" />
        {!collapsed && <span className="text-xl font-bold tracking-wider text-white">ThreatCanvas</span>}
        </div>
        <button aria-label={collapsed ? 'Expand navigation' : 'Collapse navigation'} onClick={() => setCollapsed((value) => !value)} className="text-gray-500 hover:text-white">
          {collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
        </button>
      </div>
      
      <nav className="flex-1 py-5 px-3 space-y-1 overflow-y-auto">
        {!collapsed && <p className="px-3 pb-2 text-[10px] uppercase tracking-[0.18em] text-gray-600">Workspace</p>}
        {navItems.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            onClick={onClose}
            className={({ isActive }) =>
              `flex items-center px-3 py-2.5 rounded-md transition-colors ${collapsed ? 'justify-center' : ''} ${
                isActive 
                  ? 'bg-primary/10 text-primary border border-primary/20' 
                  : 'text-gray-400 hover:text-gray-100 hover:bg-gray-800'
              }`
            }
          >
            <item.icon className="w-[18px] h-[18px] shrink-0" />
            {!collapsed && <span className="font-medium ml-3 text-sm">{item.label}</span>}
          </NavLink>
        ))}
        {!collapsed && <p className="px-3 pt-6 pb-2 text-[10px] uppercase tracking-[0.18em] text-gray-600">Manage</p>}
        {secondaryItems.map((item) => (
          <NavLink key={item.path} to={item.path} onClick={onClose} title={collapsed ? item.label : undefined} className={({ isActive }) => `flex items-center px-3 py-2.5 rounded-md transition-colors ${collapsed ? 'justify-center' : ''} ${isActive ? 'bg-primary/10 text-primary border border-primary/20' : 'text-gray-400 hover:text-gray-100 hover:bg-gray-800'}`}>
            <item.icon className="w-[18px] h-[18px] shrink-0" />
            {!collapsed && <span className="font-medium ml-3 text-sm">{item.label}</span>}
          </NavLink>
        ))}
      </nav>

      <div className="p-3 border-t border-gray-800">
        <div className={`bg-gray-800/50 p-3 rounded-md ${collapsed ? 'flex justify-center' : ''}`}>
          {!collapsed && <p className="text-xs text-gray-400 mb-1">System Status</p>}
          <div className="flex items-center">
            <div className="w-2 h-2 bg-accent rounded-full mr-2 shadow-[0_0_8px_rgba(16,185,129,0.8)]"></div>
            {!collapsed && <span className="text-xs text-gray-200">Engine Online</span>}
          </div>
        </div>
      </div>
    </aside>
  );
}
