import React from 'react';
import { NavLink } from 'react-router-dom';
import { 
  LayoutDashboard, 
  Bell, 
  BarChart3, 
  Target, 
  Clock, 
  Settings, 
  Upload,
  Shield
} from 'lucide-react';
import { useSession } from '../context/SessionContext';
import { clsx } from 'clsx';

const Sidebar = () => {
  const { isProcessing } = useSession();

  const navItems = [
    { to: '/', icon: Upload, label: 'Analysis' },
    { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
    { to: '/alerts', icon: Bell, label: 'Alerts' },
    { to: '/analytics', icon: BarChart3, label: 'Analytics' },
    { to: '/campaigns', icon: Target, label: 'Campaigns' },
    { to: '/timeline', icon: Clock, label: 'Timeline' },
    { to: '/settings', icon: Settings, label: 'Settings' },
  ];

  return (
    <aside className="w-64 glass border-r h-screen sticky top-0 flex flex-col">
      <div className="p-6 flex items-center gap-3">
        <div className="w-10 h-10 bg-primary rounded-xl flex items-center justify-center shadow-lg shadow-primary/20">
          <Shield className="text-white" size={24} />
        </div>
        <h1 className="text-xl font-bold tracking-tight text-white">AutoSOC</h1>
      </div>

      <nav className="flex-1 px-4 py-6 space-y-2">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) => clsx(
              "flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-200",
              isActive 
                ? "bg-primary/10 text-primary border border-primary/20 shadow-[0_0_15px_rgba(59,130,246,0.1)]" 
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50",
              isProcessing && item.to !== '/' && "opacity-50 pointer-events-none cursor-not-allowed"
            )}
          >
            <item.icon size={20} />
            <span className="font-medium">{item.label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="p-6 border-t border-border">
        <div className="flex items-center gap-3 px-2">
          <div className="w-2 h-2 rounded-full bg-success animate-pulse" />
          <span className="text-xs font-medium text-slate-500 uppercase tracking-wider">System Online</span>
        </div>
      </div>
    </aside>
  );
};

export default Sidebar;
