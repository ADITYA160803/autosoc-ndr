import { NavLink } from 'react-router-dom';
import { 
  LayoutDashboard, 
  TrendingUp, 
  Bell, 
  History, 
  Target, 
  Upload, 
  Settings,
  Shield
} from 'lucide-react';
import { useAnalysisStore } from '../../services/useAnalysisStore';

const navItems = [
  { path: '/dashboard', icon: LayoutDashboard, label: 'Dashboard', badge: false },
  { path: '/analytics', icon: TrendingUp, label: 'Analytics', badge: false },
  { path: '/alerts', icon: Bell, label: 'Alerts', badge: true, badgeCount: 0 },
  { path: '/campaigns', icon: Target, label: 'Campaigns', badge: false },
  { path: '/timeline', icon: History, label: 'Timeline', badge: false },
  { path: '/', icon: Upload, label: 'Processing', badge: false },
  { path: '/settings', icon: Settings, label: 'Settings', badge: false },
];

export default function Sidebar() {
  const { isProcessing, metrics } = useAnalysisStore();
  return (
    <aside className="fixed left-0 top-0 h-full w-64 glass-card rounded-none border-l-0 border-t-0 border-b-0 z-50">
      <div className="flex flex-col h-full">
        {/* Logo */}
        <div className="p-6 border-b border-white/10">
          <div className="flex items-center gap-3">
            <Shield className="w-8 h-8 text-purple-500" />
            <div>
              <h1 className="text-xl font-bold bg-gradient-to-r from-purple-500 to-cyan-500 bg-clip-text text-transparent">
                AutoSOC++
              </h1>
              <p className="text-xs text-gray-500">NDR + Threat Intel</p>
            </div>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-4 space-y-2">
          {navItems.map((item) => (
            <NavLink
              key={item.path}
              to={isProcessing ? '#' : item.path}
              onClick={(e) => isProcessing && e.preventDefault()}
              className={({ isActive }) =>
                `flex items-center justify-between px-4 py-3 rounded-lg transition-all duration-200 ${
                  isProcessing ? 'opacity-50 cursor-not-allowed text-gray-600' :
                  isActive
                    ? 'bg-purple-600/20 text-purple-400 border-r-2 border-purple-500 shadow-[inset_-10px_0_20px_rgba(139,92,246,0.05)]'
                    : 'text-gray-400 hover:bg-white/5 hover:text-white'
                }`
              }
            >
              <div className="flex items-center gap-3">
                <item.icon className={`w-5 h-5 ${isProcessing ? 'text-gray-700' : ''}`} />
                <span className="font-medium">{item.label}</span>
              </div>
              {item.badge && !isProcessing && (
                <span className="bg-red-600 text-white text-[10px] font-black px-1.5 py-0.5 rounded-md">
                  {item.label === 'Alerts' ? metrics.alerts : item.badgeCount}
                </span>
              )}
            </NavLink>
          ))}
        </nav>

        {/* System Status */}
        <div className="p-4 border-t border-white/10">
          <div className="flex items-center gap-2 text-sm">
            <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
            <span className="text-gray-400">System Online</span>
          </div>
          <div className="text-xs text-gray-600 mt-2">v2.0.0 | Sentinel Active</div>
        </div>
      </div>
    </aside>
  );
}
