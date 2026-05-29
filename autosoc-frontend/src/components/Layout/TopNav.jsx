import { Search, Bell, Moon, Sun } from 'lucide-react';
import { useState } from 'react';

export default function TopNav() {
  const [isDark, setIsDark] = useState(true);

  return (
    <header className="fixed top-0 right-0 left-64 h-16 glass-card rounded-none border-t-0 border-r-0 z-40">
      <div className="flex items-center justify-between h-full px-6">
        {/* Search */}
        <div className="relative w-96">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input
            type="text"
            placeholder="Search events, IOCs, campaigns..."
            className="w-full bg-gray-900/50 border border-gray-700 rounded-lg pl-10 pr-4 py-2 text-sm focus:outline-none focus:border-purple-500 transition-colors"
          />
        </div>

        {/* Right Section */}
        <div className="flex items-center gap-4">
          <button className="p-2 hover:bg-white/5 rounded-lg transition-colors relative">
            <Bell className="w-5 h-5 text-gray-400" />
            <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full"></span>
          </button>
          
          <button 
            onClick={() => setIsDark(!isDark)}
            className="p-2 hover:bg-white/5 rounded-lg transition-colors"
          >
            {isDark ? <Sun className="w-5 h-5 text-gray-400" /> : <Moon className="w-5 h-5 text-gray-400" />}
          </button>
          
          <div className="flex items-center gap-3 pl-4 border-l border-white/10">
            <div className="w-8 h-8 rounded-full bg-gradient-to-r from-purple-500 to-cyan-500 flex items-center justify-center">
              <span className="text-sm font-bold">SA</span>
            </div>
            <div className="text-sm">
              <div className="font-medium">Security Analyst</div>
              <div className="text-xs text-gray-500">Role: SOC L2</div>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
}
