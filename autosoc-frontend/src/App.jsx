import React from 'react';
import { BrowserRouter, Navigate, NavLink, Route, Routes, useLocation } from 'react-router-dom';
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Clock,
  LayoutDashboard,
  Lock,
  Settings as SettingsIcon,
  Shield,
  Target,
  Upload,
} from 'lucide-react';

import { SessionProvider, useSession } from './context/SessionContext';
import ProcessingPage from './pages/ProcessingPage';
import Dashboard from './pages/Dashboard';
import Alerts from './pages/Alerts';
import Analytics from './pages/Analytics';
import Campaigns from './pages/Campaigns';
import Timeline from './pages/Timeline';
import Settings from './pages/Settings';

const navItems = [
  { path: '/processing', icon: Upload, label: 'Processing', alwaysEnabled: true },
  { path: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { path: '/alerts', icon: AlertTriangle, label: 'Alerts' },
  { path: '/analytics', icon: BarChart3, label: 'Analytics' },
  { path: '/campaigns', icon: Target, label: 'Campaigns' },
  { path: '/timeline', icon: Clock, label: 'Timeline' },
  { path: '/settings', icon: SettingsIcon, label: 'Settings', alwaysEnabled: true },
];

function Shell({ children }) {
  const location = useLocation();
  const { isProcessing, hasData, progress, activeFile } = useSession();

  return (
    <div className="min-h-screen bg-background text-slate-100">
      <aside className="fixed inset-y-0 left-0 z-40 hidden w-72 border-r border-border bg-[#08090b] xl:block">
        <div className="flex h-full flex-col">
          <div className="border-b border-border px-7 py-6">
            <div className="flex items-center gap-3">
              <div className="grid h-11 w-11 place-items-center rounded-lg border border-cyan-400/30 bg-cyan-400/10">
                <Shield className="h-6 w-6 text-cyan-300" />
              </div>
              <div>
                <div className="text-xl font-semibold tracking-tight text-white">AutoSOC</div>
                <div className="text-xs uppercase tracking-[0.24em] text-slate-500">NDR Console</div>
              </div>
            </div>
          </div>

          <nav className="flex-1 space-y-1 px-4 py-5">
            {navItems.map((item) => {
              const Icon = item.icon;
              const disabled = isProcessing && !item.alwaysEnabled;

              if (disabled) {
                return (
                  <div
                    key={item.path}
                    className="flex cursor-not-allowed items-center gap-3 rounded-lg px-3 py-3 text-sm font-medium text-slate-600"
                    title="Navigation is disabled while analysis is running"
                  >
                    <Icon className="h-4 w-4" />
                    <span>{item.label}</span>
                    <Lock className="ml-auto h-3.5 w-3.5" />
                  </div>
                );
              }

              return (
                <NavLink
                  key={item.path}
                  to={item.path}
                  className={({ isActive }) =>
                    [
                      'flex items-center gap-3 rounded-lg px-3 py-3 text-sm font-medium transition',
                      isActive
                        ? 'bg-cyan-400/10 text-cyan-200 ring-1 ring-cyan-400/20'
                        : 'text-slate-400 hover:bg-white/[0.04] hover:text-white',
                    ].join(' ')
                  }
                >
                  <Icon className="h-4 w-4" />
                  <span>{item.label}</span>
                </NavLink>
              );
            })}
          </nav>

          <div className="border-t border-border p-5">
            <div className="flex items-center gap-2 text-xs text-slate-500">
              <span className="h-2 w-2 rounded-full bg-emerald-400" />
              Backend target: localhost:5000
            </div>
            <div className="mt-4 rounded-lg border border-border bg-white/[0.03] p-4">
              <div className="flex items-center justify-between text-xs uppercase tracking-[0.18em] text-slate-500">
                <span>Session</span>
                <Activity className="h-4 w-4" />
              </div>
              <div className="mt-3 text-sm font-medium text-white">
                {isProcessing ? 'Processing PCAP' : hasData ? 'Analysis loaded' : 'No analysis data'}
              </div>
              <div className="mt-1 truncate text-xs text-slate-500">{activeFile || 'Upload a PCAP file to begin'}</div>
              {isProcessing && (
                <div className="mt-4 h-1.5 overflow-hidden rounded-full bg-slate-800">
                  <div className="h-full rounded-full bg-cyan-300 transition-all" style={{ width: `${progress}%` }} />
                </div>
              )}
            </div>
          </div>
        </div>
      </aside>

      <header className="sticky top-0 z-30 border-b border-border bg-background/95 px-4 py-3 backdrop-blur xl:hidden">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="h-6 w-6 text-cyan-300" />
            <span className="font-semibold text-white">AutoSOC</span>
          </div>
          <div className="text-xs text-slate-500">{isProcessing ? `${progress}%` : location.pathname}</div>
        </div>
        <div className="mt-3 flex gap-2 overflow-x-auto pb-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const disabled = isProcessing && !item.alwaysEnabled;
            return disabled ? (
              <span key={item.path} className="grid h-10 w-10 shrink-0 place-items-center rounded-lg text-slate-700">
                <Icon className="h-4 w-4" />
              </span>
            ) : (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) =>
                  [
                    'grid h-10 w-10 shrink-0 place-items-center rounded-lg transition',
                    isActive ? 'bg-cyan-400/10 text-cyan-200' : 'text-slate-500',
                  ].join(' ')
                }
              >
                <Icon className="h-4 w-4" />
              </NavLink>
            );
          })}
        </div>
      </header>

      <main className="xl:pl-72">
        <div className="mx-auto min-h-screen max-w-[1480px] px-4 py-6 sm:px-6 lg:px-8">{children}</div>
      </main>
    </div>
  );
}

function ProcessingGuard({ children }) {
  const { isProcessing } = useSession();
  if (isProcessing) return <Navigate to="/processing" replace />;
  return children;
}

function AppRoutes() {
  return (
    <Shell>
      <Routes>
        <Route path="/" element={<Navigate to="/processing" replace />} />
        <Route path="/processing" element={<ProcessingPage />} />
        <Route
          path="/dashboard"
          element={
            <ProcessingGuard>
              <Dashboard />
            </ProcessingGuard>
          }
        />
        <Route
          path="/alerts"
          element={
            <ProcessingGuard>
              <Alerts />
            </ProcessingGuard>
          }
        />
        <Route
          path="/analytics"
          element={
            <ProcessingGuard>
              <Analytics />
            </ProcessingGuard>
          }
        />
        <Route
          path="/campaigns"
          element={
            <ProcessingGuard>
              <Campaigns />
            </ProcessingGuard>
          }
        />
        <Route
          path="/timeline"
          element={
            <ProcessingGuard>
              <Timeline />
            </ProcessingGuard>
          }
        />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/processing" replace />} />
      </Routes>
    </Shell>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <SessionProvider>
        <AppRoutes />
      </SessionProvider>
    </BrowserRouter>
  );
}
