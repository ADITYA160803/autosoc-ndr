import React from 'react';
import { AlertTriangle, Crosshair, Network, ShieldAlert } from 'lucide-react';
import EmptyState from '../components/EmptyState';
import { useSession } from '../context/SessionContext';

const severityStyles = {
  CRITICAL: 'text-red-300 bg-red-500/10 border-red-500/20',
  HIGH: 'text-orange-300 bg-orange-500/10 border-orange-500/20',
  MEDIUM: 'text-amber-300 bg-amber-500/10 border-amber-500/20',
  LOW: 'text-blue-300 bg-blue-500/10 border-blue-500/20',
};

function Stat({ label, value, icon: Icon }) {
  return (
    <div className="rounded-xl border border-border bg-surface/70 p-5">
      <div className="flex items-center justify-between">
        <span className="text-sm text-slate-500">{label}</span>
        <Icon className="h-5 w-5 text-cyan-300" />
      </div>
      <div className="mt-4 font-mono text-3xl font-semibold text-white">{Number(value || 0).toLocaleString()}</div>
    </div>
  );
}

export default function Dashboard() {
  const { hasData, analysisData, activeFile } = useSession();

  if (!hasData || !analysisData.dashboard) return <EmptyState />;

  const dashboard = analysisData.dashboard;
  const severityCounts = dashboard.severity_counts || {};

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-white">Dashboard</h1>
          <p className="mt-1 text-sm text-slate-500">Current PCAP session only{activeFile ? `: ${activeFile}` : ''}</p>
        </div>
        <div className="rounded-lg border border-emerald-400/20 bg-emerald-400/10 px-3 py-2 text-xs font-semibold uppercase tracking-[0.18em] text-emerald-200">
          Completed
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <Stat label="Total Alerts" value={dashboard.total_alerts} icon={AlertTriangle} />
        <Stat label="Aggregated Events" value={dashboard.aggregated_events} icon={ShieldAlert} />
        <Stat label="Active Campaigns" value={dashboard.active_campaigns} icon={Network} />
        <Stat label="Critical Threats" value={dashboard.critical_threats} icon={Crosshair} />
      </div>

      <section className="rounded-xl border border-border bg-surface/70 p-6">
        <h2 className="text-lg font-semibold text-white">Severity Breakdown</h2>
        <div className="mt-5 grid gap-3 sm:grid-cols-4">
          {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((severity) => (
            <div key={severity} className={`rounded-lg border p-4 ${severityStyles[severity]}`}>
              <div className="text-xs font-semibold uppercase tracking-[0.18em] opacity-80">{severity}</div>
              <div className="mt-2 font-mono text-3xl font-semibold">{Number(severityCounts[severity] || 0).toLocaleString()}</div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
