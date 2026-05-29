import React, { useMemo, useState } from 'react';
import { AlertTriangle, Search, ShieldAlert } from 'lucide-react';
import EmptyState from '../components/EmptyState';
import { useSession } from '../context/SessionContext';

const severityClass = {
  CRITICAL: 'text-red-300 bg-red-500/10',
  HIGH: 'text-orange-300 bg-orange-500/10',
  MEDIUM: 'text-amber-300 bg-amber-500/10',
  LOW: 'text-blue-300 bg-blue-500/10',
};

function formatTime(timestamp) {
  if (!timestamp) return 'N/A';
  const numeric = Number(timestamp);
  if (!Number.isFinite(numeric)) return String(timestamp);
  return new Date(numeric * 1000).toLocaleString();
}

export default function Alerts() {
  const { hasData, analysisData } = useSession();
  const [query, setQuery] = useState('');

  const alerts = analysisData.alerts || [];
  const filteredAlerts = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return alerts;
    return alerts.filter((alert) =>
      [alert.rule, alert.src_ip, alert.dst_ip, alert.protocol, alert.severity, alert.reason]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(needle))
    );
  }, [alerts, query]);

  if (!hasData || alerts.length === 0) return <EmptyState />;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-white">Alerts</h1>
        <p className="mt-1 text-sm text-slate-500">{alerts.length.toLocaleString()} alert records from the current PCAP only</p>
      </div>

      <div className="relative">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
        <input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Search rule, IP, protocol, severity, or reason"
          className="w-full rounded-lg border border-border bg-surface px-10 py-3 text-sm text-white outline-none transition placeholder:text-slate-600 focus:border-cyan-300/50"
        />
      </div>

      <div className="overflow-hidden rounded-xl border border-border bg-surface/70">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[980px] text-left text-sm">
            <thead className="border-b border-border bg-white/[0.03] text-xs uppercase tracking-[0.16em] text-slate-500">
              <tr>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Time</th>
                <th className="px-4 py-3">Rule</th>
                <th className="px-4 py-3">Source</th>
                <th className="px-4 py-3">Destination</th>
                <th className="px-4 py-3">Risk</th>
                <th className="px-4 py-3">Reason</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filteredAlerts.slice(0, 250).map((alert, index) => {
                const severity = alert.severity || 'LOW';
                const Icon = severity === 'CRITICAL' || severity === 'HIGH' ? ShieldAlert : AlertTriangle;
                return (
                  <tr key={`${alert.timestamp || index}-${alert.src_ip || 'src'}-${alert.dst_ip || 'dst'}`} className="hover:bg-white/[0.03]">
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center gap-2 rounded-md px-2 py-1 text-xs font-semibold ${severityClass[severity] || severityClass.LOW}`}>
                        <Icon className="h-3.5 w-3.5" />
                        {severity}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-slate-400">{formatTime(alert.timestamp)}</td>
                    <td className="px-4 py-3 font-medium text-white">{alert.rule || 'Unknown'}</td>
                    <td className="px-4 py-3 font-mono text-slate-400">{alert.src_ip || 'N/A'}</td>
                    <td className="px-4 py-3 font-mono text-slate-400">{alert.dst_ip || 'N/A'}</td>
                    <td className="px-4 py-3 font-mono text-white">{Number(alert.risk_score || 0)}/100</td>
                    <td className="max-w-xl px-4 py-3 text-slate-400">{alert.reason || alert.explanation || 'No reason provided'}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
