import React from 'react';
import { Route, ShieldAlert, Target } from 'lucide-react';
import EmptyState from '../components/EmptyState';
import { useSession } from '../context/SessionContext';

const severityClass = {
  CRITICAL: 'border-red-500/30 text-red-200 bg-red-500/10',
  HIGH: 'border-orange-500/30 text-orange-200 bg-orange-500/10',
  MEDIUM: 'border-amber-500/30 text-amber-200 bg-amber-500/10',
  LOW: 'border-blue-500/30 text-blue-200 bg-blue-500/10',
};

export default function Campaigns() {
  const { hasData, analysisData } = useSession();
  const campaigns = analysisData.campaigns || [];

  if (!hasData || campaigns.length === 0) return <EmptyState />;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-white">Campaigns</h1>
        <p className="mt-1 text-sm text-slate-500">Linked attack chains from the current analysis session</p>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        {campaigns.map((campaign, index) => {
          const severity = campaign.severity || 'LOW';
          const affectedIps = Array.from(new Set(campaign.affected_ips || []));
          return (
            <article key={campaign.id || index} className="rounded-xl border border-border bg-surface/70 p-5">
              <div className="flex items-start justify-between gap-4">
                <div className="flex items-center gap-3">
                  <div className="grid h-10 w-10 place-items-center rounded-lg bg-cyan-300/10 text-cyan-200">
                    <Target className="h-5 w-5" />
                  </div>
                  <div>
                    <h2 className="font-mono text-lg font-semibold text-white">{campaign.id || `CAMP-${index + 1}`}</h2>
                    <p className="text-sm text-slate-500">{campaign.total_events || 0} linked event(s)</p>
                  </div>
                </div>
                <span className={`rounded-md border px-2 py-1 text-xs font-semibold ${severityClass[severity] || severityClass.LOW}`}>
                  {severity}
                </span>
              </div>

              <div className="mt-5 rounded-lg border border-border bg-black/20 p-4">
                <div className="flex items-center gap-2 text-sm font-semibold text-white">
                  <Route className="h-4 w-4 text-cyan-300" />
                  Attack Chain
                </div>
                <p className="mt-2 text-sm text-slate-400">{campaign.attack_chain || 'Unknown attack chain'}</p>
              </div>

              <div className="mt-4">
                <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-white">
                  <ShieldAlert className="h-4 w-4 text-cyan-300" />
                  Affected IPs
                </div>
                <div className="flex flex-wrap gap-2">
                  {affectedIps.length ? (
                    affectedIps.map((ip) => (
                      <span key={ip} className="rounded-md bg-white/[0.04] px-2 py-1 font-mono text-xs text-slate-300">
                        {ip}
                      </span>
                    ))
                  ) : (
                    <span className="text-sm text-slate-500">No affected IPs reported</span>
                  )}
                </div>
              </div>
            </article>
          );
        })}
      </div>
    </div>
  );
}
