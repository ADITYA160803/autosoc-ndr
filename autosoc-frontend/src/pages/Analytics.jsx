import React from 'react';
import { BarChart3, Server } from 'lucide-react';
import EmptyState from '../components/EmptyState';
import { useSession } from '../context/SessionContext';

export default function Analytics() {
  const { hasData, analysisData } = useSession();
  const analytics = analysisData.analytics || {};
  const protocols = analytics.protocols || {};
  const topTalkers = analytics.top_talkers || [];
  const totalProtocolCount = Object.values(protocols).reduce((sum, value) => sum + Number(value || 0), 0);

  if (!hasData || (!Object.keys(protocols).length && !topTalkers.length)) return <EmptyState />;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-white">Analytics</h1>
        <p className="mt-1 text-sm text-slate-500">Traffic analytics generated from the current PCAP session</p>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <section className="rounded-xl border border-border bg-surface/70 p-6">
          <div className="flex items-center gap-2">
            <BarChart3 className="h-5 w-5 text-cyan-300" />
            <h2 className="text-lg font-semibold text-white">Protocol Distribution</h2>
          </div>
          <div className="mt-6 space-y-4">
            {Object.entries(protocols).map(([protocol, count]) => {
              const percent = totalProtocolCount ? Math.round((Number(count || 0) / totalProtocolCount) * 100) : 0;
              return (
                <div key={protocol}>
                  <div className="mb-2 flex items-center justify-between text-sm">
                    <span className="font-medium text-slate-300">{protocol}</span>
                    <span className="font-mono text-slate-500">{Number(count || 0).toLocaleString()} · {percent}%</span>
                  </div>
                  <div className="h-2 overflow-hidden rounded-full bg-slate-800">
                    <div className="h-full rounded-full bg-cyan-300" style={{ width: `${percent}%` }} />
                  </div>
                </div>
              );
            })}
          </div>
        </section>

        <section className="rounded-xl border border-border bg-surface/70 p-6">
          <div className="flex items-center gap-2">
            <Server className="h-5 w-5 text-cyan-300" />
            <h2 className="text-lg font-semibold text-white">Top Talkers</h2>
          </div>
          <div className="mt-6 space-y-4">
            {topTalkers.slice(0, 10).map((talker, index) => {
              const maxPackets = Number(topTalkers[0]?.packets || topTalkers[0]?.count || 1);
              const packetCount = Number(talker.packets || talker.count || 0);
              const percent = Math.min(100, Math.round((packetCount / maxPackets) * 100));
              return (
                <div key={`${talker.ip || index}-${index}`}>
                  <div className="mb-2 flex items-center justify-between text-sm">
                    <span className="font-mono text-slate-300">{talker.ip || talker.host || 'unknown'}</span>
                    <span className="font-mono text-slate-500">{packetCount.toLocaleString()}</span>
                  </div>
                  <div className="h-2 overflow-hidden rounded-full bg-slate-800">
                    <div className="h-full rounded-full bg-orange-300" style={{ width: `${percent}%` }} />
                  </div>
                </div>
              );
            })}
          </div>
        </section>
      </div>
    </div>
  );
}
