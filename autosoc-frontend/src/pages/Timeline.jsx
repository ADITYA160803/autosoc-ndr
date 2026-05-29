import React from 'react';
import { Clock, RadioTower } from 'lucide-react';
import EmptyState from '../components/EmptyState';
import { useSession } from '../context/SessionContext';

function formatTime(event) {
  if (event.time) return event.time;
  const timestamp = Number(event.timestamp);
  if (!Number.isFinite(timestamp)) return 'N/A';
  return new Date(timestamp * 1000).toLocaleString();
}

export default function Timeline() {
  const { hasData, analysisData } = useSession();
  const events = analysisData.timeline || [];

  if (!hasData || events.length === 0) return <EmptyState />;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-white">Timeline</h1>
        <p className="mt-1 text-sm text-slate-500">Chronological reconstruction for the current PCAP session</p>
      </div>

      <div className="relative ml-3 border-l border-border pl-6">
        {events.slice(0, 150).map((event, index) => (
          <article key={`${event.timestamp || event.time || index}-${index}`} className="relative pb-5">
            <div className="absolute -left-[34px] top-1 grid h-4 w-4 place-items-center rounded-full border border-cyan-300/40 bg-background">
              <div className="h-1.5 w-1.5 rounded-full bg-cyan-300" />
            </div>
            <div className="rounded-xl border border-border bg-surface/70 p-5">
              <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                <div>
                  <div className="flex items-center gap-2 text-sm font-semibold text-white">
                    <RadioTower className="h-4 w-4 text-cyan-300" />
                    {event.rule || event.event_type || event.type || 'Security Event'}
                  </div>
                  <p className="mt-2 text-sm leading-6 text-slate-400">{event.reason || event.description || 'No details provided'}</p>
                  {(event.src_ip || event.dst_ip) && (
                    <p className="mt-3 font-mono text-xs text-slate-500">
                      {event.src_ip || 'N/A'} to {event.dst_ip || 'N/A'}
                    </p>
                  )}
                </div>
                <div className="flex items-center gap-2 font-mono text-xs text-slate-500">
                  <Clock className="h-3.5 w-3.5" />
                  {formatTime(event)}
                </div>
              </div>
            </div>
          </article>
        ))}
      </div>
    </div>
  );
}
