import React from 'react';
import { Inbox, Upload } from 'lucide-react';
import { Link } from 'react-router-dom';

export default function EmptyState({ compact = false }) {
  return (
    <div className={`grid place-items-center text-center ${compact ? 'py-12' : 'min-h-[62vh]'}`}>
      <div>
        <div className="mx-auto grid h-20 w-20 place-items-center rounded-xl border border-border bg-white/[0.03]">
          <Inbox className="h-9 w-9 text-slate-500" />
        </div>
        <h2 className="mt-6 text-2xl font-semibold text-white">📭 No Analysis Data</h2>
        <p className="mt-2 text-slate-400">Upload a PCAP file to begin</p>
        <Link
          to="/processing"
          className="mt-7 inline-flex items-center gap-2 rounded-lg bg-cyan-300 px-4 py-2.5 text-sm font-semibold text-slate-950 transition hover:bg-cyan-200"
        >
          <Upload className="h-4 w-4" />
          Go to Upload
        </Link>
      </div>
    </div>
  );
}
