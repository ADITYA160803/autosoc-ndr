import React from 'react';
import { DatabaseZap, RotateCcw, Server, Shield } from 'lucide-react';
import { API_BASE_URL } from '../services/api';
import { useSession } from '../context/SessionContext';

export default function Settings() {
  const { resetSession, hasData, isProcessing } = useSession();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-white">Settings</h1>
        <p className="mt-1 text-sm text-slate-500">Runtime settings for the AutoSOC frontend session</p>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <section className="rounded-xl border border-border bg-surface/70 p-6">
          <div className="flex items-center gap-2">
            <Server className="h-5 w-5 text-cyan-300" />
            <h2 className="text-lg font-semibold text-white">Backend</h2>
          </div>
          <dl className="mt-5 divide-y divide-border text-sm">
            <div className="flex justify-between gap-4 py-3">
              <dt className="text-slate-500">API Base URL</dt>
              <dd className="font-mono text-slate-200">{API_BASE_URL}</dd>
            </div>
            <div className="flex justify-between gap-4 py-3">
              <dt className="text-slate-500">Upload Endpoint</dt>
              <dd className="font-mono text-slate-200">POST /upload</dd>
            </div>
            <div className="flex justify-between gap-4 py-3">
              <dt className="text-slate-500">Status Polling</dt>
              <dd className="font-mono text-slate-200">GET /status every 1s</dd>
            </div>
          </dl>
        </section>

        <section className="rounded-xl border border-border bg-surface/70 p-6">
          <div className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-cyan-300" />
            <h2 className="text-lg font-semibold text-white">Session Policy</h2>
          </div>
          <div className="mt-5 space-y-4 text-sm leading-6 text-slate-400">
            <p>Analysis data is kept only in React memory. Uploading a new PCAP clears alerts, dashboard data, analytics, campaigns, timeline, logs, and metrics before the backend upload starts.</p>
            <p>No analysis result is written to localStorage or reused between uploads.</p>
          </div>
          <button
            type="button"
            disabled={isProcessing}
            onClick={resetSession}
            className="mt-6 inline-flex items-center gap-2 rounded-lg border border-border px-4 py-2.5 text-sm font-semibold text-slate-300 transition hover:bg-white/[0.04] hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
          >
            <RotateCcw className="h-4 w-4" />
            Clear Frontend Session
          </button>
          <div className="mt-4 flex items-center gap-2 text-xs text-slate-500">
            <DatabaseZap className="h-4 w-4" />
            Current frontend state: {hasData ? 'analysis loaded' : 'empty'}
          </div>
        </section>
      </div>
    </div>
  );
}
