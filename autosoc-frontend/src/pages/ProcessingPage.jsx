import React, { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  AlertCircle,
  CheckCircle2,
  Database,
  FileCode2,
  FileText,
  Loader2,
  Play,
  RotateCcw,
  ShieldCheck,
  Terminal,
  Upload,
  X,
} from 'lucide-react';

import { useSession } from '../context/SessionContext';
import { api } from '../services/api';

function getUploadErrorMessage(err) {
  if (err?.response?.data?.error) return err.response.data.error;
  if (err?.code === 'ERR_NETWORK') {
    return 'Cannot reach backend at http://localhost:5000. Start the Flask backend, then run analysis again.';
  }
  return err?.message || 'Upload failed.';
}

const steps = [
  { id: 'upload', label: 'Upload', icon: Upload },
  { id: 'detection', label: 'Detection', icon: ShieldCheck },
  { id: 'enrichment', label: 'Enrichment', icon: Database },
  { id: 'complete', label: 'Complete', icon: CheckCircle2 },
];

const phaseOrder = ['idle', 'upload', 'parsing', 'session', 'extraction', 'detection', 'enrichment', 'correlation', 'scoring', 'complete'];

function Metric({ label, value }) {
  return (
    <div className="rounded-lg border border-border bg-white/[0.03] px-4 py-3">
      <div className="text-xs uppercase tracking-[0.18em] text-slate-500">{label}</div>
      <div className="mt-1 font-mono text-xl font-semibold text-white">{Number(value || 0).toLocaleString()}</div>
    </div>
  );
}

function normalizeLog(log, index) {
  if (typeof log === 'string') {
    return { time: String(index + 1).padStart(2, '0'), level: 'INFO', message: log };
  }
  return {
    time: log?.time || String(index + 1).padStart(2, '0'),
    level: log?.level || 'INFO',
    message: log?.message || JSON.stringify(log),
  };
}

export default function ProcessingPage() {
  const navigate = useNavigate();
  const pollingRef = useRef(null);
  const [selectedFile, setSelectedFile] = useState(null);
  const [localError, setLocalError] = useState('');

  const {
    isProcessing,
    hasData,
    progress,
    phase,
    logs,
    metrics,
    error,
    startNewSession,
    updateStatus,
    completeSession,
    failSession,
    resetSession,
  } = useSession();

  const stopPolling = () => {
    if (pollingRef.current) {
      clearInterval(pollingRef.current);
      pollingRef.current = null;
    }
  };

  const pollStatus = async () => {
    const status = await api.getStatus();
    updateStatus(status);

    const statusPhase = status.phase || status.stage;
    if (statusPhase === 'complete') {
      stopPolling();
      await completeSession();
      navigate('/dashboard');
    }

    if (statusPhase === 'error') {
      stopPolling();
      failSession('The backend reported an analysis error.');
    }
  };

  const startPolling = () => {
    stopPolling();
    pollStatus().catch(() => {});
    pollingRef.current = setInterval(() => {
      pollStatus().catch((err) => {
        stopPolling();
        failSession(err?.message || 'Could not read backend status.');
      });
    }, 1000);
  };

  const handleFileSelect = (event) => {
    const file = event.target.files?.[0];
    setLocalError('');

    if (!file) return;
    if (!file.name.toLowerCase().endsWith('.pcap')) {
      setSelectedFile(null);
      setLocalError('Select a valid .pcap file.');
      return;
    }

    setSelectedFile(file);
  };

  const startAnalysis = async () => {
    if (!selectedFile || isProcessing) return;

    startNewSession(selectedFile.name);
    setLocalError('');

    try {
      const response = await api.uploadPCAP(selectedFile);
      if (response?.success) {
        startPolling();
      } else {
        stopPolling();
        failSession(response?.error || response?.message || 'Upload failed.');
      }
    } catch (err) {
      stopPolling();
      failSession(getUploadErrorMessage(err));
    }
  };

  const resetUpload = () => {
    stopPolling();
    setSelectedFile(null);
    setLocalError('');
    resetSession();
  };

  useEffect(() => stopPolling, []);

  const currentIndex = phaseOrder.indexOf(phase);

  return (
    <div className="space-y-6">
      <section className="grid gap-6 lg:grid-cols-[minmax(0,0.95fr)_minmax(0,1.55fr)]">
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          className="rounded-xl border border-border bg-surface/70 p-6"
        >
          <div className="flex items-start justify-between gap-4">
            <div>
              <h1 className="text-2xl font-semibold text-white">PCAP Processing</h1>
              <p className="mt-2 text-sm leading-6 text-slate-400">
                Each upload starts a clean analysis session. Result pages stay empty until this run completes.
              </p>
            </div>
            <div className="grid h-11 w-11 place-items-center rounded-lg bg-cyan-300/10 text-cyan-200">
              <FileCode2 className="h-5 w-5" />
            </div>
          </div>

          <div className="mt-7 rounded-xl border border-dashed border-slate-700 bg-black/20 p-5">
            <input
              id="pcap-file"
              type="file"
              accept=".pcap"
              disabled={isProcessing}
              onChange={handleFileSelect}
              className="hidden"
            />
            <label
              htmlFor="pcap-file"
              className={[
                'flex min-h-44 cursor-pointer flex-col items-center justify-center rounded-lg text-center transition',
                isProcessing ? 'cursor-not-allowed opacity-50' : 'hover:bg-white/[0.03]',
              ].join(' ')}
            >
              <Upload className="h-9 w-9 text-slate-500" />
              <div className="mt-4 text-sm font-semibold text-white">
                {selectedFile ? selectedFile.name : 'Choose a PCAP file'}
              </div>
              <div className="mt-1 text-xs text-slate-500">
                {selectedFile ? `${(selectedFile.size / (1024 * 1024)).toFixed(2)} MB selected` : 'Upload a PCAP file to begin'}
              </div>
            </label>
          </div>

          {(localError || error) && (
            <div className="mt-4 flex items-start gap-3 rounded-lg border border-red-500/20 bg-red-500/10 p-3 text-sm text-red-200">
              <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
              <span>{localError || error}</span>
            </div>
          )}

          <div className="mt-6 flex gap-3">
            <button
              type="button"
              disabled={!selectedFile || isProcessing}
              onClick={startAnalysis}
              className="inline-flex flex-1 items-center justify-center gap-2 rounded-lg bg-cyan-300 px-4 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-200 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {isProcessing ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
              Start Analysis
            </button>
            <button
              type="button"
              disabled={isProcessing && progress > 0}
              onClick={resetUpload}
              className="grid h-12 w-12 place-items-center rounded-lg border border-border text-slate-400 transition hover:bg-white/[0.04] hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
              title="Reset upload"
            >
              <RotateCcw className="h-4 w-4" />
            </button>
          </div>

          <div className="mt-6 grid grid-cols-2 gap-3">
            <Metric label="Packets" value={metrics.packets} />
            <Metric label="Flows" value={metrics.flows} />
            <Metric label="IPs" value={metrics.ips} />
            <Metric label="Alerts" value={metrics.alerts} />
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.05 }}
          className="rounded-xl border border-border bg-surface/70 p-6"
        >
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <h2 className="text-lg font-semibold text-white">Analysis Status</h2>
              <p className="mt-1 text-sm text-slate-500">
                {isProcessing ? 'Polling /status every second' : hasData ? 'Latest session is ready' : 'No analysis data available'}
              </p>
            </div>
            <div className="text-left sm:text-right">
              <div className="font-mono text-3xl font-semibold text-cyan-200">{Math.min(100, progress)}%</div>
              <div className="text-xs uppercase tracking-[0.2em] text-slate-500">{phase}</div>
            </div>
          </div>

          <div className="mt-6 h-2 overflow-hidden rounded-full bg-slate-800">
            <div className="h-full rounded-full bg-cyan-300 transition-all duration-500" style={{ width: `${Math.min(100, progress)}%` }} />
          </div>

          <div className="mt-7 grid gap-3 sm:grid-cols-4">
            {steps.map((step) => {
              const Icon = step.icon;
              const stepIndex = phaseOrder.indexOf(step.id);
              const complete = currentIndex >= stepIndex && currentIndex !== -1;
              const active = phase === step.id || (step.id === 'detection' && isProcessing && currentIndex > 1 && currentIndex < phaseOrder.length - 1);

              return (
                <div
                  key={step.id}
                  className={[
                    'rounded-lg border p-4 transition',
                    active
                      ? 'border-cyan-300/40 bg-cyan-300/10 text-cyan-100'
                      : complete
                        ? 'border-emerald-400/20 bg-emerald-400/5 text-emerald-200'
                        : 'border-border bg-white/[0.02] text-slate-500',
                  ].join(' ')}
                >
                  <Icon className={active && isProcessing ? 'h-5 w-5 animate-pulse' : 'h-5 w-5'} />
                  <div className="mt-3 text-sm font-semibold">{step.label}</div>
                </div>
              );
            })}
          </div>

          <div className="mt-7 rounded-xl border border-border bg-[#050607]">
            <div className="flex items-center justify-between border-b border-border px-4 py-3">
              <div className="flex items-center gap-2 text-sm font-semibold text-white">
                <Terminal className="h-4 w-4 text-cyan-300" />
                Live Logs
              </div>
              {isProcessing && <Loader2 className="h-4 w-4 animate-spin text-cyan-300" />}
            </div>
            <div className="h-[320px] overflow-y-auto p-4 font-mono text-xs">
              {logs.length === 0 ? (
                <div className="flex h-full flex-col items-center justify-center text-slate-600">
                  <FileText className="mb-3 h-8 w-8" />
                  <span>No analysis logs yet</span>
                </div>
              ) : (
                <div className="space-y-2">
                  {logs.map((item, index) => {
                    const log = normalizeLog(item, index);
                    const tone =
                      log.level === 'ERROR'
                        ? 'text-red-300'
                        : log.level === 'SUCCESS'
                          ? 'text-emerald-300'
                          : log.level === 'WARNING'
                            ? 'text-amber-300'
                            : 'text-cyan-300';
                    return (
                      <div key={`${log.time}-${index}`} className="grid grid-cols-[4.75rem_5.25rem_minmax(0,1fr)] gap-2">
                        <span className="text-slate-600">{log.time}</span>
                        <span className={tone}>{log.level}</span>
                        <span className="min-w-0 break-words text-slate-400">{log.message}</span>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        </motion.div>
      </section>

      {!isProcessing && !hasData && (
        <div className="rounded-xl border border-border bg-white/[0.02] p-5 text-sm text-slate-400">
          <div className="flex items-center gap-2 font-semibold text-white">
            <X className="h-4 w-4 text-slate-500" />
            No analysis data available
          </div>
          <p className="mt-1">Upload a PCAP file to begin. Dashboard, alerts, analytics, campaigns, and timeline remain empty until processing completes.</p>
        </div>
      )}
    </div>
  );
}
