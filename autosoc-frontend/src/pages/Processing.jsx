import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { useSession } from '../context/SessionContext';
import { api } from '../services/api';
import {
  Upload, CheckCircle, Loader2, FileText,
  Database, Cpu, Shield, Globe, BarChart3, Clock,
  X, AlertCircle, Play, Trash2, Activity
} from 'lucide-react';

const pipelineSteps = [
  { id: 'upload', name: 'File Upload', icon: Upload },
  { id: 'parsing', name: 'Packet Parsing', icon: FileText },
  { id: 'session', name: 'Session Reconstruction', icon: Database },
  { id: 'extraction', name: 'Feature Extraction', icon: Cpu },
  { id: 'detection', name: 'Detection Engine', icon: Shield },
  { id: 'enrichment', name: 'Enrichment', icon: Globe },
  { id: 'correlation', name: 'Correlation', icon: BarChart3 },
  { id: 'scoring', name: 'Risk Scoring', icon: Clock },
];

const statusIcons = {
  pending: <div className="w-5 h-5 rounded-full border-2 border-gray-600"></div>,
  running: <Loader2 className="w-5 h-5 text-purple-500 animate-spin" />,
  completed: <CheckCircle className="w-5 h-5 text-green-500" />,
  error: <X className="w-5 h-5 text-red-500" />,
};

const MetricItem = ({ label, value, color = "text-white" }) => (
  <div className="bg-white/5 border border-white/10 rounded-xl p-4">
    <div className="text-[10px] uppercase tracking-widest text-gray-500 font-bold mb-1">{label}</div>
    <div className={`text-xl font-black font-mono ${color}`}>{value?.toLocaleString() || 0}</div>
  </div>
);

export default function ProcessingPage() {
  const navigate = useNavigate();
  const {
    isProcessing,
    progress,
    phase,
    logs,
    metrics,
    startNewSession,
    updateStatus,
    completeSession,
    resetSession
  } = useSession();

  const [selectedFile, setSelectedFile] = useState(null);
  const pollingRef = useRef(null);

  const startPolling = () => {
    if (pollingRef.current) clearInterval(pollingRef.current);

    pollingRef.current = setInterval(async () => {
      try {
        const data = await api.getStatus();
        updateStatus(data);

        if (data.phase === 'complete') {
          clearInterval(pollingRef.current);
          await completeSession();
          setTimeout(() => {
            navigate('/dashboard');
          }, 1500);
        } else if (data.phase === 'error') {
          clearInterval(pollingRef.current);
          resetSession();
        }
      } catch (err) {
        console.error('Polling error:', err);
      }
    }, 1000);
  };

  const handleFileSelect = (event) => {
    const file = event.target.files[0];
    if (file && file.name.endsWith('.pcap')) {
      setSelectedFile(file);
    } else {
      alert('Please select a valid .pcap file');
    }
  };

  const startAnalysis = async () => {
    if (!selectedFile) return;

    startNewSession();

    try {
      const data = await api.uploadPCAP(selectedFile);
      if (data.success) {
        startPolling();
      } else {
        console.error('Upload failed:', data);
        resetSession();
      }
    } catch (err) {
      console.error('Upload error:', err);
      resetSession();
    }
  };

  useEffect(() => {
    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current);
    };
  }, []);

  const getStepStatus = (stepId) => {
    if (phase === 'complete') return 'completed';
    if (phase === stepId) return 'running';

    const stepIndex = pipelineSteps.findIndex(s => s.id === stepId);
    const currentIndex = pipelineSteps.findIndex(s => s.id === phase);
    if (currentIndex > stepIndex) return 'completed';
    return 'pending';
  };

  return (
    <div className="max-w-7xl mx-auto space-y-8 pb-12">
      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }}>
        <h1 className="text-3xl font-bold bg-gradient-to-r from-white to-gray-400 bg-clip-text text-transparent">
          Analysis Command Center
        </h1>
        <p className="text-gray-500 mt-2 text-lg">Upload a PCAP file for fresh analysis session</p>
      </motion.div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Control Panel */}
        <div className="space-y-6">
          <div className="glass-card p-8">
            <h3 className="text-xl font-bold mb-6 flex items-center gap-2">
              <Upload className="w-5 h-5 text-purple-500" />
              Source Ingestion
            </h3>

            <div className={`relative border-2 border-dashed rounded-2xl p-10 text-center transition-all duration-300 ${selectedFile
              ? 'border-green-500/50 bg-green-500/5'
              : 'border-white/10 hover:border-purple-500/50 hover:bg-white/5'
              }`}>
              <AnimatePresence mode="wait">
                {selectedFile ? (
                  <motion.div key="selected" initial={{ scale: 0.9, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.9, opacity: 0 }}>
                    <div className="w-20 h-20 bg-green-500/20 rounded-full flex items-center justify-center mx-auto mb-4 border border-green-500/30">
                      <FileText className="w-10 h-10 text-green-500" />
                    </div>
                    <div className="font-bold text-lg text-white mb-1 truncate">{selectedFile.name}</div>
                    <div className="text-sm text-gray-400">{(selectedFile.size / (1024 * 1024)).toFixed(2)} MB</div>
                    <button
                      onClick={() => setSelectedFile(null)}
                      disabled={isProcessing}
                      className="mt-6 flex items-center gap-2 mx-auto text-red-400 hover:text-red-300 text-sm font-medium transition-colors disabled:opacity-50"
                    >
                      <Trash2 className="w-4 h-4" />
                      Discard File
                    </button>
                  </motion.div>
                ) : (
                  <motion.div key="empty" initial={{ scale: 0.9, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.9, opacity: 0 }}>
                    <div className="w-20 h-20 bg-white/5 rounded-full flex items-center justify-center mx-auto mb-4 border border-white/10">
                      <Upload className="w-10 h-10 text-gray-400" />
                    </div>
                    <div className="font-bold text-lg text-gray-300 mb-2">Drop PCAP File</div>
                    <div className="text-sm text-gray-500 mb-6">Support for standard .pcap captures</div>
                    <input type="file" accept=".pcap" onChange={handleFileSelect} className="hidden" id="pcap-upload" />
                    <label htmlFor="pcap-upload" className="inline-flex items-center gap-2 px-6 py-3 bg-white/10 rounded-xl cursor-pointer hover:bg-white/20 transition-all font-bold text-white border border-white/10">
                      Browse Files
                    </label>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>

            {selectedFile && !isProcessing && (
              <button
                onClick={startAnalysis}
                className="w-full mt-8 py-4 bg-gradient-to-r from-purple-600 to-cyan-600 rounded-xl font-bold text-lg hover:shadow-[0_0_30px_rgba(139,92,246,0.4)] transition-all flex items-center justify-center gap-3 active:scale-[0.98]"
              >
                <Play className="w-5 h-5 fill-current" />
                Start Analysis
              </button>
            )}

            {isProcessing && (
              <div className="w-full mt-8 py-4 bg-white/5 border border-white/10 rounded-xl flex items-center justify-center gap-3 text-gray-400">
                <Loader2 className="w-5 h-5 animate-spin text-purple-500" />
                Processing...
              </div>
            )}
          </div>

          {/* Metrics Panel */}
          <div className="glass-card p-6">
            <h3 className="text-lg font-bold mb-6 flex items-center gap-2">
              <Activity className="w-5 h-5 text-cyan-500" />
              Live Metrics
            </h3>
            <div className="grid grid-cols-2 gap-4">
              <MetricItem label="Packets" value={metrics.packets} />
              <MetricItem label="Flows" value={metrics.flows} color="text-cyan-400" />
              <MetricItem label="IPs" value={metrics.ips} />
              <MetricItem label="Alerts" value={metrics.alerts} color="text-red-400" />
              <MetricItem label="Domains" value={metrics.domains} />
              <MetricItem label="API Calls" value={metrics.api_calls} />
            </div>
            <div className="mt-6 pt-6 border-t border-white/5 flex items-center justify-between">
              <span className="text-xs text-gray-500 uppercase tracking-widest font-bold">Scan Rate</span>
              <span className="text-cyan-400 font-mono font-bold text-lg">{metrics.scan_rate?.toLocaleString()} <span className="text-xs text-gray-500">pps</span></span>
            </div>
          </div>
        </div>

        {/* Pipeline & Logs */}
        <div className="lg:col-span-2 space-y-6">
          {isProcessing && (
            <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="glass-card p-6 border-l-4 border-purple-500">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-purple-500/20 rounded-lg">
                    <Loader2 className="w-5 h-5 text-purple-500 animate-spin" />
                  </div>
                  <div>
                    <div className="text-sm text-gray-400 uppercase tracking-wider font-bold">Current Phase</div>
                    <div className="text-xl font-bold text-white capitalize">{phase.replace('_', ' ')}</div>
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-sm text-gray-400 uppercase tracking-wider font-bold">Progress</div>
                  <div className="text-2xl font-black text-purple-400 font-mono">{progress}%</div>
                </div>
              </div>
              <div className="w-full bg-white/5 rounded-full h-3 overflow-hidden p-1 border border-white/10">
                <div className="h-full rounded-full bg-gradient-to-r from-purple-500 via-cyan-500 to-purple-500 bg-[length:200%_100%] animate-[progress_2s_linear_infinite]" style={{ width: `${progress}%` }} />
              </div>
            </motion.div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Pipeline Steps */}
            <div className="glass-card p-6">
              <h3 className="text-lg font-bold mb-6 flex items-center gap-2">
                <Cpu className="w-5 h-5 text-purple-500" />
                Pipeline Sequence
              </h3>
              <div className="space-y-2">
                {pipelineSteps.map((step) => {
                  const status = getStepStatus(step.id);
                  return (
                    <div key={step.id} className={`flex items-center gap-3 p-3 rounded-xl transition-all border ${status === 'running' ? 'bg-purple-500/10 border-purple-500/50' :
                      status === 'completed' ? 'bg-green-500/5 border-transparent opacity-80' :
                        'bg-white/5 border-transparent opacity-40'
                      }`}>
                      <div className="flex-shrink-0">{statusIcons[status]}</div>
                      <div className={`flex-1 font-medium ${status === 'running' ? 'text-white' : 'text-gray-400'}`}>{step.name}</div>
                      {status === 'completed' && <CheckCircle className="w-4 h-4 text-green-500" />}
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Live Logs */}
            <div className="glass-card p-6 flex flex-col h-full">
              <h3 className="text-lg font-bold mb-6 flex items-center gap-2">
                <AlertCircle className="w-5 h-5 text-cyan-500" />
                Real-time Logs
              </h3>
              <div className="flex-1 bg-black/40 rounded-xl p-4 font-mono text-[11px] overflow-y-auto border border-white/5 max-h-[400px]">
                {logs.length === 0 && !isProcessing ? (
                  <div className="h-full flex flex-col items-center justify-center text-gray-600 gap-3">
                    <Database className="w-8 h-8 opacity-20" />
                    <span>Awaiting data stream...</span>
                  </div>
                ) : (
                  <div className="space-y-1.5">
                    {logs.map((log, idx) => (
                      <div key={idx} className="flex gap-2 leading-relaxed">
                        <span className="text-gray-600 shrink-0">[{log.time}]</span>
                        <span className={`shrink-0 font-bold ${log.level === 'ERROR' ? 'text-red-500' :
                          log.level === 'SUCCESS' ? 'text-green-500' :
                            log.level === 'WARNING' ? 'text-yellow-500' :
                              'text-cyan-500'
                          }`}>
                          {log.level}
                        </span>
                        <span className="text-gray-400">{log.message}</span>
                      </div>
                    ))}
                    <div ref={(el) => el?.scrollIntoView({ behavior: 'smooth' })} />
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}