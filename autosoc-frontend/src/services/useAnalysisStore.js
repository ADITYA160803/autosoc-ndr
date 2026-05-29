import { create } from 'zustand';

export const useAnalysisStore = create((set) => ({
  isProcessing: false,
  hasData: false,
  progress: 0,
  phase: 'idle',
  logs: [],
  metrics: {
    packets: 0,
    flows: 0,
    ips: 0,
    domains: 0,
    urls: 0,
    alerts: 0,
    api_calls: 0,
    scan_rate: 0,
  },
  
  startNewSession: () => set({
    isProcessing: true,
    hasData: false,
    progress: 0,
    phase: 'upload',
    logs: [],
    metrics: {
      packets: 0,
      flows: 0,
      ips: 0,
      domains: 0,
      urls: 0,
      alerts: 0,
      api_calls: 0,
      scan_rate: 0,
    },
  }),

  updateStatus: (statusData) => set({
    progress: statusData.progress || 0,
    phase: statusData.phase || 'processing',
    metrics: statusData.metrics || {},
    logs: statusData.logs || [],
  }),

  completeSession: () => set({
    isProcessing: false,
    hasData: true,
    phase: 'complete',
    progress: 100,
  }),

  resetSession: () => set({
    isProcessing: false,
    hasData: false,
    progress: 0,
    phase: 'idle',
    logs: [],
    metrics: {
      packets: 0,
      flows: 0,
      ips: 0,
      domains: 0,
      urls: 0,
      alerts: 0,
      api_calls: 0,
      scan_rate: 0,
    },
  }),
}));
