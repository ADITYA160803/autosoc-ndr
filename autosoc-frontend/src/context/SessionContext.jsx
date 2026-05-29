import React, { createContext, useCallback, useContext, useMemo, useState } from 'react';
import { api } from '../services/api';

const SessionContext = createContext(null);

const emptyMetrics = {
  packets: 0,
  flows: 0,
  ips: 0,
  domains: 0,
  urls: 0,
  alerts: 0,
  api_calls: 0,
  scan_rate: 0,
};

const emptyAnalysisData = {
  alerts: [],
  dashboard: null,
  analytics: null,
  campaigns: [],
  timeline: [],
};

const hasResponseData = (data) => {
  if (!data) return false;

  const dashboardTotal =
    Number(data.dashboard?.total_alerts || 0) +
    Number(data.dashboard?.aggregated_events || 0) +
    Number(data.dashboard?.active_campaigns || 0) +
    Number(data.dashboard?.critical_threats || 0);

  return Boolean(
    data.alerts?.length ||
      data.campaigns?.length ||
      data.timeline?.length ||
      Object.keys(data.analytics?.protocols || {}).length ||
      data.analytics?.top_talkers?.length ||
      dashboardTotal
  );
};

export function SessionProvider({ children }) {
  const [isProcessing, setIsProcessing] = useState(false);
  const [hasData, setHasData] = useState(false);
  const [progress, setProgress] = useState(0);
  const [phase, setPhase] = useState('idle');
  const [logs, setLogs] = useState([]);
  const [metrics, setMetrics] = useState(emptyMetrics);
  const [analysisData, setAnalysisData] = useState(emptyAnalysisData);
  const [activeFile, setActiveFile] = useState(null);
  const [error, setError] = useState('');

  const clearSessionData = useCallback(() => {
    setHasData(false);
    setProgress(0);
    setPhase('idle');
    setLogs([]);
    setMetrics(emptyMetrics);
    setAnalysisData(emptyAnalysisData);
    setActiveFile(null);
    setError('');
  }, []);

  const startNewSession = useCallback((fileName) => {
    setIsProcessing(true);
    setHasData(false);
    setProgress(0);
    setPhase('upload');
    setLogs([]);
    setMetrics(emptyMetrics);
    setAnalysisData(emptyAnalysisData);
    setActiveFile(fileName || null);
    setError('');
  }, []);

  const updateStatus = useCallback((status = {}) => {
    setProgress(Number(status.progress || 0));
    setPhase(status.phase || status.stage || 'processing');
    setLogs(Array.isArray(status.logs) ? status.logs : []);
    setMetrics({ ...emptyMetrics, ...(status.metrics || {}) });
  }, []);

  const completeSession = useCallback(async () => {
    const freshData = await api.getFreshAnalysisData();

    setAnalysisData(freshData);
    setHasData(hasResponseData(freshData));
    setProgress(100);
    setPhase('complete');
    setIsProcessing(false);

    return freshData;
  }, []);

  const failSession = useCallback((message = 'Analysis failed') => {
    setIsProcessing(false);
    setHasData(false);
    setAnalysisData(emptyAnalysisData);
    setProgress(0);
    setPhase('error');
    setError(message);
  }, []);

  const resetSession = useCallback(() => {
    setIsProcessing(false);
    clearSessionData();
  }, [clearSessionData]);

  const value = useMemo(
    () => ({
      isProcessing,
      hasData,
      progress,
      phase,
      logs,
      metrics,
      analysisData,
      activeFile,
      error,
      clearSessionData,
      startNewSession,
      updateStatus,
      completeSession,
      failSession,
      resetSession,
    }),
    [
      isProcessing,
      hasData,
      progress,
      phase,
      logs,
      metrics,
      analysisData,
      activeFile,
      error,
      clearSessionData,
      startNewSession,
      updateStatus,
      completeSession,
      failSession,
      resetSession,
    ]
  );

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession() {
  const context = useContext(SessionContext);
  if (!context) {
    throw new Error('useSession must be used within a SessionProvider');
  }
  return context;
}
