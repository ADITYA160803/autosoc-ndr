import axios from 'axios';

export const API_BASE_URL = 'http://localhost:5000';

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
});

apiClient.interceptors.request.use((config) => {
  config.headers = {
    ...config.headers,
    'Cache-Control': 'no-cache, no-store, must-revalidate',
    Pragma: 'no-cache',
    Expires: '0',
  };

  if (config.method?.toLowerCase() === 'get') {
    config.params = {
      ...(config.params || {}),
      _: Date.now(),
    };
  }

  return config;
});

const unwrap = (response) => response.data;

export const api = {
  uploadPCAP: async (file) => {
    const formData = new FormData();
    formData.append('file', file);

    return axios
      .post(`${API_BASE_URL}/upload`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
          'Cache-Control': 'no-cache, no-store, must-revalidate',
        },
      })
      .then(unwrap);
  },

  getStatus: () => apiClient.get('/status').then(unwrap),
  getAlerts: () => apiClient.get('/api/alerts').then(unwrap),
  getDashboard: () => apiClient.get('/api/dashboard').then(unwrap),
  getAnalytics: () => apiClient.get('/api/analytics').then(unwrap),
  getCampaigns: () => apiClient.get('/api/campaigns').then(unwrap),
  getTimeline: () => apiClient.get('/api/timeline').then(unwrap),

  getFreshAnalysisData: async () => {
    const [alerts, dashboard, analytics, campaigns, timeline] = await Promise.all([
      api.getAlerts(),
      api.getDashboard(),
      api.getAnalytics(),
      api.getCampaigns(),
      api.getTimeline(),
    ]);

    return {
      alerts: Array.isArray(alerts) ? alerts : [],
      dashboard: dashboard && typeof dashboard === 'object' ? dashboard : null,
      analytics: analytics && typeof analytics === 'object' ? analytics : null,
      campaigns: Array.isArray(campaigns) ? campaigns : [],
      timeline: Array.isArray(timeline) ? timeline : [],
    };
  },
};

export default api;
