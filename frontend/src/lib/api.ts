import axios from 'axios';

import type {
  Alert,
  AlertStats,
  AnalysisResult,
  Detection,
  Incident,
  ModelInfo,
  ThreatSnapshot,
  ThreatStats,
  TimelineBucket,
  UserProfile,
} from './types';

export interface DetectionFilters {
  level?: string;
  verdict?: string;
  family?: string;
  q?: string;
}

const TOKEN_KEY = 'threatlens.token';

export const getToken = (): string | null => localStorage.getItem(TOKEN_KEY);
export const setToken = (token: string): void => localStorage.setItem(TOKEN_KEY, token);
export const clearToken = (): void => localStorage.removeItem(TOKEN_KEY);

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000/api/v1',
  timeout: 30000,
});

api.interceptors.request.use((config) => {
  const token = getToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export interface LoginResponse {
  access_token: string;
  token_type: string;
}

export const login = async (email: string, password: string): Promise<string> => {
  const { data } = await api.post<LoginResponse>('/auth/login', { email, password });
  setToken(data.access_token);
  return data.access_token;
};

export const fetchProfile = async (): Promise<UserProfile> => {
  const { data } = await api.get<UserProfile>('/users/me');
  return data;
};

export const uploadSample = async (file: File): Promise<AnalysisResult> => {
  const form = new FormData();
  form.append('file', file);
  const { data } = await api.post<AnalysisResult>('/files/upload', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
  return data;
};

// --- Milestone 2: monitoring, alerts, model -------------------------------

export const fetchThreatSnapshot = async (): Promise<ThreatSnapshot> =>
  (await api.get<ThreatSnapshot>('/threats/snapshot')).data;

export const fetchDetections = async (
  limit = 100,
  filters: DetectionFilters = {},
): Promise<Detection[]> =>
  (
    await api.get<Detection[]>('/threats/detections', {
      params: { limit, ...Object.fromEntries(Object.entries(filters).filter(([, v]) => v)) },
    })
  ).data;

export const fetchThreatTimeline = async (window: string = '24h'): Promise<TimelineBucket[]> =>
  (await api.get<TimelineBucket[]>('/threats/timeline', { params: { window } })).data;

export const fetchThreatStats = async (): Promise<ThreatStats> =>
  (await api.get<ThreatStats>('/threats/stats')).data;

export const fetchThreatFamilies = async (): Promise<string[]> =>
  (await api.get<string[]>('/threats/families')).data;

export const fetchAlerts = async (status?: string): Promise<Alert[]> =>
  (await api.get<Alert[]>('/alerts/', { params: status ? { status } : {} })).data;

export const fetchAlertStats = async (): Promise<AlertStats> =>
  (await api.get<AlertStats>('/alerts/stats')).data;

export const fetchIncidents = async (): Promise<Incident[]> =>
  (await api.get<Incident[]>('/alerts/incidents')).data;

export const acknowledgeAlert = async (id: string): Promise<Alert> =>
  (await api.post<Alert>(`/alerts/${id}/acknowledge`)).data;

export const resolveAlert = async (id: string): Promise<Alert> =>
  (await api.post<Alert>(`/alerts/${id}/resolve`)).data;

export const createIncident = async (alertIds: string[], title?: string): Promise<Incident> =>
  (await api.post<Incident>('/alerts/incidents', { alert_ids: alertIds, title })).data;

export const fetchModelInfo = async (): Promise<ModelInfo> =>
  (await api.get<ModelInfo>('/malware/model')).data;
