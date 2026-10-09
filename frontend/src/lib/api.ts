import axios from 'axios';

import type {
  AdminModels,
  AuditEvent,
  DatasetInfo,
  FamilyDetail,
  FamilySummary,
  FeedbackRecord,
  FeedbackSummary,
  IntegrationStatus,
  ManagedUser,
  PlatformOverview,
  SettingField,
} from './adminTypes';
import type {
  Alert,
  AlertStats,
  AnalysisResult,
  AnalyticsSummary,
  AppNotification,
  BehaviorCatalog,
  BehavioralAnalysisResult,
  Detection,
  Incident,
  ModelInfo,
  NotificationCounts,
  Report,
  ReportRecord,
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

/** Default upload cap; the live value (admin-editable) comes from `fetchUploadLimit`. */
export const MAX_UPLOAD_BYTES = 32 * 1024 * 1024;

export const fetchUploadLimit = async (signal?: AbortSignal): Promise<number> =>
  (await api.get<{ max_upload_bytes: number }>('/files/limits', { signal })).data.max_upload_bytes;

export interface UploadOptions {
  /** Called with 0-100 while the file is being sent. */
  onProgress?: (percent: number) => void;
  signal?: AbortSignal;
}

export const uploadSample = async (
  file: File,
  { onProgress, signal }: UploadOptions = {},
): Promise<AnalysisResult> => {
  const form = new FormData();
  form.append('file', file);
  const { data } = await api.post<AnalysisResult>('/files/upload', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
    // Large files can take a while to scan; the default 30s timeout is too tight.
    timeout: 180_000,
    signal,
    onUploadProgress: (event) => {
      if (onProgress && event.total) onProgress(Math.round((event.loaded / event.total) * 100));
    },
  });
  return data;
};


export const downloadAnalysisPdf = async (result: AnalysisResult): Promise<Blob> =>
  (await api.post('/reports/pdf', result, { responseType: 'blob' })).data;

// --- Milestone 3: persisted per-scan threat prediction reports ------------

export const fetchReports = async (signal?: AbortSignal): Promise<Report[]> =>
  (await api.get<Report[]>('/reports', { signal })).data;

export const downloadPreviousReport = async (reportId: string): Promise<Blob> =>
  (await api.get(`/reports/${reportId}/pdf`, { responseType: 'blob' })).data;

// --- Milestone 3: behavioral analysis (MITRE ATT&CK) -----------------------

export const analyzeBehaviorDirect = async (file: File): Promise<BehavioralAnalysisResult> => {
  const form = new FormData();
  form.append('file', file);
  const { data } = await api.post<BehavioralAnalysisResult>('/behavior/analyze', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
  return data;
};

export const analyzeBehaviorFromResult = async (
  result: AnalysisResult,
): Promise<BehavioralAnalysisResult> =>
  (await api.post<BehavioralAnalysisResult>('/behavior/from-analysis', result)).data;

export const fetchBehaviorCatalog = async (signal?: AbortSignal): Promise<BehaviorCatalog> =>
  (await api.get<BehaviorCatalog>('/behavior/catalog', { signal })).data;

// --- Milestone 2: monitoring, alerts, model -------------------------------

export const fetchThreatSnapshot = async (signal?: AbortSignal): Promise<ThreatSnapshot> =>
  (await api.get<ThreatSnapshot>('/threats/snapshot', { signal })).data;

export const fetchDetections = async (
  limit = 100,
  filters: DetectionFilters = {},
  signal?: AbortSignal,
): Promise<Detection[]> =>
  (
    await api.get<Detection[]>('/threats/detections', {
      params: { limit, ...Object.fromEntries(Object.entries(filters).filter(([, v]) => v)) },
      signal,
    })
  ).data;

export const fetchThreatTimeline = async (
  window: string = '24h',
  signal?: AbortSignal,
): Promise<TimelineBucket[]> =>
  (await api.get<TimelineBucket[]>('/threats/timeline', { params: { window }, signal })).data;

export const fetchThreatStats = async (signal?: AbortSignal): Promise<ThreatStats> =>
  (await api.get<ThreatStats>('/threats/stats', { signal })).data;

export const fetchThreatFamilies = async (signal?: AbortSignal): Promise<string[]> =>
  (await api.get<string[]>('/threats/families', { signal })).data;

export interface ThreatReportParams extends DetectionFilters {
  window: string;
  threatsOnly: boolean;
}

export const downloadThreatReport = async (params: ThreatReportParams): Promise<Blob> =>
  (
    await api.get('/threats/report', {
      responseType: 'blob',
      params: {
        window: params.window,
        threats_only: params.threatsOnly,
        ...Object.fromEntries(
          Object.entries({
            level: params.level,
            verdict: params.verdict,
            family: params.family,
            q: params.q,
          }).filter(([, value]) => value),
        ),
      },
    })
  ).data;

export const fetchAlerts = async (status?: string, signal?: AbortSignal): Promise<Alert[]> =>
  (await api.get<Alert[]>('/alerts/', { params: status ? { status } : {}, signal })).data;

export const fetchAlertStats = async (signal?: AbortSignal): Promise<AlertStats> =>
  (await api.get<AlertStats>('/alerts/stats', { signal })).data;

export const fetchIncidents = async (signal?: AbortSignal): Promise<Incident[]> =>
  (await api.get<Incident[]>('/alerts/incidents', { signal })).data;

export const acknowledgeAlert = async (id: string): Promise<Alert> =>
  (await api.post<Alert>(`/alerts/${id}/acknowledge`)).data;

export const resolveAlert = async (id: string): Promise<Alert> =>
  (await api.post<Alert>(`/alerts/${id}/resolve`)).data;

export const updateIncidentStatus = async (
  id: string,
  status: Incident['status'],
): Promise<Incident> => (await api.patch<Incident>(`/alerts/incidents/${id}`, { status })).data;

export const createIncident = async (alertIds: string[], title?: string): Promise<Incident> =>
  (await api.post<Incident>('/alerts/incidents', { alert_ids: alertIds, title })).data;

export const fetchModelInfo = async (signal?: AbortSignal): Promise<ModelInfo> =>
  (await api.get<ModelInfo>('/malware/model', { signal })).data;

// --- Analytics dashboard ---------------------------------------------------

export const fetchAnalyticsSummary = async (signal?: AbortSignal): Promise<AnalyticsSummary> =>
  (await api.get<AnalyticsSummary>('/analytics/summary', { signal })).data;

export const fetchAnalyticsTimeline = async (
  window: string = '7d',
  signal?: AbortSignal,
): Promise<TimelineBucket[]> =>
  (await api.get<TimelineBucket[]>('/analytics/timeline', { params: { window }, signal })).data;

// --- Milestone 3: notification and reporting workflows --------------------

export const fetchNotifications = async (unreadOnly = false, limit = 50): Promise<AppNotification[]> =>
  (
    await api.get<AppNotification[]>('/notifications/', {
      params: { unread_only: unreadOnly, limit },
    })
  ).data;

export const fetchUnreadCount = async (signal?: AbortSignal): Promise<NotificationCounts> =>
  (await api.get<NotificationCounts>('/notifications/unread-count', { signal })).data;

export const markNotificationRead = async (id: string): Promise<AppNotification> =>
  (await api.post<AppNotification>(`/notifications/${id}/read`)).data;

export const markAllNotificationsRead = async (): Promise<{ marked: number }> =>
  (await api.post<{ marked: number }>('/notifications/read-all')).data;

export const fetchReportHistory = async (limit = 50, signal?: AbortSignal): Promise<ReportRecord[]> =>
  (await api.get<ReportRecord[]>('/reports/history', { params: { limit }, signal })).data;

export const downloadSummaryReport = async (window: string = '7d'): Promise<Blob> =>
  (await api.post('/reports/summary', null, { params: { window }, responseType: 'blob' })).data;

// --- Milestone 4: profile, administration, feedback and research -------------

export const updateProfile = async (displayName: string): Promise<UserProfile> =>
  (await api.patch<UserProfile>('/users/me', { display_name: displayName })).data;

export const fetchAdminOverview = async (signal?: AbortSignal): Promise<PlatformOverview> =>
  (await api.get<PlatformOverview>('/admin/overview', { signal })).data;

export const fetchAdminUsers = async (signal?: AbortSignal): Promise<ManagedUser[]> =>
  (await api.get<ManagedUser[]>('/admin/users', { signal })).data;

export const changeUserRole = async (userId: string, role: string): Promise<ManagedUser> =>
  (await api.patch<ManagedUser>(`/admin/users/${encodeURIComponent(userId)}/role`, { role })).data;

export const fetchAdminSettings = async (signal?: AbortSignal): Promise<SettingField[]> =>
  (await api.get<{ fields: SettingField[] }>('/admin/settings', { signal })).data.fields;

export const saveAdminSettings = async (
  values: Record<string, string | number>,
): Promise<SettingField[]> =>
  (await api.put<{ fields: SettingField[] }>('/admin/settings', { values })).data.fields;

export const resetAdminSettings = async (): Promise<SettingField[]> =>
  (await api.post<{ fields: SettingField[] }>('/admin/settings/reset')).data.fields;

export const fetchIntegrations = async (signal?: AbortSignal): Promise<IntegrationStatus[]> =>
  (await api.get<IntegrationStatus[]>('/admin/integrations', { signal })).data;

export const testIntegration = async (
  id: string,
): Promise<{ ok: boolean; error: string | null }> =>
  (await api.post<{ ok: boolean; error: string | null }>(`/admin/integrations/${id}/test`)).data;

export interface AuditFilters {
  action?: string;
  actor?: string;
  q?: string;
}

export const fetchAuditLog = async (
  filters: AuditFilters = {},
  limit = 100,
  signal?: AbortSignal,
): Promise<AuditEvent[]> =>
  (
    await api.get<AuditEvent[]>('/admin/audit', {
      params: { limit, ...Object.fromEntries(Object.entries(filters).filter(([, v]) => v)) },
      signal,
    })
  ).data;

export const fetchAdminModels = async (signal?: AbortSignal): Promise<AdminModels> =>
  (await api.get<AdminModels>('/admin/models', { signal })).data;

export const reloadModels = async (): Promise<void> => {
  await api.post('/admin/models/reload');
};

export const submitFeedback = async (
  sha256: string,
  label: 'malicious' | 'benign',
  note?: string,
): Promise<FeedbackRecord> =>
  (await api.post<FeedbackRecord>('/feedback', { sha256, label, note })).data;

export const fetchFeedback = async (limit = 200, signal?: AbortSignal): Promise<FeedbackRecord[]> =>
  (await api.get<FeedbackRecord[]>('/feedback', { params: { limit }, signal })).data;

export const fetchFeedbackSummary = async (signal?: AbortSignal): Promise<FeedbackSummary> =>
  (await api.get<FeedbackSummary>('/feedback/summary', { signal })).data;

export const fetchDatasets = async (signal?: AbortSignal): Promise<DatasetInfo[]> =>
  (await api.get<DatasetInfo[]>('/research/datasets', { signal })).data;

export const fetchFamilies = async (signal?: AbortSignal): Promise<FamilySummary[]> =>
  (await api.get<FamilySummary[]>('/research/families', { signal })).data;

export const fetchFamilyDetail = async (
  name: string,
  signal?: AbortSignal,
): Promise<FamilyDetail> =>
  (await api.get<FamilyDetail>(`/research/families/${encodeURIComponent(name)}`, { signal })).data;

/** Download an authenticated CSV endpoint (path is relative to the API base URL). */
export const downloadCsv = async (path: string): Promise<Blob> =>
  (await api.get(path, { responseType: 'blob' })).data;