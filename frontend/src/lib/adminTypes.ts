import type { UserRole } from './types';

// --- Milestone 4: administration, feedback and research -----------------------

export interface ManagedUser {
  id: string;
  email: string;
  role: UserRole;
  display_name: string | null;
  created_at: string | null;
  last_login: string | null;
}

export interface SettingField {
  key: string;
  label: string;
  group: string;
  description: string;
  type: 'choice' | 'int';
  value: string | number;
  default: string | number;
  overridden: boolean;
  choices?: string[];
  min?: number;
  max?: number;
}

export interface IntegrationStatus {
  id: string;
  name: string;
  description: string;
  configured: boolean;
  healthy: boolean | null;
  destination: string | null;
  detail: string | null;
  testable: boolean;
  stats: Record<string, unknown>;
}

export interface AuditEvent {
  id: string;
  at: string;
  actor: string | null;
  role: string | null;
  action: string;
  target: string | null;
  detail: string | null;
  status: string;
  ip: string | null;
}

export interface ModelRegistry {
  detector: {
    version: string;
    trained_at: string;
    threshold: number;
    metrics: Record<string, unknown>;
  } | null;
  classifier: {
    version: string;
    trained_at: string;
    classes: string[];
    metrics: Record<string, unknown>;
  } | null;
}

export interface PlatformOverview {
  version: string;
  environment: string;
  uptime_seconds: number;
  persistence: string;
  auth_mode: string;
  requests: {
    total_requests: number;
    by_status_class: Record<string, number>;
    rate_limited: number;
    slow_requests: number;
    avg_latency_ms: number;
    p95_latency_ms: number;
  };
  totals: Record<string, number>;
  models: ModelRegistry;
  audit_actions: Record<string, number>;
  warnings: string[];
}

export interface ConfusionCounts {
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  precision: number | null;
  recall: number | null;
  accuracy: number | null;
}

export interface FeedbackSummary {
  total: number;
  confirmed_malicious: number;
  confirmed_benign: number;
  agreement_rate: number | null;
  fused_verdict: ConfusionCounts;
  ml_detector: ConfusionCounts;
  retrain_recommended: boolean;
  retrain_reason: string;
  min_samples: number;
}

export interface FeedbackRecord {
  id: string;
  at: string;
  sha256: string;
  filename: string | null;
  label: 'malicious' | 'benign';
  model_verdict: string | null;
  model_score: number | null;
  ml_probability: number | null;
  note: string | null;
  actor: string | null;
  agrees: boolean;
}

export interface AdminModels {
  registry: ModelRegistry;
  feedback: FeedbackSummary;
}

export interface DatasetInfo {
  id: string;
  name: string;
  kind: 'training' | 'analysed' | 'feedback';
  description: string;
  source: string | null;
  license: string | null;
  records: number;
  stats: Record<string, unknown>;
  exportable: boolean;
  export_path: string | null;
  note: string | null;
}

export interface FamilySummary {
  family: string;
  samples: number;
  malicious: number;
  suspicious: number;
  avg_score: number;
  avg_ml_probability: number | null;
  ml_categories: Record<string, number>;
  signatures: string[];
  first_seen: string;
  last_seen: string;
}

export interface FamilyDetail extends FamilySummary {
  agreement: Record<string, number>;
  avg_yara_rules: number;
  recent_samples: {
    sha256: string;
    filename: string;
    verdict: string;
    score: number;
    ml_probability: number | null;
    agreement: string | null;
    at: string;
  }[];
}
