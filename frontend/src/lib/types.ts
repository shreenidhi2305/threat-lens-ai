export type UserRole =
  | 'Security Analyst'
  | 'SOC Team Member'
  | 'Administrator'
  | 'Researcher';

export interface UserProfile {
  id: string;
  email: string;
  role: UserRole;
}

export interface FileHashes {
  md5: string;
  sha1: string;
  sha256: string;
}

export interface FileMetadata {
  size_bytes: number;
  file_type: string;
  mime_type: string;
  magic_hex: string;
  extension: string | null;
  extension_matches_content: boolean | null;
  shannon_entropy: number;
  likely_packed: boolean;
  printable_ratio: number;
  likely_text: boolean;
}

export interface SignatureMatch {
  matched: boolean;
  name: string | null;
  type: string | null;
  severity: string | null;
}

export interface YaraMatch {
  rule: string;
  tags: string[];
  meta: Record<string, unknown>;
  matched_strings: string[];
}

export interface NetworkIndicators {
  urls: string[];
  ips: string[];
  domains: string[];
}

export type RiskLevel = 'low' | 'medium' | 'high';

export interface RiskAssessment {
  score: number;
  level: RiskLevel;
  classification: string;
  recommended_action: string;
}

export interface CategoryScore {
  category: string;
  probability: number;
}

export interface MLPrediction {
  available: boolean;
  applicable: boolean;
  malicious: boolean | null;
  malware_probability: number | null;
  category: string | null;
  category_confidence: number | null;
  top_categories: CategoryScore[];
  model_versions: Record<string, string | null>;
  reason: string | null;
}

export type Agreement = 'agree' | 'ml-only' | 'rules-only' | 'conflict';

export interface Verdict {
  label: 'malicious' | 'suspicious' | 'benign';
  score: number;
  level: RiskLevel;
  confidence: number;
  classification: string;
  family: string | null;
  recommended_action: string;
  agreement: Agreement;
  sources: Record<string, unknown>;
}

export interface AnalysisResult {
  object_path: string;
  sha256: string;
  md5: string;
  hashes: FileHashes;
  metadata: FileMetadata;
  signature_match: SignatureMatch;
  yara_matches: YaraMatch[];
  yara_available: boolean;
  network_indicators: NetworkIndicators;
  suspicious_indicators: string[];
  suspicious_strings: string[];
  strings_sample: string[];
  risk: RiskAssessment;
  ml: MLPrediction | null;
  verdict: Verdict | null;
  notes: string[];
}

export interface Detection {
  id: string;
  at: string;
  sha256: string;
  filename: string;
  verdict_label: string;
  score: number;
  level: RiskLevel;
  family: string | null;
  ml_probability: number | null;
  ml_category: string | null;
  yara_rule_count: number;
  signature: string | null;
  model_version: string | null;
  agreement: Agreement | null;
  analyst: string | null;
}
export interface Report {
  report_id: string;
  status: string;
  filename: string | null;
  sample_id: string | null;
  file_hash: string | null;
  predicted_class: string | null;
  confidence: number | null;
  is_malicious: boolean | null;
  risk_score: number | null;
  severity: string | null;
  static_indicators: string[];
  recommendation: string | null;
  timestamp: string | null;
}

export interface TimelineBucket {
  bucket: string;
  label: string;
  total: number;
  malicious: number;
  suspicious: number;
  benign: number;
}

export interface ThreatStats {
  total_detections: number;
  malicious: number;
  suspicious: number;
  benign: number;
  open_alerts: number;
  last_24h: number;
  detection_rate: number;
  by_level: Record<string, number>;
  by_verdict: Record<string, number>;
  by_agreement: Record<string, number>;
  by_family: { family: string; count: number }[];
  ml_only_catches: number;
  top_families: { family: string; count: number }[];
}

export interface ThreatSnapshot {
  total_detections: number;
  malicious: number;
  suspicious: number;
  benign: number;
  open_alerts: number;
  last_24h: number;
  top_families: { family: string; count: number }[];
}

export interface Alert {
  id: string;
  created_at: string;
  severity: 'high' | 'critical';
  status: 'open' | 'acknowledged' | 'resolved';
  title: string;
  sample_sha256: string;
  sample_name: string;
  verdict_label: string;
  verdict_score: number;
  category: string | null;
  agreement: Agreement | null;
  detection_id: string | null;
  incident_id: string | null;
  notified: boolean;
}

export interface AlertStats {
  open: number;
  acknowledged: number;
  resolved: number;
  critical_open: number;
  notifications_enabled: boolean;
}

export interface Incident {
  id: string;
  created_at: string;
  title: string;
  status: 'open' | 'contained' | 'closed';
  severity: string;
  alert_ids: string[];
}

export interface ModelInfo {
  detector: {
    version: string;
    trained_at: string;
    metrics: Record<string, unknown>;
    threshold: number;
  } | null;
  classifier: {
    version: string;
    trained_at: string;
    classes: string[];
    metrics: Record<string, unknown>;
  } | null;
  feature_count: number;
}
