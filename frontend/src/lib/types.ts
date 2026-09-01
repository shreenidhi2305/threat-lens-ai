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
  notes: string[];
}
