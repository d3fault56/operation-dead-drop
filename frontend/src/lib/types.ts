export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type ThreatLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "BENIGN";

export interface Finding {
  id: string;
  category: "url" | "impersonation" | "social_engineering";
  indicator: string;
  evidence: string;
  severity: Severity;
  detail: string;
}

export interface Investigation {
  operation_id: string;
  timestamp: string;
  input_type: "url" | "email" | "message";
  demo_id: string | null;
  engine: "claude" | "deterministic";
  model: string | null;
  ai_error: string | null;
  duration_ms: number;
  artifact: string;
  deterministic: {
    risk_score: number;
    findings: Finding[];
    social_engineering_categories: string[];
    indicators: {
      urls: string[];
      domains: string[];
      ip_addresses: string[];
      emails: string[];
      phone_numbers: string[];
      brands: string[];
      keywords: string[];
    };
  };
  threat_level: ThreatLevel;
  confidence: number;
  attack_type: string;
  summary: string;
  attacker_objective: string;
  social_engineering_tactics: { tactic: string; quote: string; explanation: string }[];
  evidence: { label: string; value: string; basis: "observed" | "inferred"; severity: Severity; explanation: string }[];
  attack_chain: { stage: string; detail: string; status: "observed" | "inferred" | "potential_impact" }[];
  mitre_techniques: { id: string; name: string; tactic: string; relevance: string }[];
  recommended_actions: { action: string; detail: string; priority: "immediate" | "if_exposed" | "preventive" }[];
  analyst_notes: string;
  grounding_corrections: string[];
  timeline: { t_ms: number; event: string; detail: string }[];
  external_verification: boolean;
}

export interface Demo {
  id: string;
  title: string;
  subtitle: string;
  content: string;
}
