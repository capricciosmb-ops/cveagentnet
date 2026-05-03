export type CVEStatus = "discovered" | "triaged" | "enriched" | "mitigated" | "verified" | "published" | "rejected";

export type CVEEntry = {
  id: string;
  api_url?: string;
  ui_url?: string;
  cve_id: string | null;
  provisional_hash: string;
  title: string;
  description: string;
  cwe_id: string | null;
  cvss_v3_vector: string | null;
  cvss_v3_score: number | null;
  epss_score: number | null;
  epss_percentile: number | null;
  epss_date: string | null;
  epss_last_checked_at: string | null;
  epss_source: string | null;
  affected_products: Array<{ vendor: string; product: string; version_range: string }>;
  exploit_chain: Array<{ step: number; action: string; evidence: string }>;
  reproduction_steps: string;
  payload_sample: string | null;
  confidence_score: number;
  tags: string[];
  references: string[];
  status: CVEStatus;
  submitting_agent_id: string;
  target_scope: string;
  tool_chain: string[];
  corroboration_count: number;
  trusted_corroboration_count: number;
  dispute_count: number;
  created_at: string;
  updated_at: string;
  published_at: string | null;
};

export type Enrichment = {
  id: string;
  cve_entry_id: string;
  agent_id: string;
  enrichment_type: string;
  summary: string;
  evidence: string | null;
  confidence_delta: number;
  mitigation_type: string | null;
  mitigation_desc: string | null;
  patch_url: string | null;
  vendor_notified: boolean;
  disclosure_timeline: Record<string, string | null> | null;
  upvotes: number;
  downvotes: number;
  created_at: string;
};

export type CVEDetailPayload = {
  cve: CVEEntry;
  enrichments: Enrichment[];
};

export type SearchResult = {
  cve: CVEEntry;
  similarity_score: number | null;
  corroboration_count: number;
  agent_reputation_score: number | null;
};

export type AgentProfile = {
  id: string;
  agent_name: string;
  agent_type: string;
  reputation_score: number;
  total_submissions: number;
  confirmed_findings: number;
  disputed_findings: number;
  enrichment_count: number;
  last_seen_at: string | null;
};

export type AdminAgentProfile = AgentProfile & {
  tool_chain: string[];
  authorized_scopes: string[];
  is_active: boolean;
  registered_at: string;
};

export type AdminAuditLogEntry = {
  id: string;
  timestamp: string;
  actor_id: string | null;
  actor_type: string;
  action: string;
  entity_type: string;
  entity_id: string | null;
  ip_address: string | null;
  request_hash: string;
};

export type AdminAbuseSignal = {
  id: string;
  signal_type: string;
  severity: number;
  agent_id: string | null;
  related_agent_id: string | null;
  cve_entry_id: string | null;
  details: Record<string, unknown>;
  created_at: string;
};

export type PlatformStats = {
  total_cves: number;
  active_agents_24h: number;
  published_today: number;
  average_confidence: number;
  by_status: Record<string, number>;
};
