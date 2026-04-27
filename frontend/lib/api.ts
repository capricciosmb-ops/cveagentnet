import type { AdminAbuseSignal, AdminAgentProfile, AdminAuditLogEntry, AgentProfile, CVEDetailPayload, PlatformStats, SearchResult } from "./types";

const PUBLIC_API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
const INTERNAL_API_URL = process.env.API_INTERNAL_URL ?? PUBLIC_API_URL;

function apiBaseUrl() {
  return typeof window === "undefined" ? INTERNAL_API_URL : PUBLIC_API_URL;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${apiBaseUrl()}${path}`, {
    ...init,
    headers: {
      "content-type": "application/json",
      ...(init?.headers ?? {})
    },
    cache: "no-store"
  });
  if (!response.ok) {
    throw new Error(`API request failed: ${response.status} ${response.statusText}`);
  }
  return response.json() as Promise<T>;
}

export async function getStats(): Promise<PlatformStats> {
  return request<PlatformStats>("/stats");
}

export async function searchCves(params: URLSearchParams): Promise<{ results: SearchResult[]; count: number }> {
  return request<{ results: SearchResult[]; count: number }>(`/cve/search?${params.toString()}`);
}

export async function getRecentCves(): Promise<SearchResult[]> {
  const params = new URLSearchParams({ status: "discovered", limit: "20", sort: "created_at" });
  const payload = await searchCves(params);
  return payload.results;
}

export async function getCve(id: string): Promise<CVEDetailPayload> {
  return request<CVEDetailPayload>(`/cve/${id}`);
}

export async function getLeaderboard(): Promise<AgentProfile[]> {
  return request<AgentProfile[]>("/agents/leaderboard");
}

export async function submitEnrichment(cveId: string, apiKey: string, body: unknown) {
  return request(`/cve/${cveId}/enrich`, {
    method: "POST",
    headers: { authorization: `Bearer ${apiKey}` },
    body: JSON.stringify(body)
  });
}

export async function getAdminAgents(adminKey: string): Promise<AdminAgentProfile[]> {
  return request<AdminAgentProfile[]>("/admin/agents", {
    headers: { authorization: `Bearer ${adminKey}` }
  });
}

export async function updateAdminAgent(agentId: string, adminKey: string, body: unknown): Promise<AdminAgentProfile> {
  return request<AdminAgentProfile>(`/admin/agents/${agentId}`, {
    method: "PATCH",
    headers: { authorization: `Bearer ${adminKey}` },
    body: JSON.stringify(body)
  });
}

export async function getAdminAuditLog(adminKey: string): Promise<AdminAuditLogEntry[]> {
  return request<AdminAuditLogEntry[]>("/admin/audit-log?limit=50", {
    headers: { authorization: `Bearer ${adminKey}` }
  });
}

export async function getAdminAbuseSignals(adminKey: string): Promise<AdminAbuseSignal[]> {
  return request<AdminAbuseSignal[]>("/admin/abuse-signals?limit=50", {
    headers: { authorization: `Bearer ${adminKey}` }
  });
}
