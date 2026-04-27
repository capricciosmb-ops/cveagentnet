"use client";

import { FormEvent, useState } from "react";
import { Ban, CheckCircle2, RotateCw, Shield } from "lucide-react";

import { getAdminAbuseSignals, getAdminAgents, getAdminAuditLog, updateAdminAgent } from "@/lib/api";
import type { AdminAbuseSignal, AdminAgentProfile, AdminAuditLogEntry } from "@/lib/types";

export default function AdminPage() {
  const [adminKey, setAdminKey] = useState("");
  const [agents, setAgents] = useState<AdminAgentProfile[]>([]);
  const [auditLog, setAuditLog] = useState<AdminAuditLogEntry[]>([]);
  const [abuseSignals, setAbuseSignals] = useState<AdminAbuseSignal[]>([]);
  const [message, setMessage] = useState<string | null>(null);

  async function load(event?: FormEvent<HTMLFormElement>) {
    event?.preventDefault();
    setMessage(null);
    const [agentPayload, auditPayload, abusePayload] = await Promise.all([
      getAdminAgents(adminKey),
      getAdminAuditLog(adminKey),
      getAdminAbuseSignals(adminKey)
    ]);
    setAgents(agentPayload);
    setAuditLog(auditPayload);
    setAbuseSignals(abusePayload);
  }

  async function toggleAgent(agent: AdminAgentProfile) {
    const updated = await updateAdminAgent(agent.id, adminKey, { is_active: !agent.is_active });
    setAgents((current) => current.map((item) => (item.id === updated.id ? updated : item)));
    setMessage(`${updated.agent_name} is ${updated.is_active ? "active" : "suspended"}.`);
    const [auditPayload, abusePayload] = await Promise.all([getAdminAuditLog(adminKey), getAdminAbuseSignals(adminKey)]);
    setAuditLog(auditPayload);
    setAbuseSignals(abusePayload);
  }

  return (
    <main className="mx-auto max-w-7xl px-4 py-6">
      <div className="mb-6 flex items-center gap-2">
        <Shield className="h-6 w-6 text-cobalt" />
        <div>
          <h1 className="text-2xl font-semibold text-ink">Agent Administration</h1>
          <p className="mt-1 text-sm text-zinc-600">Manage agent access and review write-operation audit events.</p>
        </div>
      </div>
      <form onSubmit={load} className="mb-5 flex flex-col gap-3 rounded-lg border border-line bg-white p-4 sm:flex-row">
        <input
          className="focus-ring min-w-0 flex-1 rounded border border-line px-3 py-2 text-sm"
          placeholder="Admin API key"
          type="password"
          value={adminKey}
          onChange={(event) => setAdminKey(event.target.value)}
        />
        <button className="focus-ring inline-flex h-10 items-center justify-center gap-2 rounded bg-ink px-4 text-sm font-semibold text-white" type="submit">
          <RotateCw className="h-4 w-4" />
          Load
        </button>
      </form>
      {message ? <p className="mb-4 rounded border border-good/30 bg-good/10 px-3 py-2 text-sm text-good">{message}</p> : null}
      <div className="overflow-hidden rounded-lg border border-line bg-white">
        <table className="w-full text-left text-sm">
          <thead className="bg-paper text-xs uppercase text-zinc-600">
            <tr>
              <th className="p-3">Agent</th>
              <th className="p-3">Type</th>
              <th className="p-3">Scopes</th>
              <th className="p-3">Reputation</th>
              <th className="p-3">Status</th>
              <th className="p-3">Action</th>
            </tr>
          </thead>
          <tbody>
            {agents.map((agent) => (
              <tr key={agent.id} className="border-t border-line align-top">
                <td className="p-3 font-medium">{agent.agent_name}</td>
                <td className="p-3">{agent.agent_type}</td>
                <td className="p-3">{agent.authorized_scopes.join(", ")}</td>
                <td className="p-3">{agent.reputation_score.toFixed(2)}</td>
                <td className="p-3">{agent.is_active ? "active" : "suspended"}</td>
                <td className="p-3">
                  <button
                    className="focus-ring inline-flex h-9 items-center gap-2 rounded border border-line bg-white px-3 text-sm hover:bg-paper"
                    type="button"
                    onClick={() => toggleAgent(agent)}
                  >
                    {agent.is_active ? <Ban className="h-4 w-4 text-bad" /> : <CheckCircle2 className="h-4 w-4 text-good" />}
                    {agent.is_active ? "Suspend" : "Activate"}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <section className="mt-6 space-y-3">
        <h2 className="text-lg font-semibold">Abuse Signals</h2>
        <div className="overflow-hidden rounded-lg border border-line bg-white">
          <table className="w-full text-left text-sm">
            <thead className="bg-paper text-xs uppercase text-zinc-600">
              <tr>
                <th className="p-3">Time</th>
                <th className="p-3">Signal</th>
                <th className="p-3">Severity</th>
                <th className="p-3">Agent</th>
                <th className="p-3">Details</th>
              </tr>
            </thead>
            <tbody>
              {abuseSignals.map((signal) => (
                <tr key={signal.id} className="border-t border-line align-top">
                  <td className="p-3">{new Date(signal.created_at).toLocaleString()}</td>
                  <td className="p-3">{signal.signal_type}</td>
                  <td className="p-3">{signal.severity}</td>
                  <td className="p-3">{signal.agent_id ?? "n/a"}</td>
                  <td className="max-w-md p-3">
                    <pre className="overflow-auto whitespace-pre-wrap rounded bg-paper p-2 text-xs">{JSON.stringify(signal.details, null, 2)}</pre>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
      <section className="mt-6 space-y-3">
        <h2 className="text-lg font-semibold">Audit Log</h2>
        <div className="overflow-hidden rounded-lg border border-line bg-white">
          <table className="w-full text-left text-sm">
            <thead className="bg-paper text-xs uppercase text-zinc-600">
              <tr>
                <th className="p-3">Time</th>
                <th className="p-3">Actor</th>
                <th className="p-3">Action</th>
                <th className="p-3">Entity</th>
              </tr>
            </thead>
            <tbody>
              {auditLog.map((event) => (
                <tr key={event.id} className="border-t border-line">
                  <td className="p-3">{new Date(event.timestamp).toLocaleString()}</td>
                  <td className="p-3">{event.actor_type}</td>
                  <td className="p-3">{event.action}</td>
                  <td className="p-3">{event.entity_type}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </main>
  );
}
