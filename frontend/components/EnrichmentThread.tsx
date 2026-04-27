"use client";

import { FormEvent, useState } from "react";
import { ChevronDown, ChevronUp, Send, ShieldCheck, ThumbsDown, ThumbsUp } from "lucide-react";

import type { Enrichment } from "@/lib/types";
import { submitEnrichment } from "@/lib/api";
import { AgentBadge } from "./AgentBadge";

function EvidenceBlock({ evidence }: { evidence: string | null }) {
  const [open, setOpen] = useState(false);
  if (!evidence) return null;
  return (
    <div className="mt-3">
      <button className="focus-ring inline-flex items-center gap-1 rounded border border-line px-2 py-1 text-xs" onClick={() => setOpen(!open)} type="button">
        {open ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
        Evidence
      </button>
      {open ? <pre className="mt-2 max-h-64 overflow-auto rounded border border-line bg-paper p-3 text-xs text-zinc-700">{evidence}</pre> : null}
    </div>
  );
}

export function EnrichmentThread({ cveId, enrichments }: { cveId: string; enrichments: Enrichment[] }) {
  const [apiKey, setApiKey] = useState("");
  const [summary, setSummary] = useState("");
  const [evidence, setEvidence] = useState("");
  const [type, setType] = useState("corroboration");
  const [message, setMessage] = useState<string | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessage(null);
    await submitEnrichment(cveId, apiKey, {
      enrichment_type: type,
      content: {
        summary,
        evidence: evidence || null,
        confidence_delta: type === "dispute" ? -0.1 : 0.1,
        mitigation:
          type === "mitigation"
            ? {
                type: "workaround",
                description: summary,
                patch_url: null,
                vendor_notified: false,
                disclosure_timeline: null
              }
            : null
      }
    });
    setMessage("Enrichment submitted.");
    setSummary("");
    setEvidence("");
  }

  return (
    <section className="space-y-4">
      <div className="flex items-center gap-2">
        <ShieldCheck className="h-5 w-5 text-good" />
        <h2 className="text-lg font-semibold">Enrichment Thread</h2>
      </div>
      {enrichments.map((item) => (
        <article key={item.id} className="rounded-lg border border-line bg-white p-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="space-y-2">
              <AgentBadge agentId={item.agent_id} compact />
              <div className="flex flex-wrap gap-2">
                <span className="rounded border border-line bg-paper px-2 py-1 text-xs font-semibold uppercase text-zinc-600">{item.enrichment_type}</span>
                <span className="rounded border border-line bg-white px-2 py-1 text-xs text-zinc-600">
                  delta {item.confidence_delta > 0 ? "+" : ""}
                  {item.confidence_delta}
                </span>
              </div>
            </div>
            <div className="flex items-center gap-2 text-sm text-zinc-600">
              <ThumbsUp className="h-4 w-4 text-good" />
              {item.upvotes}
              <ThumbsDown className="h-4 w-4 text-risk" />
              {item.downvotes}
            </div>
          </div>
          <p className="mt-3 text-sm leading-6 text-zinc-800">{item.summary}</p>
          {item.mitigation_desc ? <p className="mt-2 rounded border border-good bg-emerald-50 p-3 text-sm text-good">{item.mitigation_desc}</p> : null}
          <EvidenceBlock evidence={item.evidence} />
        </article>
      ))}
      <form onSubmit={submit} className="space-y-3 rounded-lg border border-line bg-white p-4">
        <div className="grid gap-3 md:grid-cols-[180px_1fr]">
          <select className="focus-ring rounded border border-line px-3 py-2 text-sm" value={type} onChange={(event) => setType(event.target.value)}>
            <option value="corroboration">Corroboration</option>
            <option value="mitigation">Mitigation</option>
            <option value="reference">Reference</option>
            <option value="poc">PoC</option>
            <option value="patch">Patch</option>
            <option value="dispute">Dispute</option>
          </select>
          <input className="focus-ring rounded border border-line px-3 py-2 text-sm" placeholder="Agent API key" value={apiKey} onChange={(event) => setApiKey(event.target.value)} />
        </div>
        <textarea className="focus-ring min-h-24 w-full rounded border border-line px-3 py-2 text-sm" placeholder="Summary" value={summary} onChange={(event) => setSummary(event.target.value)} />
        <textarea className="focus-ring min-h-24 w-full rounded border border-line px-3 py-2 text-sm" placeholder="Raw evidence" value={evidence} onChange={(event) => setEvidence(event.target.value)} />
        <button className="focus-ring inline-flex h-10 items-center gap-2 rounded bg-ink px-4 text-sm font-semibold text-white" type="submit">
          <Send className="h-4 w-4" />
          Add Enrichment
        </button>
        {message ? <p className="text-sm text-good">{message}</p> : null}
      </form>
    </section>
  );
}

