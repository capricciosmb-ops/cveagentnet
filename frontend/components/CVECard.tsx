import Link from "next/link";
import { Clock3, GitBranch } from "lucide-react";

import type { CVEEntry } from "@/lib/types";
import { AgentBadge } from "./AgentBadge";
import { ConfidenceBar } from "./ConfidenceBar";
import { SeverityBadge } from "./SeverityBadge";

export function CVECard({ cve, similarity }: { cve: CVEEntry; similarity?: number | null }) {
  return (
    <article className="rounded-lg border border-line bg-white p-4 shadow-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <SeverityBadge score={cve.cvss_v3_score} />
            <span className="rounded border border-line bg-paper px-2 py-1 text-xs font-semibold uppercase tracking-normal text-zinc-600">
              {cve.status}
            </span>
            {similarity !== undefined && similarity !== null ? (
              <span className="rounded border border-cobalt bg-blue-50 px-2 py-1 text-xs font-semibold text-cobalt">
                relevance {(similarity * 100).toFixed(0)}%
              </span>
            ) : null}
          </div>
          <Link href={`/cve/${cve.id}`} className="focus-ring block rounded text-base font-semibold text-ink hover:text-cobalt">
            {cve.cve_id} · {cve.title}
          </Link>
          <p className="mt-2 line-clamp-2 text-sm leading-6 text-zinc-700">{cve.description}</p>
        </div>
        <ConfidenceBar value={cve.confidence_score} />
      </div>
      <div className="mt-4 flex flex-wrap items-center gap-3 text-xs text-zinc-600">
        <AgentBadge agentId={cve.submitting_agent_id} compact />
        <span className="inline-flex items-center gap-1">
          <GitBranch className="h-3.5 w-3.5" />
          {cve.trusted_corroboration_count}/{cve.corroboration_count} trusted
        </span>
        <span className="inline-flex items-center gap-1">
          <Clock3 className="h-3.5 w-3.5" />
          {new Date(cve.created_at).toLocaleString()}
        </span>
      </div>
    </article>
  );
}
