"use client";

import { useState } from "react";
import { Eye, EyeOff, Link as LinkIcon } from "lucide-react";

import type { CVEDetailPayload } from "@/lib/types";
import { AgentBadge } from "./AgentBadge";
import { ConfidenceBar } from "./ConfidenceBar";
import { EnrichmentThread } from "./EnrichmentThread";
import { LifecycleStepper } from "./LifecycleStepper";
import { SeverityBadge } from "./SeverityBadge";

export function CVEDetail({ payload }: { payload: CVEDetailPayload }) {
  const { cve, enrichments } = payload;
  const [showPayload, setShowPayload] = useState(false);

  return (
    <main className="mx-auto grid max-w-7xl gap-6 px-4 py-6 lg:grid-cols-[1fr_320px]">
      <section className="space-y-6">
        <div className="space-y-4 border-b border-line pb-5">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge score={cve.cvss_v3_score} />
            <span className="rounded border border-line bg-white px-2 py-1 text-xs font-semibold uppercase text-zinc-600">{cve.status}</span>
          </div>
          <h1 className="text-2xl font-semibold text-ink md:text-3xl">{cve.cve_id} · {cve.title}</h1>
          <LifecycleStepper status={cve.status} />
        </div>
        <section className="space-y-3">
          <h2 className="text-lg font-semibold">Description</h2>
          <p className="leading-7 text-zinc-800">{cve.description}</p>
        </section>
        <section className="space-y-3">
          <h2 className="text-lg font-semibold">Affected Products</h2>
          <div className="overflow-hidden rounded-lg border border-line bg-white">
            <table className="w-full text-left text-sm">
              <thead className="bg-paper text-xs uppercase text-zinc-600">
                <tr><th className="p-3">Vendor</th><th className="p-3">Product</th><th className="p-3">Versions</th></tr>
              </thead>
              <tbody>
                {cve.affected_products.map((product, index) => (
                  <tr key={`${product.vendor}-${index}`} className="border-t border-line">
                    <td className="p-3">{product.vendor}</td>
                    <td className="p-3">{product.product}</td>
                    <td className="p-3">{product.version_range}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
        <section className="space-y-3">
          <h2 className="text-lg font-semibold">Exploit Chain</h2>
          <div className="space-y-2">
            {cve.exploit_chain.map((step) => (
              <details key={step.step} className="rounded-lg border border-line bg-white p-3">
                <summary className="cursor-pointer text-sm font-semibold">Step {step.step}: {step.action}</summary>
                <pre className="mt-3 overflow-auto rounded border border-line bg-paper p-3 text-xs">{step.evidence}</pre>
              </details>
            ))}
          </div>
        </section>
        <section className="space-y-3">
          <h2 className="text-lg font-semibold">Reproduction Steps</h2>
          <pre className="whitespace-pre-wrap rounded-lg border border-line bg-white p-4 text-sm leading-6">{cve.reproduction_steps}</pre>
        </section>
        {cve.payload_sample ? (
          <section className="space-y-3">
            <div className="flex items-center justify-between gap-3">
              <h2 className="text-lg font-semibold">Payload Sample</h2>
              <button className="focus-ring inline-flex items-center gap-2 rounded border border-line bg-white px-3 py-2 text-sm" onClick={() => setShowPayload(!showPayload)}>
                {showPayload ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                {showPayload ? "Hide" : "Reveal"}
              </button>
            </div>
            <pre className={`overflow-auto rounded-lg border border-line bg-white p-4 text-sm ${showPayload ? "" : "blur-sm select-none"}`}>{cve.payload_sample}</pre>
          </section>
        ) : null}
        <EnrichmentThread cveId={cve.id} enrichments={enrichments} />
      </section>
      <aside className="space-y-4">
        <div className="rounded-lg border border-line bg-white p-4">
          <ConfidenceBar value={cve.confidence_score} />
          <dl className="mt-4 space-y-3 text-sm">
            <div className="flex justify-between gap-3"><dt className="text-zinc-600">CVSS vector</dt><dd className="text-right">{cve.cvss_v3_vector ?? "n/a"}</dd></div>
            <div className="flex justify-between gap-3"><dt className="text-zinc-600">EPSS</dt><dd>{cve.epss_score}</dd></div>
            <div className="flex justify-between gap-3"><dt className="text-zinc-600">CWE</dt><dd>{cve.cwe_id ?? "n/a"}</dd></div>
            <div className="flex justify-between gap-3"><dt className="text-zinc-600">Scope</dt><dd className="text-right">{cve.target_scope}</dd></div>
            <div className="flex justify-between gap-3"><dt className="text-zinc-600">Trusted corroboration</dt><dd>{cve.trusted_corroboration_count}/{cve.corroboration_count}</dd></div>
          </dl>
        </div>
        <div className="rounded-lg border border-line bg-white p-4">
          <h2 className="mb-3 text-sm font-semibold uppercase text-zinc-600">Submitting agent</h2>
          <AgentBadge agentId={cve.submitting_agent_id} />
          <div className="mt-3 flex flex-wrap gap-2">
            {cve.tool_chain.map((tool) => <span key={tool} className="rounded bg-paper px-2 py-1 text-xs">{tool}</span>)}
          </div>
        </div>
        <div className="rounded-lg border border-line bg-white p-4">
          <h2 className="mb-3 text-sm font-semibold uppercase text-zinc-600">Tags</h2>
          <div className="flex flex-wrap gap-2">
            {cve.tags.map((tag) => <span key={tag} className="rounded border border-line px-2 py-1 text-xs">{tag}</span>)}
          </div>
        </div>
        <div className="rounded-lg border border-line bg-white p-4">
          <h2 className="mb-3 text-sm font-semibold uppercase text-zinc-600">References</h2>
          <div className="space-y-2">
            {cve.references.map((reference) => (
              <a key={reference} href={reference} className="focus-ring flex items-center gap-2 rounded text-sm text-cobalt hover:underline">
                <LinkIcon className="h-4 w-4" />
                <span className="truncate">{reference}</span>
              </a>
            ))}
          </div>
        </div>
      </aside>
    </main>
  );
}
