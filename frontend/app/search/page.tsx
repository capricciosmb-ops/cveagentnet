"use client";

import { Download } from "lucide-react";
import { useState } from "react";

import { CVECard } from "@/components/CVECard";
import { SearchBar } from "@/components/SearchBar";
import { searchCves } from "@/lib/api";
import type { SearchResult } from "@/lib/types";

function download(filename: string, content: string, type: string) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

export default function SearchPage() {
  const [results, setResults] = useState<SearchResult[]>([]);

  async function run(params: URLSearchParams) {
    const payload = await searchCves(params);
    setResults(payload.results);
  }

  function exportJsonLd() {
    download("cveagentnet-results.jsonld", JSON.stringify({ "@context": "https://cveagentnet.local/schema/jsonld_context.json", "@graph": results }, null, 2), "application/ld+json");
  }

  function exportCsv() {
    const lines = ["id,cve_id,title,status,confidence,cvss"];
    for (const result of results) {
      const cve = result.cve;
      lines.push([cve.id, cve.cve_id ?? "", `"${cve.title.replaceAll('"', '""')}"`, cve.status, cve.confidence_score, cve.cvss_v3_score ?? ""].join(","));
    }
    download("cveagentnet-results.csv", lines.join("\n"), "text/csv");
  }

  return (
    <main className="mx-auto max-w-7xl px-4 py-6">
      <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold text-ink">Hybrid Search</h1>
          <p className="mt-1 text-sm text-zinc-600">Semantic query with structured filters and exportable result sets.</p>
        </div>
        <div className="flex gap-2">
          <button className="focus-ring inline-flex items-center gap-2 rounded border border-line bg-white px-3 py-2 text-sm" onClick={() => download("cveagentnet-results.json", JSON.stringify(results, null, 2), "application/json")}>
            <Download className="h-4 w-4" />
            JSON
          </button>
          <button className="focus-ring rounded border border-line bg-white px-3 py-2 text-sm" onClick={exportCsv}>CSV</button>
          <button className="focus-ring rounded border border-line bg-white px-3 py-2 text-sm" onClick={exportJsonLd}>JSON-LD</button>
        </div>
      </div>
      <SearchBar onSearch={run} />
      <section className="mt-5 space-y-3">
        {results.map((result) => <CVECard key={result.cve.id} cve={result.cve} similarity={result.similarity_score} />)}
      </section>
    </main>
  );
}

