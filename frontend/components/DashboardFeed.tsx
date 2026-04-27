"use client";

import { useEffect, useState } from "react";
import { RefreshCw } from "lucide-react";

import { searchCves } from "@/lib/api";
import type { SearchResult } from "@/lib/types";
import { CVECard } from "./CVECard";

export function DashboardFeed({ initialResults }: { initialResults: SearchResult[] }) {
  const [results, setResults] = useState(initialResults);
  const [sort, setSort] = useState("created_at");
  const [status, setStatus] = useState("");

  useEffect(() => {
    const load = async () => {
      const params = new URLSearchParams({ limit: "20", sort });
      if (status) params.set("status", status);
      else params.set("min_conf", "0");
      const payload = await searchCves(params);
      setResults(payload.results);
    };
    load();
    const handle = window.setInterval(load, 30000);
    return () => window.clearInterval(handle);
  }, [sort, status]);

  return (
    <div className="grid gap-5 lg:grid-cols-[260px_1fr]">
      <aside className="rounded-lg border border-line bg-white p-4">
        <h2 className="mb-3 text-sm font-semibold uppercase text-zinc-600">Filters</h2>
        <div className="space-y-3">
          <select className="focus-ring w-full rounded border border-line px-3 py-2 text-sm" value={status} onChange={(event) => setStatus(event.target.value)}>
            <option value="">All statuses</option>
            <option value="discovered">Discovered</option>
            <option value="triaged">Triaged</option>
            <option value="enriched">Enriched</option>
            <option value="mitigated">Mitigated</option>
            <option value="verified">Verified</option>
            <option value="published">Published</option>
          </select>
          <select className="focus-ring w-full rounded border border-line px-3 py-2 text-sm" value={sort} onChange={(event) => setSort(event.target.value)}>
            <option value="created_at">Newest</option>
            <option value="cvss">Highest CVSS</option>
            <option value="corroboration">Most corroborated</option>
            <option value="confidence">Highest confidence</option>
          </select>
        </div>
      </aside>
      <section className="space-y-3">
        <div className="flex items-center gap-2 text-sm text-zinc-600">
          <RefreshCw className="h-4 w-4" />
          Polling every 30 seconds
        </div>
        {results.map((result) => <CVECard key={result.cve.id} cve={result.cve} similarity={result.similarity_score} />)}
      </section>
    </div>
  );
}

