"use client";

import { FormEvent, useState } from "react";
import { Search } from "lucide-react";

export function SearchBar({ onSearch }: { onSearch: (params: URLSearchParams) => void }) {
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("");
  const [minCvss, setMinCvss] = useState("");
  const [minConf, setMinConf] = useState("");

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const params = new URLSearchParams({ limit: "25" });
    if (q) params.set("q", q);
    if (status) params.set("status", status);
    if (minCvss) params.set("min_cvss", minCvss);
    if (minConf) params.set("min_conf", minConf);
    if (!q && !status && !minCvss && !minConf) params.set("status", "discovered");
    onSearch(params);
  }

  return (
    <form onSubmit={submit} className="grid gap-3 rounded-lg border border-line bg-white p-3 md:grid-cols-[1fr_150px_120px_120px_auto]">
      <input
        className="focus-ring rounded border border-line px-3 py-2 text-sm"
        placeholder="Semantic search"
        value={q}
        onChange={(event) => setQ(event.target.value)}
      />
      <select className="focus-ring rounded border border-line px-3 py-2 text-sm" value={status} onChange={(event) => setStatus(event.target.value)}>
        <option value="">Any status</option>
        <option value="discovered">Discovered</option>
        <option value="triaged">Triaged</option>
        <option value="enriched">Enriched</option>
        <option value="mitigated">Mitigated</option>
        <option value="verified">Verified</option>
        <option value="published">Published</option>
      </select>
      <input className="focus-ring rounded border border-line px-3 py-2 text-sm" placeholder="Min CVSS" value={minCvss} onChange={(event) => setMinCvss(event.target.value)} />
      <input className="focus-ring rounded border border-line px-3 py-2 text-sm" placeholder="Min conf" value={minConf} onChange={(event) => setMinConf(event.target.value)} />
      <button className="focus-ring inline-flex h-10 items-center justify-center gap-2 rounded bg-ink px-4 text-sm font-semibold text-white" type="submit">
        <Search className="h-4 w-4" />
        Search
      </button>
    </form>
  );
}

