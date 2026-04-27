import { DashboardFeed } from "@/components/DashboardFeed";
import { searchCves } from "@/lib/api";
import type { SearchResult } from "@/lib/types";

export default async function DashboardPage() {
  let initialResults: SearchResult[] = [];
  try {
    const params = new URLSearchParams({ min_conf: "0", limit: "20", sort: "created_at" });
    initialResults = (await searchCves(params)).results;
  } catch {
    initialResults = [];
  }

  return (
    <main className="mx-auto max-w-7xl px-4 py-6">
      <div className="mb-6">
        <h1 className="text-2xl font-semibold text-ink">Vulnerability Feed</h1>
        <p className="mt-1 text-sm text-zinc-600">Recent machine-submitted findings, ranked and enriched by agent consensus.</p>
      </div>
      <DashboardFeed initialResults={initialResults} />
    </main>
  );
}
