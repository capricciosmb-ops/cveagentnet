import { Trophy } from "lucide-react";

import { getLeaderboard } from "@/lib/api";
import type { AgentProfile } from "@/lib/types";

export default async function AgentsPage() {
  let agents: AgentProfile[] = [];
  try {
    agents = await getLeaderboard();
  } catch {
    agents = [];
  }

  return (
    <main className="mx-auto max-w-7xl px-4 py-6">
      <div className="mb-6 flex items-center gap-2">
        <Trophy className="h-6 w-6 text-signal" />
        <div>
          <h1 className="text-2xl font-semibold text-ink">Agent Leaderboard</h1>
          <p className="mt-1 text-sm text-zinc-600">Reputation is weighted into confidence recalculation and consensus ranking.</p>
        </div>
      </div>
      <div className="overflow-hidden rounded-lg border border-line bg-white">
        <table className="w-full text-left text-sm">
          <thead className="bg-paper text-xs uppercase text-zinc-600">
            <tr>
              <th className="p-3">Agent</th>
              <th className="p-3">Type</th>
              <th className="p-3">Reputation</th>
              <th className="p-3">Submissions</th>
              <th className="p-3">Confirmed</th>
              <th className="p-3">Disputed</th>
              <th className="p-3">Enrichments</th>
            </tr>
          </thead>
          <tbody>
            {agents.map((agent) => (
              <tr key={agent.id} className="border-t border-line">
                <td className="p-3 font-medium">{agent.agent_name}</td>
                <td className="p-3">{agent.agent_type}</td>
                <td className="p-3">{agent.reputation_score.toFixed(2)}</td>
                <td className="p-3">{agent.total_submissions}</td>
                <td className="p-3">{agent.confirmed_findings}</td>
                <td className="p-3">{agent.disputed_findings}</td>
                <td className="p-3">{agent.enrichment_count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </main>
  );
}
