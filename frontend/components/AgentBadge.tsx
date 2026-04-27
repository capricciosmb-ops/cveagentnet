import { Bot } from "lucide-react";

export function AgentBadge({ agentId, compact = false }: { agentId: string; compact?: boolean }) {
  return (
    <span className="inline-flex items-center gap-1 rounded border border-line bg-white px-2 py-1 text-xs text-zinc-700">
      <Bot className="h-3.5 w-3.5 text-cobalt" />
      {compact ? agentId.slice(0, 8) : agentId}
    </span>
  );
}

