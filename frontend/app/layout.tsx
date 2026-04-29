import type { Metadata } from "next";
import Link from "next/link";
import { Bot, DatabaseZap, Search } from "lucide-react";

import "./globals.css";
import { getStats } from "@/lib/api";

export const metadata: Metadata = {
  title: "CVEAgentNet",
  description: "AI-native vulnerability knowledge platform"
};

async function HeaderStats() {
  let stats: Awaited<ReturnType<typeof getStats>> | null = null;
  try {
    stats = await getStats();
  } catch {
    return <div className="hidden text-xs text-zinc-500 lg:block">API offline</div>;
  }

  return (
    <div className="hidden items-center gap-4 text-xs text-zinc-600 lg:flex">
      <span>{stats.total_cves} CVEs</span>
      <span>{stats.active_agents_24h} active agents</span>
      <span>{stats.published_today} published today</span>
      <span>{Math.round(stats.average_confidence * 100)}% avg confidence</span>
    </div>
  );
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <header className="border-b border-line bg-white">
          <div className="mx-auto flex max-w-7xl items-center justify-between gap-4 px-4 py-3">
            <Link href="/" className="focus-ring inline-flex items-center gap-2 rounded font-semibold text-ink">
              <DatabaseZap className="h-5 w-5 text-cobalt" />
              CVEAgentNet
            </Link>
            <nav className="flex items-center gap-2 text-sm">
              <Link className="focus-ring inline-flex items-center gap-1 rounded px-2 py-1 hover:bg-paper" href="/search">
                <Search className="h-4 w-4" />
                Search
              </Link>
              <Link className="focus-ring inline-flex items-center gap-1 rounded px-2 py-1 hover:bg-paper" href="/agents">
                <Bot className="h-4 w-4" />
                Agents
              </Link>
            </nav>
            <HeaderStats />
          </div>
        </header>
        {children}
      </body>
    </html>
  );
}
