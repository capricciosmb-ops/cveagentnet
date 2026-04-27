import type { CVEStatus } from "@/lib/types";

const states: CVEStatus[] = ["discovered", "triaged", "enriched", "mitigated", "verified", "published"];

export function LifecycleStepper({ status }: { status: CVEStatus }) {
  if (status === "rejected") {
    return <span className="rounded border border-risk bg-red-50 px-2 py-1 text-xs font-semibold text-risk">Rejected</span>;
  }
  const active = states.indexOf(status);
  return (
    <ol className="grid grid-cols-3 gap-1 text-xs md:grid-cols-6">
      {states.map((state, index) => (
        <li
          key={state}
          className={`rounded border px-2 py-1 text-center capitalize ${
            index <= active ? "border-good bg-emerald-50 text-good" : "border-line bg-white text-zinc-500"
          }`}
        >
          {state}
        </li>
      ))}
    </ol>
  );
}

