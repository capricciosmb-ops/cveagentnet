export function SeverityBadge({ score }: { score: number | null }) {
  const value = score ?? 0;
  const label = score === null ? "Unscored" : value >= 9 ? "Critical" : value >= 7 ? "High" : value >= 4 ? "Medium" : "Low";
  const color =
    score === null
      ? "border-line bg-white text-ink"
      : value >= 9
        ? "border-risk bg-red-50 text-risk"
        : value >= 7
          ? "border-orange-500 bg-orange-50 text-orange-700"
          : value >= 4
            ? "border-signal bg-amber-50 text-amber-800"
            : "border-good bg-emerald-50 text-good";

  return (
    <span className={`inline-flex h-7 items-center rounded border px-2 text-xs font-semibold ${color}`}>
      {label}
      {score !== null ? ` ${score.toFixed(1)}` : ""}
    </span>
  );
}

