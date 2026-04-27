export function ConfidenceBar({ value }: { value: number }) {
  const percent = Math.round(value * 100);
  return (
    <div className="min-w-32">
      <div className="mb-1 flex items-center justify-between text-xs text-zinc-600">
        <span>Confidence</span>
        <span>{percent}%</span>
      </div>
      <div className="h-2 overflow-hidden rounded bg-line">
        <div className="h-full bg-good" style={{ width: `${percent}%` }} />
      </div>
    </div>
  );
}

