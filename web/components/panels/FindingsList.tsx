import type { SceneFinding } from "@/lib/scene.gen";

export const STATUS_LABEL: Record<SceneFinding["status"], string> = {
  confirmed: "Confirmed",
  proved: "Proved",
  possible: "Possible, not confirmed",
};

export const SEVERITY_LABEL: Record<SceneFinding["severity"], string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};

export function StatusBadge({ status }: { status: SceneFinding["status"] }) {
  return (
    <span className="status-badge" data-status={status}>
      {STATUS_LABEL[status]}
    </span>
  );
}

/** Every finding, worst first. Possible findings are drawn dashed. */
export function FindingsList({
  findings,
  selectedId,
  onSelect,
}: {
  findings: SceneFinding[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  if (findings.length === 0) {
    return <p className="findings-empty">No findings. Every check passed.</p>;
  }
  return (
    <ul className="findings-list">
      {findings.map((f) => (
        <li key={f.id}>
          <button
            type="button"
            data-testid={`finding-${f.id}`}
            data-status={f.status}
            data-severity={f.severity}
            aria-current={f.id === selectedId ? "true" : undefined}
            onClick={() => onSelect(f.id)}
            className={`finding-row ${f.status === "possible" ? "border-dashed" : "border-solid"}`}
          >
            <span className="finding-severity" data-severity={f.severity}>
              {SEVERITY_LABEL[f.severity]}
            </span>
            <span className="finding-title">{f.title}</span>
            <StatusBadge status={f.status} />
          </button>
        </li>
      ))}
    </ul>
  );
}
