"use client";

import { useMemo, useRef, useState } from "react";
import type { Scene, SceneFinding } from "@/lib/scene.gen";
import { ZONES } from "@/components/map/layout";
import { FindingsList, SEVERITY_LABEL, StatusBadge } from "@/components/panels/FindingsList";
import { ProofRows } from "@/components/panels/ProofRows";
import { StepPanel } from "@/components/panels/StepPanel";
import { Replay } from "@/components/replay/Replay";
import { StepPlayer } from "@/components/replay/StepPlayer";
import { useReplayClock } from "@/components/replay/useReplayClock";
import { buildTimeline, replaySteps, stepEventCount } from "@/lib/timeline";

function itemLabel(scene: Scene, id: string): string | undefined {
  for (const z of scene.zones) {
    const item = z.items.find((i) => i.node_id === id);
    if (item) return item.label;
  }
  return undefined;
}

/** One finding (or the clean run): header, replay, player and the stop's panel. Remounted per finding. */
function FindingStage({
  scene,
  finding,
  autoPlay,
}: {
  scene: Scene;
  finding: SceneFinding | null;
  autoPlay: boolean;
}) {
  const timeline = useMemo(() => buildTimeline(finding, scene), [finding, scene]);
  const steps = useMemo(() => replaySteps(finding, scene), [finding, scene]);
  const clock = useReplayClock(timeline, { autoPlay });
  const index = Math.min(clock.eventIndex, stepEventCount(timeline) - 1);
  const current = steps[Math.max(0, index)];
  const where = current
    ? [ZONES[current.step.zone].label, itemLabel(scene, current.step.item_id)].filter(Boolean).join(": ")
    : undefined;

  return (
    <>
      <header className="results-head">
        {finding ? (
          <>
            <div className="results-head-tags">
              <span className="finding-severity" data-severity={finding.severity}>
                {SEVERITY_LABEL[finding.severity]}
              </span>
              <StatusBadge status={finding.status} />
            </div>
            <h2 className="results-title">{finding.title}</h2>
          </>
        ) : (
          <>
            <h2 className="results-title">Every lock held</h2>
            <p className="results-sub">Heist tried every door of {scene.meta.repo} and found no way in.</p>
          </>
        )}
        {finding && (
          <ul className="results-legend" aria-label="Map key">
            <li>
              <span className="phase-key phase-key-ghost" aria-hidden="true" />
              Legitimate route
            </li>
            <li>
              <span className="phase-key phase-key-attack" aria-hidden="true" />
              Attack route
            </li>
          </ul>
        )}
      </header>

      <section className="results-stage" aria-label="Replay">
        <Replay scene={scene} finding={finding} clock={clock} />
        <StepPlayer
          steps={steps}
          index={index}
          onIndex={clock.seek}
          playing={clock.playing}
          onPlayingChange={clock.setPlaying}
        />
      </section>

      <div className="results-panel">
        {current && <StepPanel step={current.step} heading={where} />}
        {finding?.status === "proved" && finding.proof_rows.length > 0 && (
          <section className="results-proof" aria-label="Proof">
            <h3>Proof with fake data</h3>
            <p>
              Heist applied your migrations to a throwaway database, filled it with fake people, and asked for this
              table as someone who should not see it.
            </p>
            <ProofRows rows={finding.proof_rows} />
          </section>
        )}
      </div>
    </>
  );
}

/**
 * The results layout: the replay of the selected finding (the worst one
 * first) with its step player and panel, and the list of every finding.
 * Map on top on phones, on the left on wide screens.
 */
export function ResultsView({
  scene,
  initialFindingId,
  autoPlay = true,
}: {
  scene: Scene;
  initialFindingId?: string;
  autoPlay?: boolean;
}) {
  const initial = scene.findings.find((f) => f.id === initialFindingId) ?? scene.findings[0] ?? null;
  const [selected, setSelected] = useState<{ id: string | null; play: boolean }>({
    id: initial?.id ?? null,
    play: autoPlay,
  });
  const finding = scene.findings.find((f) => f.id === selected.id) ?? null;
  const top = useRef<HTMLDivElement>(null);

  const onSelect = (id: string) => {
    setSelected({ id, play: true });
    const el = top.current;
    if (el && el.getBoundingClientRect().top < 0) {
      const reduce = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
      el.scrollIntoView({ block: "start", behavior: reduce ? "auto" : "smooth" });
    }
  };

  return (
    <div className="results" ref={top}>
      <FindingStage key={finding?.id ?? "clean"} scene={scene} finding={finding} autoPlay={selected.play} />
      <section className="results-list" aria-labelledby="results-list-title">
        <h2 id="results-list-title" className="results-list-title">
          {scene.findings.length > 0 ? `All findings (${scene.findings.length})` : "Findings"}
        </h2>
        <FindingsList findings={scene.findings} selectedId={finding?.id ?? null} onSelect={onSelect} />
      </section>
    </div>
  );
}
