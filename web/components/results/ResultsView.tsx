"use client";

import { useMemo, useRef, useState } from "react";
import type { Scene, SceneFinding } from "@/lib/scene.gen";
import { ZONES } from "@/components/map/layout";
import { FindingsList, SEVERITY_LABEL, StatusBadge } from "@/components/panels/FindingsList";
import { BadgeBlock } from "@/components/panels/BadgeBlock";
import { ExportLinks, useExports } from "@/components/panels/ExportLinks";
import { FixCard } from "@/components/panels/FixCard";
import { NoRulesCard } from "@/components/panels/NoRulesCard";
import { ProofRows } from "@/components/panels/ProofRows";
import { StepPanel } from "@/components/panels/StepPanel";
import { Replay } from "@/components/replay/Replay";
import { StepPlayer } from "@/components/replay/StepPlayer";
import { useRecordFlags } from "@/components/replay/useRecordFlags";
import { useReplayClock } from "@/components/replay/useReplayClock";
import type { Exports } from "@/lib/api";
import { offersBadge } from "@/lib/badge";
import { rulesCoverage, unreadMigrationsCopy } from "@/lib/coverage";
import { buildTimeline, playerSteps } from "@/lib/timeline";

/** "record" is the recording layout (`?record=1`, `pnpm export`): the map and the caption only. */
export type ResultsLayout = "normal" | "record";

/** Nominal size (px) of the map box in each layout at 1280x720, for the steady wide frame. */
const WIDE_BOX: Record<ResultsLayout, { width: number; height: number }> = {
  normal: { width: 892, height: 438 },
  record: { width: 1248, height: 594 },
};

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
  layout,
  badgeId,
  exports,
}: {
  scene: Scene;
  finding: SceneFinding | null;
  autoPlay: boolean;
  layout: ResultsLayout;
  /** The analysis id when the clean run offers its README badge here. */
  badgeId?: string;
  /** The exported replay's links, shown under the badge here. */
  exports: Exports | null;
}) {
  const coverage = rulesCoverage(scene);
  const timeline = useMemo(() => buildTimeline(finding, scene), [finding, scene]);
  const steps = useMemo(() => playerSteps(finding, scene), [finding, scene]);
  const clock = useReplayClock(timeline, { autoPlay });
  // Every event but the end is a player step; the end keeps the last one.
  const index = Math.max(0, Math.min(clock.eventIndex, steps.length - 1));
  const ended = timeline[clock.eventIndex]?.kind === "end" && !clock.playing;
  const record = layout === "record";
  useRecordFlags(clock, ended, record);
  const current = steps[index];
  const where = current
    ? [ZONES[current.step.zone].label, itemLabel(scene, current.step.item_id)].filter(Boolean).join(": ")
    : undefined;

  return (
    <>
      {!record && (
        <header className="results-head">
          {finding ? (
            <>
              <div className="results-head-tags">
                <span className="finding-severity" data-severity={finding.severity}>
                  {SEVERITY_LABEL[finding.severity]}
                </span>
                <StatusBadge status={finding.status} />
              </div>
              <h1 className="results-title">{finding.title}</h1>
            </>
          ) : coverage === "full" ? (
            <>
              <h1 className="results-title">Every lock held</h1>
              <p className="results-sub">Heist tried every door of {scene.meta.repo} and found no way in.</p>
            </>
          ) : coverage === "partial" ? (
            // Rules in the unread files were never checked: no "every lock".
            <>
              <h1 className="results-title">No way in found</h1>
              <p className="results-sub">
                Heist found no way into {scene.meta.repo}, but{" "}
                {unreadMigrationsCopy(scene.meta.unparsed_migrations.length)}
              </p>
            </>
          ) : (
            // Mistakes 3 and 4 need the database rules: never claim those locks held.
            <>
              <h1 className="results-title">No way in through the code</h1>
              <p className="results-sub">
                Heist found no way in through the code of {scene.meta.repo}, but it could not check your database rules.
              </p>
            </>
          )}
        </header>
      )}

      <section className="results-stage" aria-label="Replay">
        <Replay scene={scene} finding={finding} clock={clock} wideBox={WIDE_BOX[layout]} record={record} />
        {!record && (
          <StepPlayer
            steps={steps}
            index={index}
            ended={ended}
            onIndex={clock.seek}
            playing={clock.playing}
            onPlayingChange={clock.setPlaying}
          />
        )}
      </section>

      {layout === "normal" && (
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
          {!finding && badgeId && <BadgeBlock scene={scene} id={badgeId} />}
          {!finding && badgeId && <ExportLinks exports={exports} />}
        </div>
      )}
      {/* Under the panel on phones; under the replay on wide screens, where the diff has room. */}
      {layout === "normal" && finding && (
        <div className="results-fix">
          <FixCard fix={finding.fix} />
        </div>
      )}
    </>
  );
}

/**
 * The results layout: the replay of the selected finding (the worst one
 * first) with its step player and panel, and the list of every finding.
 * Map on top on phones, on the left on wide screens.
 *
 * `layout="record"` is for recordings (`pnpm export`): the map as large as the
 * viewport allows and the caption, auto-playing to an end card; no header,
 * player, side panel, findings list, fix, missing-rules, badge or download
 * cards. It flags its progress on the body for the export (`useRecordFlags`).
 *
 * The selected finding's fix sits under its step panel on phones and under
 * the replay on wide screens. Without database rules the missing-rules card
 * comes before the list (under the replay on wide screens, so the query gets
 * the full width) and replaces it when there are no findings. With an `id`,
 * every check held and every migration read, the README badge is offered.
 * With an `id`, links to the exported replay (MP4 and GIF) follow the badge,
 * or open the list when there is no badge, once the engine has them.
 */
export function ResultsView({
  scene,
  id,
  initialFindingId,
  autoPlay = true,
  layout = "normal",
}: {
  scene: Scene;
  /** The analysis id, for the README badge. Pages without one (the dev pages) offer no badge. */
  id?: string;
  initialFindingId?: string;
  autoPlay?: boolean;
  layout?: ResultsLayout;
}) {
  const initial = scene.findings.find((f) => f.id === initialFindingId) ?? scene.findings[0] ?? null;
  const [selected, setSelected] = useState<{ id: string | null; play: boolean }>({
    id: initial?.id ?? null,
    play: autoPlay,
  });
  const finding = scene.findings.find((f) => f.id === selected.id) ?? null;
  const top = useRef<HTMLDivElement>(null);
  const badgeId = id && offersBadge(scene) ? id : undefined;
  const coverage = rulesCoverage(scene);
  const rulesMissing = coverage === "none";
  const hasFindings = scene.findings.length > 0;
  const exports = useExports(layout === "normal" ? id : undefined);
  // The clean run's badge sits in the panel and the links go under it; otherwise they lead the list.
  const exportsInPanel = !finding && Boolean(badgeId);

  const onSelect = (id: string) => {
    setSelected({ id, play: true });
    const el = top.current;
    if (el && el.getBoundingClientRect().top < 0) {
      const reduce = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
      el.scrollIntoView({ block: "start", behavior: reduce ? "auto" : "smooth" });
    }
  };

  return (
    <div className="results" data-layout={layout} ref={top}>
      <FindingStage
        key={finding?.id ?? "clean"}
        scene={scene}
        finding={finding}
        autoPlay={selected.play}
        layout={layout}
        badgeId={badgeId}
        exports={exports}
      />
      {layout === "normal" && rulesMissing && (
        <div className="results-rules">
          <NoRulesCard />
        </div>
      )}
      {layout === "normal" && (
        <div className="results-list">
          {/* Only possible findings, every check held: the badge is earned, offer it above the list. */}
          {hasFindings && badgeId && <BadgeBlock scene={scene} id={badgeId} />}
          {!exportsInPanel && <ExportLinks exports={exports} />}
          {(hasFindings || !rulesMissing) && (
            <section aria-labelledby="results-list-title">
              <h2 id="results-list-title" className="results-list-title">
                {hasFindings ? `All findings (${scene.findings.length})` : "Findings"}
              </h2>
              <FindingsList
                findings={scene.findings}
                selectedId={finding?.id ?? null}
                onSelect={onSelect}
                emptyText={coverage === "full" ? undefined : "No findings in the parts Heist could read."}
              />
            </section>
          )}
        </div>
      )}
    </div>
  );
}
