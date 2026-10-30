"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { CityMap } from "@/components/map/CityMap";
import { ResultsView, type ResultsLayout } from "@/components/results/ResultsView";
import { getAnalysis, LOST_CONNECTION_COPY, subscribe, UNREACHABLE_COPY, type ProgressEvent } from "@/lib/api";
import { liveScene, liveStatus } from "@/lib/liveScene";
import type { Scene } from "@/lib/scene.gen";

export const GONE_COPY = "This analysis is gone. Run it again.";
const GENERIC_COPY = "Something went wrong while analyzing this repo. Please try again.";

type State =
  | { phase: "live"; events: ProgressEvent[] }
  | { phase: "results"; scene: Scene }
  | { phase: "error"; message: string }
  | { phase: "lost"; message: string }
  | { phase: "gone" };

const repoName = (url: string | null) => url?.replace(/^https:\/\/github\.com\//, "") ?? "";

function findingsCount(n: number): string {
  if (n === 0) return "No findings yet";
  return n === 1 ? "1 finding so far" : `${n} findings so far`;
}

/** The map while the analysis runs: zones light up as Heist finds the app's parts. */
export function LiveView({
  events,
  repo,
  layout = "normal",
}: {
  events: ProgressEvent[];
  repo: string | null;
  layout?: ResultsLayout;
}) {
  const scene = useMemo(() => liveScene(events, repo ?? ""), [events, repo]);
  const status = liveStatus(events);
  return (
    <div className="live" data-layout={layout}>
      {/* Title and status share one line, so the map gets the rest of the screen. */}
      <header className="results-head live-head">
        <h1 className="results-title">{repo ? `Casing ${repoName(repo)}` : "Casing the app"}</h1>
        <p className="live-status" role="status" aria-live="polite">
          <span className="live-dot" aria-hidden="true" />
          <span className="live-stage" data-testid="live-stage">
            {status.stage ?? "Connecting to the engine"}
          </span>
          <span className="live-count" data-testid="live-count">
            {findingsCount(status.findings)}
          </span>
        </p>
      </header>
      <div className="replay-map live-map">
        <CityMap scene={scene} idPrefix="live-map" inactiveNote={status.mapped ? undefined : null} />
      </div>
    </div>
  );
}

/** The thin top bar: the way home and the repo under analysis. */
export function SiteBar({ repo }: { repo: string | null }) {
  return (
    <header className="site-bar">
      <Link href="/" className="site-mark">
        Heist
      </Link>
      {repo && <span className="site-repo">{repoName(repo)}</span>}
    </header>
  );
}

function Notice({
  title,
  message,
  onReload,
}: {
  title: string;
  message: string;
  /** Offered when the analysis may still be running: pick it up again in place. */
  onReload?: () => void;
}) {
  return (
    <section className="live-notice" role="alert">
      <h1 className="results-title">{title}</h1>
      <p>{message}</p>
      <div className="live-actions">
        {onReload && (
          <button type="button" className="run-button live-again" onClick={onReload}>
            Reload
          </button>
        )}
        <Link href="/" className={onReload ? "run-chip live-other" : "run-button live-again"}>
          Try another repo
        </Link>
      </div>
    </section>
  );
}

/**
 * One analysis page: the live map while it runs (reloading resumes it, since
 * the engine replays past events), then the results with the worst finding
 * playing. Errors are shown in the engine's plain words. A dropped connection
 * is not a failed heist: it gets its own notice and can be picked up again.
 */
export function LiveAnalysis({ id, layout = "normal" }: { id: string; layout?: ResultsLayout }) {
  const [state, setState] = useState<State>({ phase: "live", events: [] });
  const [repo, setRepo] = useState<string | null>(null);
  // Bumped by "Reload" to run the effect again: GET, then the stream's full replay.
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    let active = true;
    let unsubscribe = () => {};
    const show = (next: State) => {
      if (active) setState(next);
    };
    /** Where things stand after `done` or a dropped stream, asked of the engine. */
    const settle = async (lostMessage: string) => {
      const a = await getAnalysis(id).catch(() => undefined);
      if (a === null) show({ phase: "gone" });
      else if (a?.status === "done" && a.scene) show({ phase: "results", scene: a.scene });
      else if (a?.status === "error") show({ phase: "error", message: a.error ?? GENERIC_COPY });
      else show({ phase: "lost", message: lostMessage });
    };

    (async () => {
      const a = await getAnalysis(id).catch(() => undefined);
      if (!active) return;
      if (a === undefined) return show({ phase: "lost", message: UNREACHABLE_COPY });
      if (a === null) return show({ phase: "gone" });
      setRepo(a.url);
      if (a.status === "done" && a.scene) return show({ phase: "results", scene: a.scene });
      if (a.status === "error") return show({ phase: "error", message: a.error ?? GENERIC_COPY });
      const seen: ProgressEvent[] = [];
      unsubscribe = subscribe(id, (e) => {
        if (e.kind === "done") return void settle(LOST_CONNECTION_COPY);
        // A lost stream may be a restarted engine (gone) or a blip (still running).
        if (e.kind === "error" && e.message === LOST_CONNECTION_COPY) return void settle(e.message);
        if (e.kind === "error") return show({ phase: "error", message: e.message });
        seen.push(e);
        show({ phase: "live", events: [...seen] });
      });
    })();

    return () => {
      active = false;
      unsubscribe();
    };
  }, [id, attempt]);

  const reload = () => {
    setState({ phase: "live", events: [] });
    setAttempt((n) => n + 1);
  };

  return (
    <main className="results-page">
      {layout === "normal" && <SiteBar repo={repo} />}
      {state.phase === "live" && <LiveView events={state.events} repo={repo} layout={layout} />}
      {state.phase === "results" && <ResultsView scene={state.scene} layout={layout} />}
      {state.phase === "error" && <Notice title="We couldn't run this heist" message={state.message} />}
      {state.phase === "lost" && <Notice title="Lost the connection" message={state.message} onReload={reload} />}
      {state.phase === "gone" && <Notice title="Nothing here" message={GONE_COPY} />}
    </main>
  );
}
