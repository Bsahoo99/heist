// DEV ONLY: a preview of the city map against the test fixtures.
// Not part of the product; it returns 404 in production builds.
// Usage: /dev/map?scene=vuln|clean&finding=<finding id>&progress=0..1
import { Suspense } from "react";
import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { CityMap } from "@/components/map/CityMap";
import type { Scene, SceneFinding } from "@/lib/scene.gen";
import vulnJson from "@/tests/fixtures/vuln-scene.json";
import cleanJson from "@/tests/fixtures/clean-scene.json";

export const metadata: Metadata = { title: "City map (dev preview)" };

const SCENES: Record<string, Scene> = {
  vuln: vulnJson as unknown as Scene,
  clean: cleanJson as unknown as Scene,
};

const SEVERITY_RANK: Record<SceneFinding["severity"], number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

function worstFinding(scene: Scene): SceneFinding | undefined {
  return scene.findings
    .map((f, i) => ({ f, i }))
    .sort((a, b) => SEVERITY_RANK[a.f.severity] - SEVERITY_RANK[b.f.severity] || a.i - b.i)[0]?.f;
}

const one = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v);

type SearchParams = Promise<{ [key: string]: string | string[] | undefined }>;

export default function DevMapPage({ searchParams }: { searchParams: SearchParams }) {
  if (process.env.NODE_ENV === "production") notFound();
  return (
    <Suspense fallback={<main className="min-h-dvh bg-[var(--map-bg)]" />}>
      <DevMap searchParams={searchParams} />
    </Suspense>
  );
}

async function DevMap({ searchParams }: { searchParams: SearchParams }) {
  const params = await searchParams;
  const sceneKey = one(params.scene) === "clean" ? "clean" : "vuln";
  const scene = SCENES[sceneKey];
  const findingId = one(params.finding);
  const finding = scene.findings.find((f) => f.id === findingId) ?? worstFinding(scene);
  const progressParam = Number(one(params.progress));
  const progress = Number.isFinite(progressParam) && one(params.progress) !== undefined ? progressParam : 1;

  return (
    <main className="flex min-h-dvh flex-col bg-[var(--map-bg)] text-[var(--map-ink)] sm:h-dvh">
      <header className="flex flex-wrap items-center gap-x-6 gap-y-2 border-b border-[var(--map-slab-edge)] px-4 py-2.5 text-sm">
        <span className="rounded bg-[var(--map-badge-bg)] px-2 py-0.5 text-xs text-[var(--map-zone-ink)]">
          Dev preview
        </span>
        <nav className="flex gap-1" aria-label="Fixture">
          {Object.keys(SCENES).map((key) => (
            <Link
              key={key}
              href={`/dev/map?scene=${key}`}
              aria-current={key === sceneKey ? "page" : undefined}
              className={`rounded px-2 py-0.5 ${
                key === sceneKey
                  ? "bg-[var(--map-slab-top)] text-[var(--map-ink)]"
                  : "text-[var(--map-muted)] hover:text-[var(--map-ink)]"
              }`}
            >
              {key === "vuln" ? "Vulnerable app" : "Clean app"}
            </Link>
          ))}
        </nav>
        <p className="order-last basis-full text-[var(--map-zone-ink)] lg:order-none lg:basis-auto lg:min-w-0 lg:flex-1 lg:truncate">
          {finding ? finding.title : "No findings: every lock held"}
        </p>
        {finding && (
          <ul className="flex gap-4 text-xs text-[var(--map-muted)]">
            <li className="flex items-center gap-2">
              <span className="inline-block w-5 border-t-2 border-dashed border-[var(--map-ghost)]" />
              Legitimate route
            </li>
            <li className="flex items-center gap-2">
              <span className="inline-block w-5 border-t-2 border-[var(--map-flag)]" />
              Attack route
            </li>
          </ul>
        )}
      </header>
      {/* Phones: the map takes its own height; wider screens: it fills the rest of the viewport. */}
      <div className="p-4 sm:min-h-0 sm:flex-1 sm:p-3">
        <CityMap
          scene={scene}
          ghost={finding?.ghost_path}
          attack={finding?.attack_path}
          progress={progress}
        />
      </div>
    </main>
  );
}
