// DEV ONLY: the results layout (replay, step player, panels) against the
// test fixtures. Not part of the product; it returns 404 in production builds.
// Usage: /dev/replay?scene=vuln|clean&finding=<finding id>&proved=1&video=1
//   proved=1 marks the first confirmed m3 finding as proved, with the two
//   fake proof users. video=1 shows the recording layout without the dev bar.
import { Suspense } from "react";
import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { ResultsView } from "@/components/results/ResultsView";
import type { Scene } from "@/lib/scene.gen";

export const metadata: Metadata = { title: "Heist replay (dev preview)" };

const one = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v);

type SearchParams = Promise<{ [key: string]: string | string[] | undefined }>;

export default function DevReplayPage({ searchParams }: { searchParams: SearchParams }) {
  if (process.env.NODE_ENV === "production") notFound();
  return (
    <Suspense fallback={<main className="results-page" />}>
      <DevReplay searchParams={searchParams} />
    </Suspense>
  );
}

async function DevReplay({ searchParams }: { searchParams: SearchParams }) {
  // Loaded only after the production 404 above, so production bundles leave the fixtures out.
  const { cleanScene, vulnScene, withProvedFinding } = await import("@/tests/helpers/scenes");
  const params = await searchParams;
  const sceneKey = one(params.scene) === "clean" ? "clean" : "vuln";
  const proved = sceneKey === "vuln" && one(params.proved) === "1";
  const video = one(params.video) === "1";
  let scene: Scene = sceneKey === "clean" ? cleanScene : vulnScene;
  let findingId = one(params.finding);
  if (proved) {
    const p = withProvedFinding(scene);
    scene = p.scene;
    findingId ??= p.finding.id;
  }
  const links = [
    { href: "/dev/replay?scene=vuln", label: "Vulnerable app", on: sceneKey === "vuln" && !proved },
    { href: "/dev/replay?scene=vuln&proved=1", label: "With proof", on: proved },
    { href: "/dev/replay?scene=clean", label: "Clean app", on: sceneKey === "clean" },
  ];

  return (
    <main className="results-page">
      {!video && (
        <header className="dev-bar">
          <span className="dev-tag">Dev preview</span>
          <p className="dev-repo">{scene.meta.repo}</p>
          <nav aria-label="Fixture" className="dev-nav">
            {links.map((l) => (
              <Link key={l.href} href={l.href} aria-current={l.on ? "page" : undefined}>
                {l.label}
              </Link>
            ))}
          </nav>
        </header>
      )}
      <ResultsView
        key={`${sceneKey}-${proved}-${findingId ?? ""}-${video}`}
        scene={scene}
        initialFindingId={findingId}
        layout={video ? "video" : "normal"}
      />
    </main>
  );
}
