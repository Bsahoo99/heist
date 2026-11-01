import { Suspense } from "react";
import type { Metadata } from "next";
import { connection } from "next/server";
import { LiveAnalysis, LiveView, SiteBar } from "@/components/live/LiveAnalysis";
import { isAnalysisId } from "@/lib/analysisId";
import { getAnalysis, serverEngineUrl } from "@/lib/api";
import { repoName, shareTitle } from "@/lib/share";

type Props = {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ [key: string]: string | string[] | undefined }>;
};

/** Give up on the engine after this long: the title is a nicety, never worth a slow page. */
const ENGINE_TIMEOUT_MS = 3_000;

/** `Heist: owner/name` once the engine knows the analysis; the card image is `opengraph-image.tsx`. */
export async function generateMetadata({ params }: Pick<Props, "params">): Promise<Metadata> {
  const { id } = await params;
  const analysis = isAnalysisId(id)
    ? await getAnalysis(id, { base: serverEngineUrl(), signal: AbortSignal.timeout(ENGINE_TIMEOUT_MS) }).catch(
        () => null,
      )
    : null;
  const title = shareTitle(repoName(analysis?.url));
  return { title, openGraph: { title }, twitter: { card: "summary_large_image", title } };
}

const one = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v);

/**
 * One analysis: the live map while it runs, then the results. `?record=1` is
 * the recording layout `pnpm export` films (`?video=1`, its older name, still works).
 */
export default function AnalysisPage({ params, searchParams }: Props) {
  return (
    // The empty block shows from the first paint, before the id is read.
    <Suspense
      fallback={
        <main className="results-page">
          <SiteBar repo={null} />
          <LiveView events={[]} repo={null} />
        </main>
      }
    >
      <Analysis params={params} searchParams={searchParams} />
    </Suspense>
  );
}

async function Analysis({ params, searchParams }: Props) {
  // Marks the page as rendered per request, as the metadata asks the engine
  // (uncached); the empty block above still prerenders as the static shell.
  await connection();
  const { id } = await params;
  const query = await searchParams;
  const record = one(query.record) === "1" || one(query.video) === "1";
  return <LiveAnalysis key={id} id={id} layout={record ? "record" : "normal"} />;
}
