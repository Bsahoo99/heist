import { Suspense } from "react";
import type { Metadata } from "next";
import { LiveAnalysis, LiveView, SiteBar } from "@/components/live/LiveAnalysis";

export const metadata: Metadata = { title: "Heist" };

type Props = {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ [key: string]: string | string[] | undefined }>;
};

const one = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v);

/** One analysis: the live map while it runs, then the results. `?video=1` is the recording layout. */
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
  const { id } = await params;
  const video = one((await searchParams).video) === "1";
  return <LiveAnalysis key={id} id={id} layout={video ? "video" : "normal"} />;
}
