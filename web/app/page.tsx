import type { Metadata } from "next";
import { CityMap } from "@/components/map/CityMap";
import { RunForm } from "@/components/landing/RunForm";
import { shownExamples } from "@/lib/examples";
import { liveScene } from "@/lib/liveScene";

export const metadata: Metadata = { title: "Heist" };

export default function Home() {
  return (
    <main className="landing">
      <div className="landing-copy">
        <p className="site-mark">Heist</p>
        <h1 className="landing-title">See how your vibe-coded app gets robbed, before someone else does.</h1>
        <p className="landing-pitch">
          Scanners give you a list of warnings. Heist shows you the robbery, proves it, and teaches you how to lock the
          door.
        </p>
        <RunForm examples={shownExamples()} />
        <p className="landing-fine">
          For Vite + React + Supabase and Next.js + Supabase apps. Heist only reads your code. It never sends a request
          to your live app.
        </p>
      </div>
      {/* The empty block the analysis lights up. Decoration only. */}
      <div className="landing-map" aria-hidden="true">
        <CityMap scene={liveScene([])} idPrefix="landing-map" testIds={false} inactiveNote={null} />
      </div>
    </main>
  );
}
