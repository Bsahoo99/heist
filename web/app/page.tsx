import type { Metadata } from "next";
import { CityMap } from "@/components/map/CityMap";
import { RunForm } from "@/components/landing/RunForm";
import { landingFrame } from "@/components/landing/frame";
import { shownExamples } from "@/lib/examples";
import { SAMPLE_FINDING, SAMPLE_SCENE } from "@/lib/sampleScene";

/** The landing map box's shape (px); `.landing-map` keeps this aspect ratio. */
const LANDING_BOX = { width: 680, height: 440 };
const LANDING_FRAME = landingFrame(SAMPLE_SCENE, SAMPLE_FINDING.attack_path, LANDING_BOX);

export const metadata: Metadata = { title: "Heist" };

export default function Home() {
  return (
    <main className="landing">
      <div className="landing-copy">
        <p className="site-mark">Heist</p>
        <h1 className="landing-title">
          {/* Keeps "vibe-coded" on one line; the heading text is unchanged. */}
          See how your <span className="nowrap">vibe-coded</span> app gets robbed, before someone else does.
        </h1>
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
      {/* A sample app's block with one break-in drawn on it. Decoration only. */}
      <div className="landing-map" aria-hidden="true">
        <CityMap
          scene={SAMPLE_SCENE}
          attack={SAMPLE_FINDING.attack_path}
          wideFrame={LANDING_FRAME}
          idPrefix="landing-map"
          testIds={false}
        />
      </div>
    </main>
  );
}
