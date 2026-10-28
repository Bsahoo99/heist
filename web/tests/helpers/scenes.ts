import type { Scene, SceneFinding } from "@/lib/scene.gen";
import vulnJson from "@/tests/fixtures/vuln-scene.json";
import cleanJson from "@/tests/fixtures/clean-scene.json";

export const vulnScene = vulnJson as unknown as Scene;
export const cleanScene = cleanJson as unknown as Scene;

/** The worst finding: the scene lists findings worst first. */
export const worst = (scene: Scene): SceneFinding | null => scene.findings[0] ?? null;

/**
 * The first confirmed mistake-3 finding, marked proved with the two fake
 * proof users. Used by tests and by the dev replay page (`&proved=1`).
 */
export function proveFirstOpenTable(finding: SceneFinding): SceneFinding {
  const table = finding.id.replace(/^m3-/, "");
  return {
    ...structuredClone(finding),
    status: "proved",
    proof_rows: [
      {
        table,
        as_who: "another_user",
        row: { id: 1, name: "Test Alice", email: "alice@example.test", note: "Fake note: please call after 5pm" },
      },
      {
        table,
        as_who: "another_user",
        row: { id: 2, name: "Test Bob", email: "bob@example.test", note: "Fake note: I have a fenced garden" },
      },
    ],
  };
}

/** The scene with its first confirmed m3 finding proved. */
export function withProvedFinding(scene: Scene): { scene: Scene; finding: SceneFinding } {
  const i = scene.findings.findIndex((f) => f.mistake === 3 && f.status === "confirmed");
  if (i < 0) throw new Error("no confirmed m3 finding in this scene");
  const finding = proveFirstOpenTable(scene.findings[i]);
  const findings = scene.findings.map((f, j) => (j === i ? finding : f));
  return { scene: { ...scene, findings }, finding };
}

export const provedFinding = withProvedFinding(vulnScene).finding;
