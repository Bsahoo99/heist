// Analysis ids are the engine's `secrets.token_urlsafe(9)`; anything else never reaches the engine.
// Plain TypeScript with no imports: `scripts/export-replay.ts` loads it straight into Node.

export const ANALYSIS_ID = /^[A-Za-z0-9_-]{1,64}$/;

export function isAnalysisId(id: string): boolean {
  return ANALYSIS_ID.test(id);
}
