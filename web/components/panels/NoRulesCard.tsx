"use client";

import { useId } from "react";
import { CHECK_RULES_SQL } from "@/lib/checkRules";
import { useCopy } from "@/lib/useCopy";

/**
 * Shown when the repo has no Supabase migrations: Heist could not check the
 * database rules, so it hands over a read-only query to run in Supabase.
 */
export function NoRulesCard() {
  const { state, copy } = useCopy();
  const id = useId();
  return (
    <section className="rules-card" aria-labelledby={`${id}-title`}>
      <h2 id={`${id}-title`}>We can&apos;t see your database rules</h2>
      <p>
        Your app&apos;s Supabase key is public by design, so the database rules are the only lock on your data. Heist
        found no migrations in this repo, so it could not check them.
      </p>
      <pre className="rules-sql" data-testid="check-sql" tabIndex={0} aria-label="Read-only query">
        {CHECK_RULES_SQL}
      </pre>
      <div className="rules-actions">
        <button type="button" className="copy-button" data-state={state} onClick={() => void copy(CHECK_RULES_SQL)}>
          <span aria-live="polite">{state === "copied" ? "Copied" : "Copy query"}</span>
        </button>
        <p>Paste this into the SQL editor in your Supabase dashboard.</p>
      </div>
      {state === "failed" && (
        <p className="copy-failed" role="status">
          Copy failed, select the query above
        </p>
      )}
    </section>
  );
}
