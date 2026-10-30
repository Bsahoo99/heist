"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { ApiError, UNREACHABLE_COPY, startAnalysis } from "@/lib/api";
import type { Example } from "@/lib/examples";

/** The repo URL input and "Run the heist". The engine's refusal shows inline, in its own words. */
export function RunForm({ examples }: { examples: Required<Example>[] }) {
  const router = useRouter();
  const [url, setUrl] = useState("");
  const [error, setError] = useState<string | null>(null);
  // Pending from the post until the analysis page has loaded, so going back
  // to this page (which Next keeps alive) finds the button ready again.
  const [busy, startTransition] = useTransition();

  const run = (target: string) => {
    if (busy) return;
    setError(null);
    startTransition(async () => {
      try {
        const { id } = await startAnalysis(target.trim());
        router.push(`/a/${encodeURIComponent(id)}`);
      } catch (e) {
        setError(e instanceof ApiError ? e.message : UNREACHABLE_COPY);
      }
    });
  };

  return (
    <form
      className="run-form"
      noValidate
      onSubmit={(e) => {
        e.preventDefault();
        run(url);
      }}
    >
      <label htmlFor="repo-url" className="run-label">
        Public GitHub repo
      </label>
      <div className="run-row">
        <input
          id="repo-url"
          className="run-input"
          type="url"
          inputMode="url"
          autoComplete="off"
          autoCapitalize="off"
          spellCheck={false}
          placeholder="https://github.com/you/your-app"
          value={url}
          onChange={(e) => {
            setUrl(e.target.value);
            if (error) setError(null);
          }}
          aria-invalid={error ? true : undefined}
          aria-describedby={error ? "repo-url-error" : undefined}
        />
        <button type="submit" className="run-button" disabled={busy} aria-busy={busy || undefined}>
          {busy ? "Starting the heist" : "Run the heist"}
        </button>
      </div>
      <p id="repo-url-error" className="run-error" role="alert">
        {error}
      </p>
      {examples.length > 0 && (
        <div className="run-examples">
          <span>Or try</span>
          {examples.map((ex) => (
            <button
              key={ex.url}
              type="button"
              className="run-chip"
              disabled={busy}
              onClick={() => {
                setUrl(ex.url);
                run(ex.url);
              }}
            >
              {ex.label}
            </button>
          ))}
        </div>
      )}
    </form>
  );
}
