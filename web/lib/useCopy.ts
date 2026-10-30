"use client";

import { useCallback, useEffect, useRef, useState } from "react";

export type CopyState = "idle" | "copied" | "failed";

/** How long a button says "Copied". */
export const COPIED_MS = 2000;

/**
 * Copy text to the clipboard. `state` is "copied" for about two seconds after
 * a copy, and "failed" when the browser has no clipboard (an insecure page) or
 * refuses it, so the caller can show the text to select instead. Never throws.
 */
export function useCopy(): { state: CopyState; copy: (text: string) => Promise<void> } {
  const [state, setState] = useState<CopyState>("idle");
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => () => clearTimeout(timer.current), []);

  const copy = useCallback(async (text: string) => {
    clearTimeout(timer.current);
    try {
      if (typeof navigator === "undefined" || !navigator.clipboard?.writeText) throw new Error("no clipboard");
      await navigator.clipboard.writeText(text);
      setState("copied");
      timer.current = setTimeout(() => setState("idle"), COPIED_MS);
    } catch {
      setState("failed");
    }
  }, []);

  return { state, copy };
}
