import { afterEach, expect, test } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { NoRulesCard } from "./NoRulesCard";
import { CHECK_RULES_SQL } from "@/lib/checkRules";

afterEach(cleanup);

test("no rules card shows read-only query", () => {
  render(<NoRulesCard />);
  expect(screen.getByRole("heading", { name: "We can't see your database rules" })).toBeTruthy();
  expect(screen.getByTestId("check-sql").textContent).not.toMatch(/\b(insert|update|delete|drop|alter|create)\b/i);
  expect(screen.getByTestId("check-sql").textContent).toBe(CHECK_RULES_SQL);
  expect(screen.getByText("Paste this into the SQL editor in your Supabase dashboard.")).toBeTruthy();
});

test("copy query copies the whole query", async () => {
  const user = userEvent.setup();
  render(<NoRulesCard />);
  await user.click(screen.getByRole("button", { name: "Copy query" }));
  expect(await navigator.clipboard.readText()).toBe(CHECK_RULES_SQL);
});
