import { readFileSync } from "node:fs";
import path from "node:path";
import { expect, test } from "vitest";
import { CHECK_RULES_SQL } from "./checkRules";

test("matches shared/check_rules.sql byte for byte", () => {
  const file = readFileSync(path.resolve(__dirname, "../../shared/check_rules.sql"), "utf-8");
  expect(CHECK_RULES_SQL).toBe(file);
});

test("reads only", () => {
  expect(CHECK_RULES_SQL).not.toMatch(/\b(insert|update|delete|drop|alter|create|truncate|grant|revoke)\b/i);
  expect(CHECK_RULES_SQL).toMatch(/pg_policies/);
  expect(CHECK_RULES_SQL).toMatch(/relrowsecurity/);
  expect(CHECK_RULES_SQL).toMatch(/storage\.buckets/);
});
