// How much of the database rules Heist could check, so no copy claims a lock it did not test.
import type { Scene } from "./scene.gen";

/**
 * "full": every migration was read. "none": no migrations, so the table and
 * storage checks (mistakes 3 and 4) did not run. "partial": some migration
 * files could not be read, so those checks may have missed rules.
 */
export type RulesCoverage = "full" | "none" | "partial";

export function rulesCoverage(scene: Scene): RulesCoverage {
  if (!scene.meta.has_db_rules) return "none";
  if (scene.meta.unparsed_migrations.length > 0) return "partial";
  return "full";
}

/** Plain words for migrations Heist could not read. */
export function unreadMigrationsCopy(n: number): string {
  const files = n === 1 ? "1 migration file" : `${n} migration files`;
  return `${files} could not be read, so the database checks may be incomplete.`;
}
