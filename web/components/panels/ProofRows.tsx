import type { ProofRow } from "@/lib/scene.gen";

const AS_WHO: Record<ProofRow["as_who"], string> = {
  anonymous: "an anonymous visitor",
  another_user: "another signed-in user",
};

const cell = (v: unknown): string => {
  if (v === null || v === undefined) return "";
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
};

/** Columns the compact view leaves out: row ids say nothing about who leaked. */
const ID_COLUMN = /^(id|uuid|.*_id)$/i;
/** The engine shows an owner uuid as whose id it is: "Test Alice (user id)". */
const OWNER_VALUE = /\(user id\)$/;
const EMAIL_COLUMN = /e-?mail/i;

/**
 * The compact card's columns: whose row it is (the owner column) first, then
 * the email and other named columns in the table's order. Owner and email are
 * never cut, since they show whose data leaked and that it is fake; with both
 * present the card keeps two columns rather than cutting one of them.
 */
export function compactColumns(rows: ProofRow[]): { cols: string[]; whole: Set<string> } {
  const all = [...new Set(rows.flatMap((r) => Object.keys(r.row)))];
  const owner = all.find((c) => rows.some((r) => OWNER_VALUE.test(cell(r.row[c]))));
  const email = all.find((c) => c !== owner && EMAIL_COLUMN.test(c));
  const whole = new Set([owner, email].filter((c): c is string => c !== undefined));
  // Owner first, then the table's own order; owner and email always make the cut.
  const rest = all.filter((c) => c !== owner && (whole.has(c) || !ID_COLUMN.test(c)));
  const ordered = owner ? [owner, ...rest] : rest;
  const limit = whole.size >= 2 ? 2 : 3;
  const keep = new Set(whole);
  for (const c of ordered) if (keep.size < limit) keep.add(c);
  const cols = ordered.filter((c) => keep.has(c));
  return { cols: cols.length ? cols : all.slice(0, 3), whole };
}

/**
 * The fake rows the proof read back from a throwaway copy of the database.
 * One table per (table, who asked) pair. Values are plain text.
 *
 * `compact` (the replay's climax card): see `compactColumns`; one line per
 * cell, owner and email whole, the rest cut with an ellipsis.
 */
export function ProofRows({ rows, compact = false }: { rows: ProofRow[]; compact?: boolean }) {
  if (rows.length === 0) return null;
  const groups: { key: string; table: string; asWho: ProofRow["as_who"]; rows: ProofRow[] }[] = [];
  for (const r of rows) {
    const key = `${r.table}\u0000${r.as_who}`;
    const g = groups.find((x) => x.key === key);
    if (g) g.rows.push(r);
    else groups.push({ key, table: r.table, asWho: r.as_who, rows: [r] });
  }
  return (
    <div className={compact ? "proof-rows proof-rows-compact" : "proof-rows"}>
      {groups.map((g) => {
        const all = [...new Set(g.rows.flatMap((r) => Object.keys(r.row)))];
        const { cols, whole } = compact ? compactColumns(g.rows) : { cols: all, whole: new Set<string>() };
        return (
          <figure key={g.key} className="proof-rows-group">
            <figcaption>
              Read from <code>{g.table}</code> as {AS_WHO[g.asWho]}
            </figcaption>
            <div className="proof-rows-scroll">
              <table>
                <thead>
                  <tr>
                    {cols.map((c) => (
                      <th key={c} scope="col">
                        {c}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {g.rows.map((r, i) => (
                    <tr key={i}>
                      {cols.map((c) => (
                        <td key={c} data-col={c} className={whole.has(c) ? "proof-cell-whole" : undefined}>
                          {cell(r.row[c])}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </figure>
        );
      })}
    </div>
  );
}
