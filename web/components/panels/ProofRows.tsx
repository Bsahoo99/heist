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

/**
 * The fake rows the proof read back from a throwaway copy of the database.
 * One table per (table, who asked) pair. Values are plain text.
 *
 * `compact` (the replay's climax card): at most 3 columns, id columns left
 * out, one line per cell.
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
        const named = all.filter((c) => !ID_COLUMN.test(c));
        const cols = compact ? (named.length ? named : all).slice(0, 3) : all;
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
                        <td key={c} data-col={c}>
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
