import { afterEach, describe, expect, test } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { ProofRows } from "./ProofRows";
import { provedFinding } from "@/tests/helpers/scenes";

afterEach(cleanup);

describe("ProofRows", () => {
  test("shows the leaked fake rows and who could read them", () => {
    render(<ProofRows rows={provedFinding.proof_rows} />);
    const table = screen.getByRole("table");
    expect(table.textContent).toContain("Test Alice");
    expect(table.textContent).toContain("alice@example.test");
    expect(table.textContent).toContain("Test Bob");
    expect(table.textContent).toContain("bob@example.test");
    expect(screen.getByText(/another signed-in user/i)).toBeTruthy();
    expect(screen.getAllByRole("row")).toHaveLength(3); // header + 2
  });

  test("compact: up to 3 columns, no id column", () => {
    render(<ProofRows rows={provedFinding.proof_rows} compact />);
    const headers = screen.getAllByRole("columnheader").map((h) => h.textContent);
    expect(headers).toEqual(["name", "email", "note"]);
    expect(screen.getByRole("table").textContent).toContain("Test Bob");
  });

  test("renders nothing without rows", () => {
    const { container } = render(<ProofRows rows={[]} />);
    expect(container.textContent).toBe("");
  });

  test("values are text, never HTML", () => {
    const { container } = render(
      <ProofRows rows={[{ table: "t", as_who: "anonymous", row: { name: "<b>x</b>", n: 3, nested: { a: 1 } } }]} />,
    );
    expect(container.querySelector("b")).toBeNull();
    expect(container.textContent).toContain("<b>x</b>");
    expect(container.textContent).toContain('{"a":1}');
  });
});
