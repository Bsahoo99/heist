import { afterEach, describe, expect, test } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { ProofRows, compactColumns } from "./ProofRows";
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

  test("compact: owner and email first and whole, at most two columns then", () => {
    const rows = [
      {
        table: "adoption_requests",
        as_who: "another_user" as const,
        row: {
          user_id: "Test Alice (user id)",
          email: "alice@example.test",
          phone: "555-0100",
          message: "Fake note for testing",
          id: "a8bd332d-073c-4383-8f69-d81d2d1a6e0d",
        },
      },
    ];
    expect(compactColumns(rows).cols).toEqual(["user_id", "email"]);
    render(<ProofRows rows={rows} compact />);
    const headers = screen.getAllByRole("columnheader").map((h) => h.textContent);
    expect(headers).toEqual(["user_id", "email"]);
    const owner = screen.getByText("Test Alice (user id)");
    const email = screen.getByText("alice@example.test");
    expect(owner.className).toContain("proof-cell-whole");
    expect(email.className).toContain("proof-cell-whole");
  });

  test("compact: an owner with other columns keeps three", () => {
    const rows = [
      {
        table: "messages",
        as_who: "anonymous" as const,
        row: { sender_id: "Test Alice (user id)", body: "Fake note for testing", id: "x" },
      },
    ];
    expect(compactColumns(rows).cols).toEqual(["sender_id", "body"]);
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
