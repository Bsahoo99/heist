/** Example repos offered as one-click chips on the landing page. */
export type Example = {
  label: string;
  /** A public GitHub URL. Entries without one are not shown. */
  url?: string;
};

export const EXAMPLES: Example[] = [
  // Task 21 fills in these two URLs once the demo and clean apps are public repos.
  { label: "Demo app" },
  { label: "Clean app" },
];

export const shownExamples = (examples: Example[] = EXAMPLES) =>
  examples.filter((e): e is Required<Example> => Boolean(e.url));
