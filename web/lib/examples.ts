/** Example repos offered as one-click chips on the landing page. */
export type Example = {
  label: string;
  /** A public GitHub URL. Entries without one are not shown. */
  url?: string;
};

export const EXAMPLES: Example[] = [
  { label: "Demo app", url: "https://github.com/Bsahoo99/pawhaven" },
  { label: "Clean app", url: "https://github.com/Bsahoo99/pawhaven-fixed" },
];

export const shownExamples = (examples: Example[] = EXAMPLES) =>
  examples.filter((e): e is Required<Example> => Boolean(e.url));
