/** Test helper: a plural-aware text function rendered for n = 0, 1, 2. */
export function pluralCases(fn: (n: number) => string): string[] {
  return [0, 1, 2].map((n) => fn(n));
}
