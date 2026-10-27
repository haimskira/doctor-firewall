import { describe, expect, it } from 'vitest';

// A translation call written as JSX text (`<th>t('x')</th>`) renders the literal code instead
// of the text. Scan every page and component for it.
const SOURCES = import.meta.glob<string>(['../pages/*.tsx', '../components/*.tsx'], {
  query: '?raw',
  import: 'default',
  eager: true,
});

describe('JSX text', () => {
  it('never shows a translation call as literal text', () => {
    const offenders = Object.entries(SOURCES).flatMap(([file, source]) =>
      source
        .split('\n')
        .map((line, n) => ({ file, n: n + 1, line }))
        .filter(({ line }) => />\s*t\('[^']+'\)\s*</.test(line)),
    );
    expect(Object.keys(SOURCES).length).toBeGreaterThan(20);
    expect(offenders).toEqual([]);
  });
});
