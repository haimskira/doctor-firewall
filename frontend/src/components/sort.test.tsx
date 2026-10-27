import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import { I18nProvider } from '../i18n/I18nProvider';
import { SortedTable, SortTh, useServerSort } from './sort';

interface Row {
  name: string;
  rules: number;
  seen: string | null;
}

const ROWS: Row[] = [
  { name: 'host-10', rules: 3, seen: '2026-10-02T10:00:00Z' },
  { name: 'host-9', rules: 120, seen: null },
  { name: 'Alpha', rules: 3, seen: '2026-10-05T10:00:00Z' },
];

function Table() {
  return (
    <table>
      <SortedTable
        rows={ROWS}
        columns={{ name: (r) => r.name, rules: (r) => r.rules, seen: (r) => r.seen }}
        head={(th) => (
          <tr>
            {th('name', 'Name')}
            {th('rules', 'Rules', true)}
            {th('seen', 'Seen', true)}
          </tr>
        )}
      >
        {(r) => (
          <tr key={r.name}>
            <td>{r.name}</td>
          </tr>
        )}
      </SortedTable>
    </table>
  );
}

function names(): string[] {
  const body = screen.getAllByRole('rowgroup')[1];
  if (body === undefined) throw new Error('no body');
  return within(body)
    .getAllByRole('row')
    .map((tr) => tr.textContent);
}

describe('SortedTable', () => {
  it('sorts numbers from the largest first, toggles, and keeps ties and blanks stable', async () => {
    render(
      <I18nProvider initial="en">
        <Table />
      </I18nProvider>,
    );
    const user = userEvent.setup();
    expect(names()).toEqual(['host-10', 'host-9', 'Alpha']); // server order until a click

    const rules = screen.getByRole('columnheader', { name: /Rules/ });
    await user.click(within(rules).getByRole('button'));
    expect(rules).toHaveAttribute('aria-sort', 'descending');
    expect(names()).toEqual(['host-9', 'host-10', 'Alpha']); // tie keeps original order
    await user.click(within(rules).getByRole('button'));
    expect(rules).toHaveAttribute('aria-sort', 'ascending');
    expect(names()).toEqual(['host-10', 'Alpha', 'host-9']);

    // Text: natural order (host-9 before host-10), case-insensitive; the other header resets.
    const name = screen.getByRole('columnheader', { name: /Name/ });
    await user.click(within(name).getByRole('button'));
    expect(name).toHaveAttribute('aria-sort', 'ascending');
    expect(rules).toHaveAttribute('aria-sort', 'none');
    expect(names()).toEqual(['Alpha', 'host-9', 'host-10']);

    // Empty values go last in both directions.
    const seen = screen.getByRole('columnheader', { name: /Seen/ });
    await user.click(within(seen).getByRole('button'));
    expect(names()).toEqual(['Alpha', 'host-10', 'host-9']);
    await user.click(within(seen).getByRole('button'));
    expect(names()).toEqual(['host-10', 'Alpha', 'host-9']);
  });
});

function ServerHeader() {
  const sort = useServerSort(['rule_refs', 'name']);
  const location = useLocation();
  return (
    <table>
      <thead>
        <tr>
          <SortTh label="Rules" sortKey="rule_refs" state={sort.state} onSort={sort.onSort} numeric />
        </tr>
      </thead>
      <tbody>
        <tr>
          <td data-testid="search">{location.search}</td>
        </tr>
      </tbody>
    </table>
  );
}

describe('useServerSort', () => {
  it('keeps the order in the URL, resets paging and ignores unknown columns', async () => {
    render(
      <I18nProvider initial="en">
        <MemoryRouter initialEntries={['/objects?sort=evil&offset=200&kind=host']}>
          <Routes>
            <Route path="/objects" element={<ServerHeader />} />
          </Routes>
        </MemoryRouter>
      </I18nProvider>,
    );
    const header = screen.getByRole('columnheader', { name: /Rules/ });
    expect(header).toHaveAttribute('aria-sort', 'none'); // "evil" is not an allowed column
    await userEvent.click(within(header).getByRole('button'));
    expect(header).toHaveAttribute('aria-sort', 'descending');
    const search = new URLSearchParams(screen.getByTestId('search').textContent);
    expect(search.get('sort')).toBe('rule_refs');
    expect(search.get('order')).toBe('desc');
    expect(search.get('offset')).toBeNull();
    expect(search.get('kind')).toBe('host');
  });
});
