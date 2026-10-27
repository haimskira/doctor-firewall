import { render, screen, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import type { Me, Snapshot } from '../api/types';
import { AuthProvider } from '../auth/AuthProvider';
import { isAhead, PHASE_OF, PHASES } from '../components/roadmap';
import type { Roadmap } from '../components/roadmap';
import { I18nProvider } from '../i18n/I18nProvider';
import { mockFetch } from '../test/fetchMock';
import { RoadmapPage } from './RoadmapPage';

const ME: Me = {
  id: 1,
  username: 'viewer',
  display_name: 'Viewer',
  roles: ['viewer'],
  permissions: ['policy:read'],
  language: 'en',
  auth_provider: 'local',
  must_change_password: false,
  theme: 'system',
  csrf_token: 'csrf-1',
};
const SNAP: Snapshot = {
  id: 7,
  connection_id: 1,
  connection_name: 'FMC-HA',
  status: 'complete',
  requested_by: 'opt',
  created_at: '2026-10-19T10:00:00Z',
  started_at: '2026-10-19T10:00:00Z',
  finished_at: '2026-10-19T10:01:00Z',
  analyzed_at: '2026-10-19T10:02:00Z',
  fmc_version: '10.1.0 (build 117)',
  error: null,
  error_detail: null,
  stats: { rules: 3, objects: 10, clusters: 1 },
};
const zero = { total: 0, open: 0, accepted: 0, staged: 0, dismissed: 0, ace_delta: 0 };
const ROAD: Roadmap = {
  snapshot_id: 7,
  prepare: [
    { code: 'assets', ok: true, args: { count: 42 } },
    { code: 'limits', ok: false, args: { unverified: 1, clusters: 2 } },
    { code: 'hits', ok: true, args: { with_hits: 300, rules: 300, days: 90 } },
    { code: 'fresh', ok: true, args: {} },
  ],
  phases: [
    {
      name: 'never_match',
      status: 'done',
      behavior: 'preserves',
      ...zero,
      total: 5,
      staged: 5,
      kinds: [{ kind: 'remove_shadowed_rule', ...zero, total: 5, staged: 5 }],
    },
    {
      name: 'objects',
      status: 'current',
      behavior: 'preserves',
      ...zero,
      total: 30,
      open: 20,
      accepted: 4,
      dismissed: 6,
      ace_delta: -35464,
      kinds: [
        { kind: 'compact_group', ...zero, total: 10, open: 10, ace_delta: -35464 },
        { kind: 'merge_duplicate_objects', ...zero, total: 20, open: 10, accepted: 4, dismissed: 6 },
      ],
    },
    { name: 'structure', status: 'next', behavior: 'preserves', ...zero, total: 3, open: 3, kinds: [{ kind: 'split_rule', ...zero, total: 3, open: 3 }] },
    { name: 'access', status: 'next', behavior: 'changes', ...zero, kinds: [] },
    { name: 'closing', status: 'next', behavior: 'preserves', ...zero, total: 9, open: 9, kinds: [{ kind: 'remove_unused_object', ...zero, total: 9, open: 9 }] },
  ],
  current: 'objects',
};

describe('RoadmapPage', () => {
  it('shows the preparation, the phases in order and where the project stands', async () => {
    mockFetch((req) => {
      if (req.url === '/api/auth/me') return { status: 200, body: ME };
      if (req.url.startsWith('/api/snapshots?')) return { status: 200, body: [SNAP] };
      if (req.url === '/api/snapshots/7/roadmap') return { status: 200, body: ROAD };
      return { status: 404, body: { detail: 'not_found' } };
    });
    render(
      <I18nProvider>
        <AuthProvider>
          <MemoryRouter initialEntries={['/roadmap']}>
            <Routes>
              <Route path="/roadmap" element={<RoadmapPage />} />
            </Routes>
          </MemoryRouter>
        </AuthProvider>
      </I18nProvider>,
    );
    expect(await screen.findByText('1 of 2 clusters still use the default ACE / deploy limits.')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Set the limits' })).toHaveAttribute('href', '/clusters');

    const steps = screen.getAllByRole('listitem').filter((li) => li.classList.contains('road-phase'));
    expect(steps.map((s) => within(s).getByRole('heading').textContent)).toEqual([
      '1 Rules that match nothing',
      '2 Objects and groups',
      '3 Rule structure by tier',
      '4 Changes to access',
      '5 Closing',
    ]);
    const step = (i: number): HTMLElement => {
      const el = steps.at(i);
      if (el === undefined) throw new Error(`phase ${String(i)}`);
      return el;
    };
    const now = step(1);
    expect(now).toHaveAttribute('aria-current', 'step');
    expect(within(now).getByText('Now')).toBeInTheDocument();
    expect(within(now).getByText(/20 to decide · 4 accepted, not staged · 0 in a changeset · 6 dismissed/)).toBeInTheDocument();
    expect(within(now).getByText(/saves ~35,464 ACEs/)).toBeInTheDocument();
    expect(within(now).getByRole('link', { name: 'Decide this phase (20)' })).toHaveAttribute(
      'href',
      '/recommendations?snapshot=7&phase=objects&state=open',
    );
    expect(within(now).getByRole('link', { name: /Compact group/ })).toHaveAttribute('href', '/recommendations?snapshot=7&kind=compact_group');
    expect(within(step(0)).getByText('Done')).toBeInTheDocument();
    expect(within(step(3)).getByText('Changes access')).toBeInTheDocument();
    expect(within(step(3)).getByText('Nothing to do in this snapshot.')).toBeInTheDocument();
  });

  it('knows which recommendations are ahead of the current phase', () => {
    expect(Object.values(PHASE_OF).every((p) => PHASES.includes(p))).toBe(true);
    expect(isAhead('remove_unused_object', 'objects')).toBe(true);
    expect(isAhead('compact_group', 'objects')).toBe(false);
    expect(isAhead('remove_shadowed_rule', 'objects')).toBe(false);
    expect(isAhead('remove_unused_object', null)).toBe(false);
  });
});
