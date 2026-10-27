import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { Me } from '../api/types';
import { AuthProvider } from '../auth/AuthProvider';
import { I18nProvider } from '../i18n/I18nProvider';
import { mockFetch } from '../test/fetchMock';
import { HistoryPage } from './HistoryPage';

const ME: Me = {
  id: 1,
  username: 'appr',
  display_name: 'Appr',
  roles: ['approver'],
  permissions: ['policy:read', 'deploy:approve'],
  language: 'en',
  auth_provider: 'local',
  must_change_password: false,
  theme: 'system',
  csrf_token: 'csrf-1',
};

const ENTRY = {
  changeset_id: 5,
  title: 'Q4 clean-up',
  ticket_id: 'CHG-9',
  created_by: 'opt',
  snapshot_id: 17,
  seq: 2,
  status: 'deployed',
  op_count: 3,
  approved_by: 'appr2',
  started_at: '2026-10-27T09:00:00Z',
  finished_at: '2026-10-27T09:05:00Z',
  error: null,
  proof: { ok: true, flows: 120, differences: 0, behavior: 'preserves' },
  proof_after: { ok: true, flows: 120, differences: 0 },
  revert_blocker: null,
};

const CHANGES = [
  {
    op: 'update_rule',
    label: 'MIXED_TIERS_SQL',
    what: 'rule',
    action: 'changed',
    fields: [{ field: 'destinationNetworks', before: 'NET_GOLD_DB, NET_SILVER_APP', after: 'NET_GOLD_DB' }],
    undone: false,
  },
  { op: 'create_rule', label: 'MIXED_TIERS_SQL_SILVER', what: 'rule', action: 'created', fields: [], undone: false },
];

afterEach(() => {
  vi.restoreAllMocks();
});

describe('HistoryPage', () => {
  it('shows each batch with its proof, its changes before / after, and reverts it', async () => {
    const calls = mockFetch((req) => {
      if (req.url === '/api/auth/me') return { status: 200, body: ME };
      if (req.url.startsWith('/api/history?')) return { status: 200, body: [ENTRY] };
      if (req.url === '/api/changesets/5/batches/2/changes') return { status: 200, body: CHANGES };
      if (req.url === '/api/changesets/5/batches/2/revert') return { status: 202, body: { run_id: 9, batches: [{ changeset_id: 5, batch: 2 }] } };
      if (req.url.startsWith('/api/jobs')) return { status: 200, body: { active: 0, rows: [] } };
      return { status: 404, body: { detail: 'not_found' } };
    });
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true);
    render(
      <I18nProvider>
        <AuthProvider>
          <MemoryRouter initialEntries={['/history']}>
            <Routes>
              <Route path="/history" element={<HistoryPage />} />
            </Routes>
          </MemoryRouter>
        </AuthProvider>
      </I18nProvider>,
    );
    const user = userEvent.setup();
    const row = (await screen.findByRole('button', { name: /Q4 clean-up · Batch 2/ })).closest('tr');
    if (row === null) throw new Error('row');
    expect(within(row).getByText('verified: no flow changed (120 checked)')).toBeInTheDocument();
    expect(within(row).getByRole('link', { name: 'Policy before' })).toHaveAttribute('href', '/rules?snapshot=17');

    await user.click(within(row).getByRole('button', { name: /Q4 clean-up · Batch 2/ }));
    expect(await screen.findByText('MIXED_TIERS_SQL_SILVER')).toBeInTheDocument();
    expect(screen.getByText('NET_GOLD_DB, NET_SILVER_APP')).toBeInTheDocument();
    expect(screen.getAllByText('Created').length).toBeGreaterThan(0);

    await user.click(within(row).getByRole('button', { name: 'Revert' }));
    expect(confirm).toHaveBeenLastCalledWith(expect.stringContaining('Revert Q4 clean-up · batch 2?'));
    await waitFor(() => {
      expect(calls.some((c) => c.method === 'POST' && c.url === '/api/changesets/5/batches/2/revert')).toBe(true);
    });
    expect(await screen.findByText(/Revert of 1 batch\(es\) queued/)).toBeInTheDocument();
  });
});
