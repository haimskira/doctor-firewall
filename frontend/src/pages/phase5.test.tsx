import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ReactNode } from 'react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { ChangesetDetail, Me, Permission } from '../api/types';
import { AuthProvider } from '../auth/AuthProvider';
import { I18nProvider } from '../i18n/I18nProvider';
import { mockFetch } from '../test/fetchMock';
import type { Recorded } from '../test/fetchMock';
import { DeployPage } from './DeployPage';

function me(username: string, permissions: Permission[]): Me {
  return {
    id: 1, username, display_name: username, roles: ['approver'], permissions, language: 'en',
    auth_provider: 'local', must_change_password: false, theme: 'system', csrf_token: 'csrf-5',
  };
}

const CS: ChangesetDetail = {
  id: 3, snapshot_id: 7, connection_id: 1, title: 'Q4 clean-up', ticket_id: 'CHG-1001', status: 'in_progress',
  deploy_limit: 2, deploy_limit_verified: false, created_by: 'opt', created_at: '2026-10-21T08:00:00Z',
  op_count: 4, item_count: 3,
  batches: [
    {
      seq: 1, status: 'deployed', op_count: 2, deploy_limit: 2, clusters: ['c1'], approved_by: 'appr',
      approved_at: '2026-10-21T08:10:00Z', started_at: '2026-10-21T08:11:00Z', finished_at: '2026-10-21T08:12:00Z',
      error: null,
      results: [
        { op: 'update_rule', name: 'MIXED', id: 'r12' },
        { op: 'create_rule', name: 'MIXED_SILVER', id: 'r99' },
      ],
    },
    {
      seq: 2, status: 'pending', op_count: 2, deploy_limit: 2, clusters: ['c1'], approved_by: null,
      approved_at: null, started_at: null, finished_at: null, error: null, results: [],
    },
  ],
  items: [
    {
      fingerprint: 'a'.repeat(64), kind: 'split_rule', title: 'Split #12 MIXED', policy_fmc_id: 'p1', batch_seq: 1, op_count: 2,
      plan: { ops: [{ op: 'update_rule', rule_name: 'MIXED' }, { op: 'create_rule', name: 'MIXED_SILVER' }] },
    },
    {
      fingerprint: 'b'.repeat(64), kind: 'rename_role', title: 'Rename GRP_10.30.0.0', policy_fmc_id: null, batch_seq: 2, op_count: 1,
      plan: { ops: [{ op: 'rename_object', object_name: 'GRP_10.30.0.0', name: 'GRP_APPS' }] },
    },
    {
      fingerprint: 'c'.repeat(64), kind: 'remove_unused_object', title: 'Remove GRP_UNUSED', policy_fmc_id: null, batch_seq: 2, op_count: 1,
      plan: { ops: [{ op: 'delete_object', object_name: 'GRP_UNUSED' }] },
    },
  ],
};

function setup(user: Me, cs: ChangesetDetail, extra?: (req: Recorded) => { status: number; body?: unknown } | undefined): Recorded[] {
  const calls = mockFetch((req) => {
    if (req.url === '/api/auth/me') return { status: 200, body: user };
    if (req.url === '/api/changesets') return { status: 200, body: [cs] };
    if (req.url === '/api/changesets/3') return { status: 200, body: cs };
    return extra?.(req) ?? { status: 404, body: { detail: 'not_found' } };
  });
  const routes: ReactNode = <Route path="/deploy" element={<DeployPage />} />;
  render(
    <I18nProvider>
      <AuthProvider>
        <MemoryRouter initialEntries={['/deploy?changeset=3']}>
          <Routes>{routes}</Routes>
        </MemoryRouter>
      </AuthProvider>
    </I18nProvider>,
  );
  return calls;
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('DeployPage', () => {
  it('lets an approver who is not the author approve the next batch', async () => {
    const calls = setup(me('appr', ['policy:read', 'deploy:approve']), CS, (req) =>
      req.url === '/api/changesets/3/batches/2/approve' ? { status: 200, body: CS } : undefined,
    );
    const panel = await screen.findByRole('region', { name: 'Q4 clean-up' });
    expect(within(panel).getByText('CHG-1001')).toBeInTheDocument();
    expect(within(panel).getByText('(unverified default)')).toBeInTheDocument();
    const first = within(panel).getByRole('article', { name: 'Batch 1' });
    expect(within(first).getByText('Deployed')).toBeInTheDocument();
    expect(within(first).getAllByText('Create rule MIXED_SILVER')).toHaveLength(2); // planned + written
    const second = within(panel).getByRole('article', { name: 'Batch 2' });
    expect(within(second).getByText('Rename GRP_10.30.0.0 to GRP_APPS')).toBeInTheDocument();
    expect(within(second).getByText('2 of 2 changes')).toBeInTheDocument();
    // Only the first not-yet-deployed batch can be acted on.
    expect(within(first).queryByRole('button')).not.toBeInTheDocument();
    await userEvent.click(within(second).getByRole('button', { name: 'Approve' }));
    await waitFor(() => {
      expect(calls.some((c) => c.method === 'POST' && c.url === '/api/changesets/3/batches/2/approve')).toBe(true);
    });
    expect(calls.find((c) => c.method === 'POST')?.headers['X-CSRF-Token']).toBe('csrf-5');
  });

  it('asks for confirmation before writing to the FMC', async () => {
    const [done, next] = CS.batches;
    if (done === undefined || next === undefined) throw new Error('fixture');
    const approved: ChangesetDetail = { ...CS, batches: [done, { ...next, status: 'approved', approved_by: 'appr' }] };
    const confirm = vi.spyOn(window, 'confirm');
    confirm.mockReturnValueOnce(false).mockReturnValueOnce(true);
    const calls = setup(me('appr', ['policy:read', 'deploy:approve']), approved, (req) =>
      req.url === '/api/changesets/3/batches/2/run' ? { status: 202, body: approved } : undefined,
    );
    const second = await screen.findByRole('article', { name: 'Batch 2' });
    const run = within(second).getByRole('button', { name: 'Write and deploy' });
    await userEvent.click(run);
    expect(calls.some((c) => c.url.endsWith('/run'))).toBe(false); // declined
    await userEvent.click(run);
    await waitFor(() => {
      expect(calls.some((c) => c.method === 'POST' && c.url === '/api/changesets/3/batches/2/run')).toBe(true);
    });
    expect(confirm).toHaveBeenLastCalledWith(expect.stringContaining('Write batch 2 (2 changes) to the FMC'));
    expect(await screen.findByText(/Batch queued for writing/)).toBeInTheDocument();
  });

  it('never offers approval to the author', async () => {
    setup(me('opt', ['policy:read', 'changeset:write', 'deploy:approve']), CS);
    const panel = await screen.findByRole('region', { name: 'Q4 clean-up' });
    expect(within(panel).getByText(/You authored this changeset/)).toBeInTheDocument();
    expect(within(panel).queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument();
    expect(within(panel).getByRole('button', { name: 'Cancel changeset' })).toBeInTheDocument();
  });

  it('shows a rolled-back batch with its error and offers nothing more', async () => {
    const [first, second] = CS.batches;
    if (first === undefined || second === undefined) throw new Error('fixture');
    const failed: ChangesetDetail = {
      ...CS,
      status: 'failed',
      batches: [
        { ...first, status: 'rolled_back', error: 'drift: rule MIXED: field dst_net changed in the FMC', results: [] },
        second,
      ],
    };
    setup(me('appr', ['policy:read', 'deploy:approve', 'changeset:write']), failed);
    const panel = await screen.findByRole('region', { name: 'Q4 clean-up' });
    const batch = within(panel).getByRole('article', { name: 'Batch 1' });
    expect(within(batch).getByText('Rolled back')).toBeInTheDocument();
    expect(within(batch).getByText('Error: drift: rule MIXED: field dst_net changed in the FMC')).toBeInTheDocument();
    expect(within(panel).queryByRole('button')).not.toBeInTheDocument();
  });
});
