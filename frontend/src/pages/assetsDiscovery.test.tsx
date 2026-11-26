import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import type { Me, Snapshot } from '../api/types';
import { AuthProvider } from '../auth/AuthProvider';
import { I18nProvider } from '../i18n/I18nProvider';
import { mockFetch } from '../test/fetchMock';
import type { Recorded } from '../test/fetchMock';
import { AssetsPage } from './AssetsPage';

const ME: Me = {
  id: 1, username: 'opt', display_name: 'Opt', roles: ['optimizer'],
  permissions: ['policy:read', 'collect:run', 'assets:write'], language: 'en',
  auth_provider: 'local', must_change_password: false, theme: 'system', csrf_token: 'csrf-2',
};
const SNAP = { id: 7, connection_id: 1, connection_name: 'FMC', status: 'complete', requested_by: 'x', created_at: '2026-10-20T10:00:00Z', started_at: null, finished_at: null, analyzed_at: null, fmc_version: null, error: null, error_detail: null, stats: {} } satisfies Snapshot;

const SEGMENT = {
  id: 5, network: '10.20.0.0/16', name: 'SDA-A', role: 'sda_users', domain: null, cluster: 'FTD-CL01', interface: 'Port-channel1.200', zone: 'USERS',
  gateway: true, in_dc: false, source: 'discovery', confirmed: false, confidence: 80, evidence: [{ source: 'interface', detail: 'Port-channel1.200 10.20.0.1/16' }], notes: '', updated_by: 'x',
};
const SUGGESTION = {
  id: 20, name: 'SRV-DB', kind: 'server', tier: 'GOLD', user_type: null, owner: '', description: '', updated_by: 'x', components: [], source: 'discovery',
  confirmed: false, domain: null, confidence: 70, evidence: [{ source: 'names', detail: 'DB-*' }],
};

function setup(path: string): Recorded[] {
  const calls = mockFetch((req) => {
    if (req.url === '/api/auth/me') return { status: 200, body: ME };
    if (req.url.startsWith('/api/snapshots?')) return { status: 200, body: [SNAP] };
    if (req.url === '/api/asset-groups' && req.method === 'GET') return { status: 200, body: [SUGGESTION] };
    if (req.url === '/api/assets' && req.method === 'GET') return { status: 200, body: [] };
    if (req.url === '/api/segments' && req.method === 'GET') return { status: 200, body: [SEGMENT] };
    if (req.url === '/api/asset-domains' && req.method === 'GET') return { status: 200, body: [] };
    if (req.url === '/api/assets/discover') return { status: 200, body: { segments: 12, assets: 5, components: 90, domains: 2, replaced: 3, skipped: 0 } };
    if (req.url === '/api/segments/5') return { status: 200, body: { ...SEGMENT, role: 'dc_servers', confirmed: true } };
    if (req.url === '/api/asset-groups/confirm') return { status: 200, body: { confirmed: 1 } };
    if (req.url === '/api/assets/purge') return { status: 200, body: { deleted: 4 } };
    return { status: 404, body: { detail: 'not_found' } };
  });
  render(
    <I18nProvider>
      <AuthProvider>
        <MemoryRouter initialEntries={[path]}>
          <Routes>
            <Route path="/assets" element={<AssetsPage />} />
          </Routes>
        </MemoryRouter>
      </AuthProvider>
    </I18nProvider>,
  );
  return calls;
}

describe('asset discovery', () => {
  it('runs discovery for the snapshot and shows the summary', async () => {
    const calls = setup('/assets');
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Smart asset discovery' }));
    expect(await screen.findByText(/12 segments, 5 assets, 90 components, 2 domains, 3 old suggestions replaced/)).toBeInTheDocument();
    expect(calls.find((c) => c.url === '/api/assets/discover')?.body).toEqual({ snapshot_id: 7 });
  });

  it('approves all suggestions and lets the evidence expand', async () => {
    const calls = setup('/assets');
    const user = userEvent.setup();
    expect(await screen.findByText('SRV-DB')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Show evidence (1)' }));
    expect(screen.getByText('DB-*')).toBeInTheDocument();
    expect(screen.getByText('Names')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Approve all' }));
    await waitFor(() => {
      expect(calls.find((c) => c.url === '/api/asset-groups/confirm')?.body).toEqual({ all: true });
    });
  });

  it('shows segments with a translated role and patches a changed role', async () => {
    const calls = setup('/assets?tab=segments');
    const user = userEvent.setup();
    expect(await screen.findByText('10.20.0.0/16')).toBeInTheDocument();
    expect(screen.getByText('The FTD is the gateway')).toBeInTheDocument();
    const select = screen.getByLabelText('Role — 10.20.0.0/16');
    expect(within(select).getByRole('option', { name: 'SDA users' })).toBeInTheDocument();
    await user.selectOptions(select, 'dc_servers');
    await waitFor(() => {
      expect(calls.find((c) => c.url === '/api/segments/5' && c.method === 'PATCH')?.body).toEqual({ role: 'dc_servers' });
    });
  });

  it('gives the segment name and notes a column each, with a placeholder', async () => {
    setup('/assets?tab=segments');
    expect(await screen.findByText('10.20.0.0/16')).toBeInTheDocument();
    const table = screen.getByRole('table');
    expect(within(table).getByRole('columnheader', { name: /Notes/ })).toBeInTheDocument();
    const name = screen.getByLabelText('Name — 10.20.0.0/16');
    const notes = screen.getByLabelText('Notes — 10.20.0.0/16');
    expect(name).toHaveAttribute('placeholder', 'Name');
    expect(notes).toHaveAttribute('placeholder', 'Notes');
    expect(name.closest('td')).not.toBe(notes.closest('td'));
  });

  it('sends a purge only after DELETE is typed', async () => {
    const calls = setup('/assets');
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Delete all assets' }));
    const dialog = screen.getByRole('dialog');
    const confirm = within(dialog).getByRole('button', { name: 'Delete' });
    expect(confirm).toBeDisabled();
    await user.type(within(dialog).getByLabelText('Type DELETE to confirm'), 'DELET');
    expect(confirm).toBeDisabled();
    expect(calls.some((c) => c.url === '/api/assets/purge')).toBe(false);
    await user.type(within(dialog).getByLabelText('Type DELETE to confirm'), 'E');
    await user.click(confirm);
    await waitFor(() => {
      expect(calls.find((c) => c.url === '/api/assets/purge')?.body).toEqual({ scope: 'all', confirm: 'DELETE' });
    });
  });
});
