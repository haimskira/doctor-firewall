import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';

import type { Me, Snapshot } from '../api/types';
import { AuthProvider } from '../auth/AuthProvider';
import { I18nProvider } from '../i18n/I18nProvider';
import { mockFetch } from '../test/fetchMock';
import { ObjectsPage } from './ObjectsPage';

const ME: Me = {
  id: 1, username: 'v', display_name: 'V', auth_provider: 'local', roles: ['viewer'], permissions: ['policy:read'],
  language: 'en', theme: 'system', must_change_password: false, csrf_token: 'c',
};
const SNAP = {
  id: 7, connection_id: 1, connection_name: 'FMC', status: 'complete', requested_by: 'x', created_at: '2026-10-27T10:00:00Z',
  started_at: null, finished_at: null, analyzed_at: '2026-10-27T10:05:00Z', fmc_version: null, error: null, error_detail: null, stats: {},
} satisfies Snapshot;
const POLICY = {
  id: 'p1', kind: 'access', name: 'ACP-1', default_action: 'BLOCK', rule_count: 3, links: [], attrs: {}, clusters: ['c1'],
};

describe('ObjectsPage policy scope', () => {
  it('sends ?policy= and offers the policy picker', async () => {
    const calls = mockFetch((req) => {
      if (req.url === '/api/auth/me') return { status: 200, body: ME };
      if (req.url.startsWith('/api/snapshots?')) return { status: 200, body: [SNAP] };
      if (req.url === '/api/snapshots/7/policies') return { status: 200, body: [POLICY] };
      if (req.url.startsWith('/api/snapshots/7/objects?')) return { status: 200, body: { total: 0, offset: 0, rows: [] } };
      return { status: 404 };
    });
    render(
      <I18nProvider>
        <AuthProvider>
          <MemoryRouter initialEntries={['/objects?snapshot=7&policy=p1']}>
            <Routes>
              <Route path="/objects" element={<ObjectsPage />} />
            </Routes>
          </MemoryRouter>
        </AuthProvider>
      </I18nProvider>,
    );
    expect(await screen.findByRole('combobox', { name: /Policy/ })).toHaveValue('p1');
    await vi.waitFor(() => {
      expect(calls.some((c) => c.url.startsWith('/api/snapshots/7/objects?') && c.url.includes('policy=p1'))).toBe(true);
    });
  });

  it('groups objects into category tabs with counts and filters by the tab kinds', async () => {
    const KINDS = { kinds: [
      { kind: 'host', total: 5, unused: 2 },
      { kind: 'network_group', total: 3, unused: 0 },
      { kind: 'port', total: 4, unused: 1 },
    ] };
    const calls = mockFetch((req) => {
      if (req.url === '/api/auth/me') return { status: 200, body: ME };
      if (req.url.startsWith('/api/snapshots?')) return { status: 200, body: [SNAP] };
      if (req.url === '/api/snapshots/7/policies') return { status: 200, body: [POLICY] };
      if (req.url.startsWith('/api/snapshots/7/object-kinds')) return { status: 200, body: KINDS };
      if (req.url.startsWith('/api/snapshots/7/objects?')) return { status: 200, body: { total: 0, offset: 0, rows: [] } };
      return { status: 404 };
    });
    render(
      <I18nProvider>
        <AuthProvider>
          <MemoryRouter initialEntries={['/objects?snapshot=7']}>
            <Routes>
              <Route path="/objects" element={<ObjectsPage />} />
            </Routes>
          </MemoryRouter>
        </AuthProvider>
      </I18nProvider>,
    );
    const network = await screen.findByRole('tab', { name: /Network\s*8/ });
    expect(screen.getByRole('tab', { name: /Services\s*4/ })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: /All types\s*12/ })).toHaveAttribute('aria-selected', 'true');
    expect(screen.queryByRole('tab', { name: /Zones/ })).toBeNull();
    fireEvent.click(network);
    expect(await screen.findByRole('button', { name: /Unused \(2\)/ })).toBeInTheDocument();
    const last = () => calls.filter((c) => c.url.startsWith('/api/snapshots/7/objects?')).at(-1)?.url ?? '';
    await screen.findByRole('button', { name: /Network group/ });
    expect(last()).toContain('kind=host');
    expect(last()).toContain('kind=network_group');
    expect(last()).not.toContain('kind=port');
    fireEvent.click(screen.getByRole('button', { name: /Unused \(2\)/ }));
    await vi.waitFor(() => {
      expect(last()).toContain('usage=unused');
    });
  });
});
