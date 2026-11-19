import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import type { Dossier, Me, Snapshot } from '../api/types';
import { AuthProvider } from '../auth/AuthProvider';
import { I18nProvider } from '../i18n/I18nProvider';
import { mockFetch } from '../test/fetchMock';
import { DossierPage } from './DossierPage';

const ME: Me = {
  id: 1, username: 'v', display_name: 'V', auth_provider: 'local', roles: ['viewer'], permissions: ['policy:read'],
  language: 'en', theme: 'system', must_change_password: false, csrf_token: 'c',
};
const SNAP = {
  id: 7, connection_id: 1, connection_name: 'FMC', status: 'complete', requested_by: 'x', created_at: '2026-10-27T10:00:00Z',
  started_at: null, finished_at: null, analyzed_at: '2026-10-27T10:05:00Z', fmc_version: null, error: null, error_detail: null, stats: {},
} satisfies Snapshot;
const TARGETS = [
  { id: 'CORE|DNA', label: 'DNA', tier: 'CORE', networks: ['10.1.1.10/32'] },
  { id: 'CORE|ISE', label: 'ISE', tier: 'CORE', networks: ['10.2.0.0/24'] },
];
const RULE = {
  policy_id: 'p1', policy: 'ACP', id: 'r1', name: 'PAW to DNA', index: 12, action: 'ALLOW', inspected: false,
  partial: false, default: false, hits: 40, conditions: [], risk: 'yellow' as const, broad: false, services: ['TCP-443'],
};
const DOSSIER: Dossier = {
  system: {
    id: 'CORE|DNA', name: 'DNA', tier: 'CORE', kind: 'system', owner: 'NetOps', description: 'Catalyst Center',
    components: [{ name: 'DNAC-1', network: '10.1.1.10/32', role: 'App', ports: '443' }],
  },
  inbound: [
    {
      key: 'obj:paw', kind: 'object', label: 'H_PAW_025', tier: null, values: ['10.105.0.35/32'],
      services: ['TCP-443', 'TCP-22'], apps: [], conditions: [], rule_count: 1, rules: [RULE], hits: 40,
      risk: 'yellow', broad: 0, specific: 1, inspected: 0, targets: ['DNAC-1'],
    },
  ],
  outbound: [
    {
      key: 'sys:CORE|ISE', kind: 'system', label: 'ISE', tier: 'CORE', values: ['10.2.0.0/24'],
      services: ['TCP-49'], apps: [], conditions: [], rule_count: 1,
      rules: [{ ...RULE, id: 'r2', name: 'DNA to ISE', risk: 'green', services: ['TCP-49'] }],
      hits: 3, risk: 'green', broad: 1, specific: 0, inspected: 1, targets: ['DNAC-1'],
    },
  ],
  summary: { inbound_peers: 1, outbound_peers: 1, inbound_rules: 1, outbound_rules: 1, internal_rules: 2, truncated: false },
};

function at(path: string) {
  const calls = mockFetch((req) => {
    if (req.url === '/api/auth/me') return { status: 200, body: ME };
    if (req.url.startsWith('/api/snapshots?')) return { status: 200, body: [SNAP] };
    if (req.url === '/api/snapshots/7/policies') return { status: 200, body: [] };
    if (req.url === '/api/snapshots/7/attack-surface/targets') return { status: 200, body: TARGETS };
    if (req.url.startsWith('/api/snapshots/7/dossier?')) return { status: 200, body: DOSSIER };
    return { status: 404 };
  });
  render(
    <I18nProvider>
      <AuthProvider>
        <MemoryRouter initialEntries={[path]}>
          <Routes>
            <Route path="/dossier" element={<DossierPage />} />
          </Routes>
        </MemoryRouter>
      </AuthProvider>
    </I18nProvider>,
  );
  return calls;
}

describe('DossierPage', () => {
  it('offers the systems by tier before one is chosen', async () => {
    at('/dossier?snapshot=7');
    expect(await screen.findByRole('button', { name: 'DNA' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'ISE' })).toBeInTheDocument();
  });

  it('draws the system with who reaches it and what it reaches, and explains a peer', async () => {
    const calls = at('/dossier?snapshot=7&system=CORE%7CDNA');
    const paw = await screen.findByRole('button', { name: /H_PAW_025/ });
    expect(calls.some((c) => c.url.includes('/dossier?system=CORE%7CDNA'))).toBe(true);
    expect(screen.getByRole('heading', { level: 2, name: 'DNA' })).toBeInTheDocument();
    expect(screen.getByText('TCP-443 · TCP-22')).toBeInTheDocument(); // the services on the arrow
    expect(screen.getByRole('button', { name: /ISE/ })).toBeInTheDocument();
    fireEvent.click(paw);
    const panel = await screen.findByRole('complementary');
    expect(within(panel).getByRole('link', { name: /PAW to DNA/ })).toHaveAttribute(
      'href',
      '/rules?snapshot=7&policy=p1&q=PAW%20to%20DNA',
    );
    expect(within(panel).getByText('DNAC-1')).toBeInTheDocument();
  });

  it('hides peers reached only through broad rules and filters by text', async () => {
    at('/dossier?snapshot=7&system=CORE%7CDNA&broad=hide');
    expect(await screen.findByRole('button', { name: /H_PAW_025/ })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /: ISE/ })).toBeNull();
    fireEvent.change(screen.getByRole('searchbox', { name: /Filter/ }), { target: { value: 'nothing-like-this' } });
    expect(await screen.findByText('Nothing matches the filters.')).toBeInTheDocument();
  });

  it('lists the peers in a table view', async () => {
    at('/dossier?snapshot=7&system=CORE%7CDNA&view=table');
    expect(await screen.findByRole('cell', { name: /10.105.0.35/ })).toBeInTheDocument();
    expect(screen.getAllByRole('table').length).toBeGreaterThanOrEqual(3);
  });
});
