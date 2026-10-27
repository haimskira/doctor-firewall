import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import type { AttackSurface, AttackTarget, Me, Snapshot } from '../api/types';
import { AuthProvider } from '../auth/AuthProvider';
import { I18nProvider } from '../i18n/I18nProvider';
import { mockFetch } from '../test/fetchMock';
import { AttackSurfacePage } from './AttackSurfacePage';

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
const TARGETS: AttackTarget[] = [
  { id: 'GOLD|SAP', label: 'SAP', tier: 'GOLD', networks: ['10.3.0.0/24'] },
  { id: 'SILVER|CRM', label: 'CRM', tier: 'SILVER', networks: ['10.2.0.0/24'] },
];
const rule = (name: string, index: number, inspected: boolean) => ({
  policy_id: 'p1', policy: 'ACP', id: `r${String(index)}`, name, index, action: 'ALLOW', inspected, partial: false, default: false, hits: 4,
});
const SURFACE: AttackSurface = {
  mode: 'to',
  origin: { nodes: ['GOLD|SAP'], networks: ['10.3.0.0/24'] },
  nodes: [
    { id: 'GOLD|SAP', label: 'SAP', tier: 'GOLD', kind: 'origin', depth: 0, networks: ['10.3.0.0/24'] },
    { id: 'SILVER|CRM', label: 'CRM', tier: 'SILVER', kind: 'system', depth: 1, networks: ['10.2.0.0/25'] },
    { id: 'ANY', label: 'ANY', tier: null, kind: 'anywhere', depth: 2, networks: ['any'] },
  ],
  edges: [
    { id: 'SILVER|CRM->GOLD|SAP', src: 'SILVER|CRM', dst: 'GOLD|SAP', depth: 1, services: ['tcp/1433'], apps: [], rules: [rule('CRM_TO_SAP', 12, true)], rule_count: 1, risk: 'green' },
    { id: 'ANY->SILVER|CRM', src: 'ANY', dst: 'SILVER|CRM', depth: 2, services: ['any'], apps: [], rules: [rule('TEMP_ANY', 3, false)], rule_count: 1, risk: 'red' },
  ],
  paths: [
    {
      score: 120,
      reasons: ['anywhere', 'pivot', 'uninspected', 'any_service'],
      steps: [
        { nodes: ['ANY'], networks: ['any'] },
        { nodes: ['SILVER|CRM'], networks: ['10.2.0.0/25'] },
        { nodes: ['GOLD|SAP'], networks: ['10.3.0.0/24'] },
      ],
      hops: [
        { services: ['any'], apps: [], rules: [rule('TEMP_ANY', 3, false)], rule_count: 1 },
        { services: ['tcp/1433'], apps: [], rules: [{ ...rule('CRM_TO_SAP', 12, true), conditions: [{ field: 'src_sgt', name: 'SGT_FIN' }] }], rule_count: 1 },
      ],
    },
    {
      score: 50,
      reasons: ['direct'],
      steps: [
        { nodes: ['SILVER|CRM'], networks: ['10.2.0.0/25'] },
        { nodes: ['GOLD|SAP'], networks: ['10.3.0.0/24'] },
      ],
      hops: [{ services: ['tcp/1433'], apps: [], rules: [rule('CRM_TO_SAP', 12, true)], rule_count: 1 }],
    },
  ],
  summary: { paths: 2, entry_points: 2, anywhere: true, shortest: 1, services: ['tcp/1433'], reached: 2, truncated: false },
};

function setup(path: string) {
  const calls = mockFetch((req) => {
    if (req.url === '/api/auth/me') return { status: 200, body: ME };
    if (req.url.startsWith('/api/snapshots?')) return { status: 200, body: [SNAP] };
    if (req.url === '/api/snapshots/7/attack-surface/targets') return { status: 200, body: TARGETS };
    if (req.url === '/api/snapshots/7/clusters') return { status: 200, body: [] };
    if (req.url.startsWith('/api/snapshots/7/attack-surface?')) return { status: 200, body: SURFACE };
    return { status: 404, body: { detail: 'not_found' } };
  });
  render(
    <I18nProvider>
      <AuthProvider>
        <MemoryRouter initialEntries={[path]}>
          <Routes>
            <Route path="/attack" element={<AttackSurfacePage />} />
          </Routes>
        </MemoryRouter>
      </AuthProvider>
    </I18nProvider>,
  );
  return calls;
}

describe('AttackSurfacePage', () => {
  it('asks for a target, then maps every way to it with ranked paths and their rules', async () => {
    const calls = setup('/attack');
    expect(await screen.findByText(/Choose a system from the asset table/)).toBeInTheDocument();
    const user = userEvent.setup();
    await screen.findByRole('option', { name: 'SAP' }); // the targets list has loaded
    await user.selectOptions(screen.getByRole('combobox', { name: 'Target' }), 'GOLD|SAP');
    await waitFor(() => {
      expect(calls.some((c) => c.url === '/api/snapshots/7/attack-surface?mode=to&depth=3&system=GOLD%7CSAP')).toBe(true);
    });

    const summary = await screen.findByRole('region', { name: 'Summary' });
    expect(within(summary).getByText('Reachable from anywhere').previousSibling).toHaveTextContent('Yes');
    expect(within(summary).getByText('tcp/1433')).toBeInTheDocument();

    const map = screen.getByRole('img', { name: 'Attack surface map' });
    expect(within(map).getByRole('button', { name: 'Anywhere' })).toBeInTheDocument(); // translated

    const paths = screen.getByRole('region', { name: 'Paths, most dangerous first' });
    const top = within(paths).getByRole('button', { name: /Anywhere\s*→\s*CRM\s*→\s*SAP/ });
    expect(within(paths).getByText('hop without IPS')).toBeInTheDocument();
    await user.click(top);
    expect(top).toHaveAttribute('aria-expanded', 'true');
    expect(within(paths).getByRole('link', { name: '#3 TEMP_ANY' })).toHaveAttribute('href', '/rules?snapshot=7&policy=p1&q=TEMP_ANY');
    // A hop that also needs an SGT says so (the map is drawn from addresses alone).
    expect(within(paths).getByText('SGT_FIN').closest('.atk-conditions')).toHaveTextContent('only for: source SGT: SGT_FIN');
    // The path is highlighted on the map: the other edges are dimmed, its own are not.
    const edges = map.querySelectorAll('path.atk-edge');
    expect([...edges].every((e) => !e.classList.contains('dim'))).toBe(true);

    // A system on the map shows its networks and dims what does not touch it.
    await user.click(within(map).getByRole('button', { name: 'SAP' }));
    expect(screen.getByText('The analysed target / source.')).toBeInTheDocument();
  });

  it('runs a blast radius from a typed address', async () => {
    const calls = setup('/attack?mode=from');
    const user = userEvent.setup();
    await user.type(await screen.findByRole('searchbox', { name: 'or address / network' }), '10.1.0.0/24');
    await user.click(screen.getByRole('button', { name: 'Analyse' }));
    await waitFor(() => {
      expect(calls.some((c) => c.url === '/api/snapshots/7/attack-surface?mode=from&depth=3&address=10.1.0.0%2F24')).toBe(true);
    });
    expect(screen.getByRole('button', { name: 'Blast radius from a source' })).toHaveAttribute('aria-pressed', 'true');
  });
});
