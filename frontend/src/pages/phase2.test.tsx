import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ReactNode } from 'react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { Me, RuleRow, Snapshot } from '../api/types';
import { AuthProvider } from '../auth/AuthProvider';
import { ReasonList } from '../components/score';
import { I18nProvider } from '../i18n/I18nProvider';
import { mockFetch } from '../test/fetchMock';
import type { Recorded } from '../test/fetchMock';
import { AssetsPage } from './AssetsPage';
import { ClustersPage } from './ClustersPage';
import { RulebasePage } from './RulebasePage';
import { ScoresPage } from './ScoresPage';

const ME: Me = {
  id: 1, username: 'opt', display_name: 'Opt', roles: ['optimizer'],
  permissions: ['policy:read', 'collect:run', 'assets:write'], language: 'en',
  must_change_password: false, csrf_token: 'csrf-2',
};
const SNAP = { id: 7, connection_id: 1, connection_name: 'FMC', status: 'complete', requested_by: 'x', created_at: '2026-10-20T10:00:00Z', started_at: null, finished_at: null, analyzed_at: null, fmc_version: null, error: null, error_detail: null, stats: {} } satisfies Snapshot;

type Handler = (req: Recorded) => { status: number; body?: unknown } | undefined;

function setup(path: string, routes: ReactNode, handler: Handler): Recorded[] {
  const calls = mockFetch((req) => {
    if (req.url === '/api/auth/me') return { status: 200, body: ME };
    if (req.url.startsWith('/api/snapshots?')) return { status: 200, body: [SNAP] };
    return handler(req) ?? { status: 404, body: { detail: 'not_found' } };
  });
  render(
    <I18nProvider>
      <AuthProvider>
        <MemoryRouter initialEntries={[path]}>
          <Routes>{routes}</Routes>
        </MemoryRouter>
      </AuthProvider>
    </I18nProvider>,
  );
  return calls;
}

describe('score reasons', () => {
  it('translates with details and falls back to the code', () => {
    render(
      <I18nProvider initial="en">
        <ReasonList reasons={[{ code: 'tier_skip', points: 30, source: 'BRONZE', destination: 'GOLD' }, { code: 'brand_new_code', points: 1 }, { code: 'unclassified_destination', points: 0 }]} />
      </I18nProvider>,
    );
    expect(screen.getByText(/Skips tiers \(BRONZE to GOLD\)/)).toBeInTheDocument();
    expect(screen.getByText(/brand_new_code/)).toBeInTheDocument();
    expect(screen.getByText('−30')).toBeInTheDocument();
  });

  it('shows "no deductions" for a perfect rule', () => {
    render(
      <I18nProvider initial="en">
        <ReasonList reasons={[]} />
      </I18nProvider>,
    );
    expect(screen.getByText('No deductions.')).toBeInTheDocument();
  });
});

describe('ScoresPage', () => {
  it('lists the worst rules with explanations and links into the rulebase', async () => {
    setup('/scores', <Route path="/scores" element={<ScoresPage />} />, (req) => {
      if (req.url.startsWith('/api/snapshots/7/scores')) {
        return { status: 200, body: [{ policy_fmc_id: 'p1', policy_name: 'ACP', rule_id: 'r1', rule_index: 999, rule_name: 'ANY_ANY_TEMP', action: 'ALLOW', score: 0, ace_count: 1, reasons: [{ code: 'any_destination', points: 25 }], dst_tiers: ['GOLD', 'SILVER'] }] };
      }
      return undefined;
    });
    const link = await screen.findByRole('link', { name: 'ANY_ANY_TEMP' });
    expect(link).toHaveAttribute('href', '/rules?snapshot=7&policy=p1&q=ANY_ANY_TEMP');
    expect(screen.getByText(/not anchored on a destination/)).toBeInTheDocument();
    expect(screen.getByText('GOLD')).toBeInTheDocument();
  });
});

describe('RulebasePage scores', () => {
  beforeEach(() => {
    vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockReturnValue(DOMRect.fromRect({ x: 0, y: 0, width: 1200, height: 800 }));
    vi.spyOn(HTMLElement.prototype, 'offsetHeight', 'get').mockReturnValue(800);
    vi.spyOn(HTMLElement.prototype, 'offsetWidth', 'get').mockReturnValue(1200);
  });

  it('expands a rule score into its reasons and flags shadowed rules', async () => {
    const row: RuleRow = {
      id: 'r2', rule_type: null, index: 2, section: 'Default', category: '--Undefined--', name: 'NESTED_LOOP',
      enabled: true, action: 'ALLOW', hit_count: 0, last_hit: null, ips_policy: null, file_policy: null,
      log_begin: false, log_end: true, refs: {}, score: 35, ace_count: 12, shadowed_by: 'r1', dead: true,
      reasons: [{ code: 'shadowed', points: 20, by: 'r1' }],
    };
    setup('/rules', <Route path="/rules" element={<RulebasePage />} />, (req) => {
      if (req.url === '/api/snapshots/7/clusters') {
        return { status: 200, body: [{ fmc_id: 'c1', name: 'C', kind: 'ha_pair', sw_version: '', model: '', members: [], policy_fmc_id: 'p1', policy_name: 'ACP', rule_count: 1, ace_total: 10, ace_limit: 100, ace_limit_verified: false, policies: [{ id: 'p1', name: 'ACP', kind: 'access', via: 'assignment', rule_count: 1 }] }] };
      }
      if (req.url.includes('/rules?')) {
        return { status: 200, body: { policy_fmc_id: 'p1', policy_kind: 'access', policy_name: 'ACP', default_action: 'BLOCK', groups: [], categories: [], total: 1, offset: 0, rows: [row] } };
      }
      return undefined;
    });
    expect(await screen.findByText('NESTED_LOOP')).toBeInTheDocument();
    expect(screen.getByText('shadowed')).toBeInTheDocument();
    expect(screen.getByText('no hits')).toBeInTheDocument();
    expect(screen.queryByText(/an earlier rule covers it/)).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Why this score: 35' }));
    expect(screen.getByText(/an earlier rule covers it/)).toBeInTheDocument();
  });
});

describe('AssetsPage', () => {
  it('reports CSV errors by line, bootstraps and confirms suggestions', async () => {
    let assets = [
      { id: 1, network: '10.20.5.0/24', system: 'SQL-FIN', tier: 'GOLD', system_type: 'DB', user_type: null, ports: 'TCP 1433', notes: '', source: 'manual', confirmed: true, updated_by: 'x' },
      { id: 2, network: '10.0.0.53/32', system: 'H_DNS1', tier: 'CORE', system_type: '', user_type: null, ports: '', notes: '', source: 'bootstrap', confirmed: false, updated_by: 'x' },
    ];
    const calls = setup('/assets', <Route path="/assets" element={<AssetsPage />} />, (req) => {
      if (req.url === '/api/assets' && req.method === 'GET') return { status: 200, body: assets };
      if (req.url === '/api/assets/import') return { status: 422, body: { detail: 'csv_invalid_rows', errors: [{ line: 3, fields: ['network'] }, { line: 7, fields: ['tier'] }] } };
      if (req.url === '/api/assets/bootstrap') return { status: 200, body: { created: 4, updated: 0 } };
      if (req.url === '/api/assets/confirm') {
        assets = assets.map((a) => ({ ...a, confirmed: true }));
        return { status: 200, body: { created: 0, updated: 1 } };
      }
      return undefined;
    });
    expect(await screen.findByText('SQL-FIN')).toBeInTheDocument();
    expect(screen.getByText('pending confirmation')).toBeInTheDocument();
    const user = userEvent.setup();
    const file = new File(['network,system,tier\nbad,x,GOLD\n'], 'assets.csv', { type: 'text/csv' });
    await user.upload(screen.getByLabelText('Import CSV'), file);
    expect(await screen.findByText('The file was not imported. Fix lines: 3, 7')).toBeInTheDocument();
    const upload = calls.find((c) => c.url === '/api/assets/import');
    expect(upload?.body).toEqual({ csv: 'network,system,tier\nbad,x,GOLD\n' });
    await user.click(screen.getByRole('button', { name: 'Suggest from snapshot' }));
    expect(await screen.findByText(/4 suggestions added/)).toBeInTheDocument();
    expect(calls.find((c) => c.url === '/api/assets/bootstrap')?.body).toEqual({ snapshot_id: 7 });
    await user.click(screen.getByRole('button', { name: 'Confirm all suggestions (1)' }));
    expect(calls.find((c) => c.url === '/api/assets/confirm')?.body).toEqual({ ids: [2] });
  });
});

describe('ClustersPage ACE usage', () => {
  it('shows usage against an unverified limit', async () => {
    setup('/clusters', <Route path="/clusters" element={<ClustersPage />} />, (req) => {
      if (req.url === '/api/snapshots/7/clusters') {
        return { status: 200, body: [{ fmc_id: 'c1', name: 'FTD-CL01', kind: 'ha_pair', sw_version: '7.7.13', model: 'x', members: [], policy_fmc_id: 'p1', policy_name: 'ACP', rule_count: 1, ace_total: 900, ace_limit: 1000, ace_limit_verified: false, policies: [] }] };
      }
      return undefined;
    });
    const row = (await screen.findByText('FTD-CL01')).closest('tr');
    expect(row).not.toBeNull();
    if (row === null) return;
    expect(within(row).getByText('90%')).toBeInTheDocument();
    expect(within(row).getByText('unverified default')).toBeInTheDocument();
  });
});
